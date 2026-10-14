// Package login runs the OAuth device flow against systemapi's
// controlplane/oauth.js and returns the opaque bearer token.
//
// Threats: the device code and the access token are secrets. Neither is
// printed, logged, or put in a URL; requests are form POST bodies. The
// verification URL must be on the same origin as the control plane and must
// not carry device_code or access_token, so a hostile response cannot send the
// user elsewhere. The HTTP client is the guarded one (TLS 1.3, no proxy, no
// redirects); response bodies are capped at 64 KiB. Polling honors the
// server's interval clamped to 5-300 s and slows by 5 s on slow_down. Any
// unexpected status or body fails closed. Does NOT verify who approves the code: a stolen
// verification URL inside its 10-minute TTL is consent (see oauth.js).
package login

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/afterdarksys/sahconnect/internal/client"
	"github.com/afterdarksys/sahconnect/internal/token"
)

// DeviceGrant is the RFC 8628 grant type oauth.js accepts.
const DeviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

const maxBody = 64 << 10

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$`)

// ValidUsername mirrors oauth.js USER_RE.
func ValidUsername(u string) bool { return usernameRE.MatchString(u) }

// Error is a fixed failure code; it never carries a secret.
type Error struct{ Code string }

func (e *Error) Error() string {
	switch e.Code {
	case "login_denied":
		return "login_denied: the username is not a member, or the code was refused"
	case "access_denied":
		return "access_denied: the login was denied in the browser"
	case "expired_token":
		return "expired_token: the code expired before it was approved; run sahconnect login again"
	case "oauth_unavailable":
		return "oauth_unavailable: device login is not configured on this control plane"
	case "too_many_pending":
		return "too_many_pending: too many unfinished logins for this user; wait 10 minutes"
	}
	return e.Code
}

func fail(code string) error { return &Error{Code: code} }

// Prompt is what the user must open. Code is the user code from the URL.
type Prompt struct {
	VerificationURL string
	Code            string
	ExpiresIn       time.Duration
}

// Flow is one device login.
type Flow struct {
	Base     *url.URL     // validated control-plane origin
	Username string       // member user id
	HTTP     *http.Client // guarded client
	// Show is called once with the verification prompt.
	Show func(Prompt)
	// Sleep waits d or until ctx ends. nil uses a timer. Tests inject it.
	Sleep func(ctx context.Context, d time.Duration) error
	// MaxWait caps the whole flow (default 15 min; the server's expires_in
	// shortens it).
	MaxWait time.Duration
}

type startResp struct {
	DeviceCode      string `json:"device_code"`
	VerificationURL string `json:"verification_url"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type tokenResp struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// Result is the issued bearer. Token is secret: store it, never print it.
type Result struct {
	Token     string
	ExpiresIn time.Duration
}

// Run starts the flow, shows the prompt, and polls until approval, denial,
// or expiry.
func (f *Flow) Run(ctx context.Context) (*Result, error) {
	if f.Base == nil || f.HTTP == nil {
		return nil, fail("login_misconfigured")
	}
	if !ValidUsername(f.Username) {
		return nil, fail("invalid_username")
	}
	sleep := f.Sleep
	if sleep == nil {
		sleep = timerSleep
	}
	status, body, err := f.post(ctx, "/oauth/device", url.Values{"username": {f.Username}})
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, statusError(status, body, "device_login_failed")
	}
	var start startResp
	if json.Unmarshal(body, &start) != nil || len(start.DeviceCode) < 16 || len(start.DeviceCode) > 256 {
		return nil, fail("device_login_failed")
	}
	userCode, err := f.checkVerification(start.VerificationURL)
	if err != nil {
		return nil, err
	}
	maxWait := f.MaxWait
	if maxWait <= 0 {
		maxWait = 15 * time.Minute
	}
	if start.ExpiresIn > 0 && time.Duration(start.ExpiresIn)*time.Second < maxWait {
		maxWait = time.Duration(start.ExpiresIn) * time.Second
	}
	deadline := time.Now().Add(maxWait)
	secs := start.Interval
	if secs > 300 {
		secs = 300 // also keeps the multiplication below from overflowing
	}
	interval := clampInterval(time.Duration(secs) * time.Second)
	if f.Show != nil {
		f.Show(Prompt{VerificationURL: start.VerificationURL, Code: userCode, ExpiresIn: maxWait})
	}
	form := url.Values{"grant_type": {DeviceGrant}, "device_code": {start.DeviceCode}}
	for {
		if err := waitUntil(ctx, sleep, deadline, interval); err != nil {
			return nil, err
		}
		status, body, err := f.post(ctx, "/oauth/token", form)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			var tr tokenResp
			if json.Unmarshal(body, &tr) != nil || !strings.EqualFold(tr.TokenType, "Bearer") || !token.Valid(tr.AccessToken) {
				return nil, fail("device_login_failed")
			}
			return &Result{Token: tr.AccessToken, ExpiresIn: time.Duration(tr.ExpiresIn) * time.Second}, nil
		}
		switch c := errorCode(body); {
		case status == http.StatusBadRequest && c == "authorization_pending":
			continue
		case (status == http.StatusBadRequest && c == "slow_down") || status == http.StatusTooManyRequests:
			interval = clampInterval(interval + 5*time.Second)
			continue
		default:
			return nil, statusError(status, body, "device_login_failed")
		}
	}
}

// Poll interval bounds. The server's interval is honored inside them; 0 (or
// anything below) becomes 5 s, and a hostile or broken server cannot stretch
// the wait past 300 s.
const (
	minInterval = 5 * time.Second
	maxInterval = 300 * time.Second
)

func clampInterval(d time.Duration) time.Duration {
	if d < minInterval {
		return minInterval
	}
	if d > maxInterval {
		return maxInterval
	}
	return d
}

func waitUntil(ctx context.Context, sleep func(context.Context, time.Duration) error, deadline time.Time, d time.Duration) error {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return fail("expired_token")
	}
	if d > remaining {
		d = remaining
	}
	if err := sleep(ctx, d); err != nil {
		return fail("login_cancelled")
	}
	return nil
}

func timerSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func errorCode(body []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e) // a non-JSON body yields "" and fails closed below
	return e.Error
}

func statusError(status int, body []byte, fallback string) error {
	c := errorCode(body)
	switch {
	case status == http.StatusForbidden:
		return fail("login_denied")
	case status == http.StatusTooManyRequests:
		return fail("too_many_pending")
	case status == http.StatusServiceUnavailable:
		return fail("oauth_unavailable")
	case status == http.StatusBadRequest:
		switch c {
		case "expired_token", "access_denied", "invalid_grant", "unsupported_grant_type":
			return fail(c)
		}
	}
	return fail(fallback)
}

func (f *Flow) post(ctx context.Context, path string, form url.Values) (int, []byte, error) {
	u := *f.Base
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return 0, nil, fail("device_login_failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, client.ErrRedirect) {
			return 0, nil, fail("redirect_denied")
		}
		if ctx.Err() != nil {
			return 0, nil, fail("login_cancelled")
		}
		return 0, nil, fail("request_failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return 0, nil, fail("device_login_failed")
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return 0, nil, fail("redirect_denied")
	}
	return resp.StatusCode, body, nil
}

// checkVerification requires the verification URL to be on the control
// plane's own origin, at /oauth/device/verify, with a code and no secrets.
func (f *Flow) checkVerification(raw string) (string, error) {
	if raw == "" || len(raw) > 1024 {
		return "", fail("url_rejected")
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Fragment != "" {
		return "", fail("url_rejected")
	}
	if u.Scheme != f.Base.Scheme || !strings.EqualFold(u.Host, f.Base.Host) || u.Path != "/oauth/device/verify" {
		return "", fail("url_rejected")
	}
	q := u.Query()
	if q.Has("device_code") || q.Has("access_token") || q.Has("token") {
		return "", fail("url_rejected")
	}
	code := q.Get("code")
	if len(code) < 16 || len(code) > 256 {
		return "", fail("url_rejected")
	}
	for _, r := range raw {
		if r < 0x21 || r > 0x7e {
			return "", fail("url_rejected")
		}
	}
	return code, nil
}

// ErrCode extracts the code from a login error, or "".
func ErrCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

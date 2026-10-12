// Threats: calls the operator's systemapi with a key from the environment.
// The key is a header, never a query parameter, and it is never copied into
// an error string. http is accepted only for a loopback IP or the name
// localhost. https uses the system CA pool and TLS 1.3 or newer. Redirects
// are refused. Query keys api_key, access_token, token, and device_code are
// refused. This client does not open a shell of its own. sahconnect ssh
// executes the adssh binary the operator already has.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

const maxBody = 256 << 10
const maxResponse = 1 << 20

// Error is a fixed failure code. It does not carry a URL or a key.
type Error struct{ Code string }

func (e *Error) Error() string {
	if e == nil || e.Code == "" {
		return "request_failed"
	}
	return e.Code
}

func code(c string) error { return &Error{Code: c} }

// ValidateBase accepts an http(s) origin with no userinfo, query, or path.
// Plain http is only valid for loopback.
func ValidateBase(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > 200 {
		return nil, code("invalid_url")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, code("invalid_url")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, code("invalid_url")
	}
	if strings.ContainsAny(u.Host, " \t\r\n") {
		return nil, code("invalid_url")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, code("invalid_url")
		}
	default:
		return nil, code("invalid_url")
	}
	if badName(u.Hostname()) {
		return nil, code("invalid_url")
	}
	return u, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func badName(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	switch h {
	case "metadata.google.internal", "metadata.goog":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if ip.IsLoopback() {
			return false
		}
		if ip.Equal(net.ParseIP("fd00:ec2::254")) || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			return true
		}
	}
	return false
}

// ValidPath is an absolute path with no dot-dot, backslash, or query.
func ValidPath(p string) bool {
	if len(p) == 0 || len(p) > 512 || !strings.HasPrefix(p, "/") {
		return false
	}
	if strings.Contains(p, "..") || strings.Contains(p, "//") || strings.Contains(p, "\\") || strings.Contains(p, "?") || strings.Contains(p, "#") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

// ValidQuery rejects credential-bearing keys.
func ValidQuery(raw string) error {
	if len(raw) > 2048 {
		return code("invalid_query")
	}
	if raw == "" {
		return nil
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return code("invalid_query")
	}
	for key := range q {
		switch strings.ToLower(key) {
		case "api_key", "access_token", "token", "device_code":
			return code("invalid_query")
		}
	}
	return nil
}

var methods = map[string]struct{}{
	http.MethodGet: {}, http.MethodPost: {}, http.MethodPut: {},
	http.MethodPatch: {}, http.MethodDelete: {},
}

// Do performs one request. key is sent as X-API-Key. Errors are codes.
func Do(ctx context.Context, base *url.URL, key, method, path, rawQuery string, body []byte) (int, []byte, error) {
	if base == nil {
		return 0, nil, code("invalid_url")
	}
	method = strings.ToUpper(method)
	if _, ok := methods[method]; !ok {
		return 0, nil, code("bad_method")
	}
	if !ValidPath(path) {
		return 0, nil, code("bad_path")
	}
	if err := ValidQuery(rawQuery); err != nil {
		return 0, nil, err
	}
	if strings.TrimSpace(key) == "" || len(key) > 512 || strings.ContainsAny(key, " \t\r\n") {
		return 0, nil, code("key_rejected")
	}
	if len(body) > maxBody {
		return 0, nil, code("too_large")
	}
	u := *base
	u.Path = path
	u.RawQuery = rawQuery
	u.Fragment = ""
	u.User = nil
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return 0, nil, code("request_failed")
	}
	req.Header.Set("X-API-Key", key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirect_denied")
		},
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "redirect_denied") {
			return 0, nil, code("redirect_denied")
		}
		if strings.Contains(err.Error(), key) {
			return 0, nil, code("request_failed")
		}
		return 0, nil, code("request_failed")
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, code("request_failed")
	}
	if len(buf) > maxResponse {
		return 0, nil, code("response_too_large")
	}
	return resp.StatusCode, buf, nil
}

// LookAdssh resolves an explicit binary or adssh on PATH.
func LookAdssh(explicit string) (string, error) {
	if explicit != "" {
		if strings.Contains(explicit, "\x00") {
			return "", code("adssh_missing")
		}
		st, err := os.Stat(explicit)
		if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
			return "", code("adssh_missing")
		}
		return explicit, nil
	}
	p, err := exec.LookPath("adssh")
	if err != nil {
		return "", code("adssh_missing")
	}
	return p, nil
}

// RunAdssh executes adssh with the operator's stdio. It does not add arguments.
func RunAdssh(ctx context.Context, bin string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if bin == "" {
		return code("adssh_missing")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit
		}
		return code("adssh_failed")
	}
	return nil
}

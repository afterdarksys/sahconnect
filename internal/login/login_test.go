package login

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/afterdarksys/sahconnect/internal/client"
)

const (
	deviceCode = "DEVICECODE-0123456789abcdefghij"
	userCode   = "USERCODE-0123456789abcdefghijkl"
	access     = "ACCESSTOKEN-0123456789abcdefghij"
)

type fake struct {
	mu        sync.Mutex
	responses []func(w http.ResponseWriter) // one per /oauth/token poll
	polls     int
	verifyURL string // override
	interval  *int
	startCode int
	forms     []url.Values
}

func (f *fake) handler(base *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
			w.WriteHeader(http.StatusTeapot)
			return
		}
		_ = r.ParseForm()
		f.forms = append(f.forms, r.PostForm)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/device":
			if f.startCode != 0 {
				w.WriteHeader(f.startCode)
				_, _ = w.Write([]byte(`{"error":"x"}`))
				return
			}
			vu := *base + "/oauth/device/verify?code=" + userCode
			if f.verifyURL != "" {
				vu = f.verifyURL
			}
			iv := 5
			if f.interval != nil {
				iv = *f.interval
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": deviceCode, "verification_url": vu, "expires_in": 600, "interval": iv,
			})
		case "/oauth/token":
			if r.PostForm.Get("grant_type") != DeviceGrant || r.PostForm.Get("device_code") != deviceCode {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			i := f.polls
			f.polls++
			if i >= len(f.responses) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			f.responses[i](w)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func oauthErr(code string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
	}
}

func success(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"access_token":"` + access + `","token_type":"Bearer","expires_in":3600}`))
}

func run(t *testing.T, f *fake) (*Result, error, []time.Duration, []Prompt) {
	t.Helper()
	var base string
	srv := httptest.NewServer(f.handler(&base))
	t.Cleanup(srv.Close)
	base = srv.URL
	u, err := client.ValidateBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var sleeps []time.Duration
	var prompts []Prompt
	flow := &Flow{
		Base: u, Username: "user-1", HTTP: client.NewHTTPClient(nil, 5*time.Second),
		Show:  func(p Prompt) { prompts = append(prompts, p) },
		Sleep: func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil },
	}
	res, err := flow.Run(context.Background())
	return res, err, sleeps, prompts
}

func TestPendingSlowDownSuccess(t *testing.T) {
	f := &fake{responses: []func(http.ResponseWriter){
		oauthErr("authorization_pending"), oauthErr("slow_down"), oauthErr("authorization_pending"), success,
	}}
	res, err, sleeps, prompts := run(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if res.Token != access || res.ExpiresIn != time.Hour {
		t.Fatalf("result %+v", res)
	}
	// slow_down raises the interval by 5 s for every later poll (RFC 8628 3.5).
	want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}
	if len(sleeps) != len(want) {
		t.Fatalf("sleeps %v", sleeps)
	}
	for i := range want {
		if sleeps[i] != want[i] {
			t.Fatalf("sleeps %v want %v", sleeps, want)
		}
	}
	if len(prompts) != 1 || prompts[0].Code != userCode || !strings.Contains(prompts[0].VerificationURL, "/oauth/device/verify?code=") {
		t.Fatalf("prompt %+v", prompts)
	}
	if strings.Contains(prompts[0].VerificationURL, deviceCode) {
		t.Fatal("device code shown")
	}
	if f.forms[0].Get("username") != "user-1" {
		t.Fatalf("start form %v", f.forms[0])
	}
}

func TestTerminalFailures(t *testing.T) {
	for _, code := range []string{"expired_token", "access_denied", "invalid_grant"} {
		f := &fake{responses: []func(http.ResponseWriter){oauthErr("authorization_pending"), oauthErr(code)}}
		_, err, _, _ := run(t, f)
		if ErrCode(err) != code {
			t.Fatalf("%s: got %v", code, err)
		}
		if strings.Contains(err.Error(), deviceCode) || strings.Contains(err.Error(), userCode) {
			t.Fatal("error leaked a code")
		}
	}
	f := &fake{responses: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusInternalServerError)
	}}}
	if _, err, _, _ := run(t, f); ErrCode(err) != "device_login_failed" {
		t.Fatalf("500: %v", err)
	}
	f = &fake{responses: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"access_token":"` + access + `","token_type":"mac"}`))
	}}}
	if _, err, _, _ := run(t, f); ErrCode(err) != "device_login_failed" {
		t.Fatalf("non-bearer accepted: %v", err)
	}
	f = &fake{responses: []func(http.ResponseWriter){func(w http.ResponseWriter) {
		_, _ = w.Write([]byte(`{"access_token":"short","token_type":"Bearer"}`))
	}}}
	if _, err, _, _ := run(t, f); ErrCode(err) != "device_login_failed" {
		t.Fatalf("short token accepted: %v", err)
	}
}

func TestStartRefusals(t *testing.T) {
	for status, want := range map[int]string{403: "login_denied", 429: "too_many_pending", 503: "oauth_unavailable", 500: "device_login_failed"} {
		f := &fake{startCode: status}
		if _, err, _, _ := run(t, f); ErrCode(err) != want {
			t.Fatalf("%d: %v", status, err)
		}
	}
	bad := []string{
		"https://evil.example/oauth/device/verify?code=" + userCode,
		"http://127.0.0.1:1/oauth/device/verify?code=" + userCode,
		"PLACEHOLDER/elsewhere?code=" + userCode,
		"PLACEHOLDER/oauth/device/verify?code=" + userCode + "&device_code=" + deviceCode,
		"PLACEHOLDER/oauth/device/verify?code=short",
		"javascript:alert(1)",
	}
	for _, vu := range bad {
		f := &fake{responses: []func(http.ResponseWriter){success}}
		var base string
		srv := httptest.NewServer(f.handler(&base))
		base = srv.URL
		f.verifyURL = strings.Replace(vu, "PLACEHOLDER", srv.URL, 1)
		u, _ := client.ValidateBase(srv.URL)
		flow := &Flow{Base: u, Username: "user-1", HTTP: client.NewHTTPClient(nil, 5*time.Second),
			Sleep: func(context.Context, time.Duration) error { return nil }}
		_, err := flow.Run(context.Background())
		srv.Close()
		if ErrCode(err) != "url_rejected" {
			t.Fatalf("%s: %v", vu, err)
		}
		if f.polls != 0 {
			t.Fatal("polled after a rejected verification URL")
		}
	}
	u, _ := client.ValidateBase("https://cp.example")
	flow := &Flow{Base: u, Username: "bad user", HTTP: client.NewHTTPClient(nil, time.Second)}
	if _, err := flow.Run(context.Background()); ErrCode(err) != "invalid_username" {
		t.Fatalf("username: %v", err)
	}
}

func TestExpiresWhilePending(t *testing.T) {
	var base string
	f := &fake{}
	for i := 0; i < 1000; i++ {
		f.responses = append(f.responses, oauthErr("authorization_pending"))
	}
	srv := httptest.NewServer(f.handler(&base))
	defer srv.Close()
	base = srv.URL
	u, _ := client.ValidateBase(srv.URL)
	flow := &Flow{Base: u, Username: "user-1", HTTP: client.NewHTTPClient(nil, 5*time.Second),
		MaxWait: 50 * time.Millisecond,
		Sleep: func(ctx context.Context, d time.Duration) error {
			time.Sleep(10 * time.Millisecond)
			return nil
		}}
	if _, err := flow.Run(context.Background()); ErrCode(err) != "expired_token" {
		t.Fatalf("expiry: %v", err)
	}
}

func TestRedirectRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	u, _ := client.ValidateBase(srv.URL)
	flow := &Flow{Base: u, Username: "user-1", HTTP: client.NewHTTPClient(nil, 5*time.Second)}
	if _, err := flow.Run(context.Background()); ErrCode(err) != "redirect_denied" {
		t.Fatalf("redirect: %v", err)
	}
}

func TestIntervalClamped(t *testing.T) {
	cases := map[int][]time.Duration{
		0:       {5 * time.Second, 10 * time.Second},
		-3:      {5 * time.Second, 10 * time.Second},
		120:     {120 * time.Second, 125 * time.Second},
		400:     {300 * time.Second, 300 * time.Second},
		1 << 62: {300 * time.Second, 300 * time.Second},
	}
	for iv, want := range cases {
		iv := iv
		f := &fake{interval: &iv, responses: []func(http.ResponseWriter){oauthErr("slow_down"), success}}
		_, err, sleeps, _ := run(t, f)
		if err != nil {
			t.Fatal(err)
		}
		if len(sleeps) != 2 || sleeps[0] != want[0] || sleeps[1] != want[1] {
			t.Fatalf("interval %d: sleeps %v want %v", iv, sleeps, want)
		}
	}
}

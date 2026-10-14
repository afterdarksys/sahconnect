package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/term"

	"github.com/afterdarksys/sahconnect/internal/tty"
)

const (
	testBearer = "BEARER-SENTINEL-abcdefghijklmnop"
	testTicket = "stk_TICKET-SENTINEL-0123"
)

// cp is a loopback fake of the control plane: device login, resolve, ticket
// and the terminal socket.
type cp struct {
	mu          sync.Mutex
	auths       []string
	purposes    []string
	exit        int
	status      string // pty_status error to send instead of a session
	rateLimited bool   // ws-ticket answers 429
}

func (f *cp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if strings.HasPrefix(r.URL.Path, "/api/v1/systems/terminal/") {
		// The socket authenticates by ticket only: no credential header.
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
			http.Error(w, "", http.StatusBadRequest)
			f.mu.Unlock()
			return
		}
	} else {
		f.auths = append(f.auths, r.Header.Get("Authorization")+"|"+r.Header.Get("X-API-Key"))
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/oauth/device":
		_, _ = w.Write([]byte(`{"device_code":"DEVICE-0123456789abcdef","verification_url":"http://` + r.Host +
			`/oauth/device/verify?code=USERCODE-0123456789abcdef","expires_in":600,"interval":1}`))
	case "/oauth/token":
		_, _ = w.Write([]byte(`{"access_token":"` + testBearer + `","token_type":"Bearer","expires_in":3600}`))
	case "/api/v1/hosts/resolve":
		if r.URL.Query().Get("name") == "dup" {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"ambiguous","matches":2}`))
			return
		}
		_, _ = w.Write([]byte(`{"host_id":"h-1","hostname":"web1","tenant":"t","status":"online"}`))
	case "/api/v1/ws-ticket":
		if f.rateLimited {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.purposes = append(f.purposes, req["purpose"])
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"ticket":"` + testTicket + `","expires_at":"2026-10-14T00:00:00Z"}`))
	case "/api/v1/systems/terminal/h-1":
		if r.URL.Query().Get("ticket") != testTicket {
			http.Error(w, "", http.StatusUnauthorized)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		ctx := r.Context()
		if f.status != "" {
			_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"pty_status","payload":{"error":"`+f.status+`"}}`))
			_ = c.Close(websocket.StatusInternalError, "")
			return
		}
		_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"pty_status","payload":{"status":"started","session_id":"s"}}`))
		for {
			_, data, err := c.Read(ctx)
			if err != nil {
				return
			}
			var m struct {
				Type    string `json:"type"`
				DataB64 string `json:"data_b64"`
			}
			_ = json.Unmarshal(data, &m)
			if m.Type == "pty_input" {
				raw, _ := base64.StdEncoding.DecodeString(m.DataB64)
				_ = c.Write(ctx, websocket.MessageBinary, raw)
			}
			if m.Type == "pty_eof" {
				_ = c.Write(ctx, websocket.MessageText, []byte(`{"type":"pty_exit","payload":{"session_id":"s","code":`+strconv.Itoa(f.exit)+`,"reason":"exited"}}`))
				_ = c.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type ttyRec struct{ raw, restored int }

func testApp(t *testing.T, env map[string]string, stdin string, isTTY bool) (*app, *bytes.Buffer, *bytes.Buffer, *ttyRec) {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	rec := &ttyRec{}
	return &app{
		stdin: strings.NewReader(stdin), stdout: out, stderr: errb, stdinFd: -1, sizeFd: -1,
		tty: tty.Ops{
			IsTerminal: func(int) bool { return isTTY },
			MakeRaw:    func(int) (*term.State, error) { rec.raw++; return &term.State{}, nil },
			Restore:    func(int, *term.State) error { rec.restored++; return nil },
		},
		env:   func(k string) string { return env[k] },
		sleep: func(context.Context, time.Duration) error { return nil },
	}, out, errb, rec
}

func TestLoginConnectLogout(t *testing.T) {
	f := &cp{exit: 42}
	srv := httptest.NewServer(f)
	defer srv.Close()
	xdg := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": xdg, "SYSTEMAPI_URL": srv.URL, "SYSTEMAPI_API_KEY": "KEY-SENTINEL", "USER": "user-1"}

	a, out, errb, _ := testApp(t, env, "", false)
	if code := a.run([]string{"login"}); code != 0 {
		t.Fatalf("login %d: %s", code, errb)
	}
	if strings.Contains(out.String()+errb.String(), testBearer) {
		t.Fatal("login printed the token")
	}
	if !strings.Contains(errb.String(), "/oauth/device/verify?code=USERCODE") || !strings.Contains(errb.String(), "Code: USERCODE") {
		t.Fatalf("prompt: %s", errb)
	}
	tokPath := filepath.Join(xdg, "sahconnect", "token")
	st, err := os.Stat(tokPath)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("token file %v %v", st, err)
	}

	a, out, errb, rec := testApp(t, env, "hello\n", true)
	code := a.run([]string{"web1", "--root"})
	if code != 42 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if out.String() != "hello\n" || rec.raw != 1 || rec.restored != 1 {
		t.Fatalf("stdout %q tty %+v", out, rec)
	}
	f.mu.Lock()
	for _, au := range f.auths[2:] {
		if au != "Bearer "+testBearer+"|" {
			t.Fatalf("bearer must win and be the only credential: %q", au)
		}
	}
	if f.purposes[len(f.purposes)-1] != "terminal:root" {
		t.Fatalf("purpose %v", f.purposes)
	}
	f.mu.Unlock()
	if strings.Contains(errb.String(), testTicket) || strings.Contains(errb.String(), testBearer) {
		t.Fatal("stderr leaked a secret")
	}

	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"logout"}); code != 0 {
		t.Fatalf("logout %d %s", code, errb)
	}
	if _, err := os.Stat(tokPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("token not removed")
	}
	// Without the token file, the API key is used.
	a, _, _, _ = testApp(t, env, "", false)
	if code := a.run([]string{"connect", "web1"}); code != 42 {
		t.Fatalf("key connect %d", code)
	}
	f.mu.Lock()
	if last := f.auths[len(f.auths)-1]; last != "|KEY-SENTINEL" {
		t.Fatalf("api key fallback %q", last)
	}
	if f.purposes[len(f.purposes)-1] != "terminal:open" {
		t.Fatalf("purpose %v", f.purposes)
	}
	f.mu.Unlock()
}

func TestConnectFailuresRestoreTTY(t *testing.T) {
	f := &cp{status: "recording_unavailable"}
	srv := httptest.NewServer(f)
	defer srv.Close()
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir(), "SYSTEMAPI_URL": srv.URL, "SYSTEMAPI_API_KEY": "KEY-SENTINEL"}
	a, _, errb, rec := testApp(t, env, "", true)
	code := a.run([]string{"web1"})
	if code == 0 || rec.raw != 1 || rec.restored != 1 || !strings.Contains(errb.String(), "recording_unavailable") {
		t.Fatalf("code %d tty %+v stderr %s", code, rec, errb)
	}
	a, _, errb, rec = testApp(t, env, "", true)
	if code := a.run([]string{"dup"}); code != 1 || !strings.Contains(errb.String(), "use the host_id") || rec.raw != 0 {
		t.Fatalf("ambiguous %d %s %+v", code, errb, rec)
	}
}

func TestMethodAndDispatchRules(t *testing.T) {
	xdg := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "SYSTEMAPI_URL": "https://cp.example", "SYSTEMAPI_API_KEY": "k"}
	a, _, errb, _ := testApp(t, env, "", false)
	if code := a.run([]string{"web1", "--method", "ssh"}); code != 2 || !strings.Contains(errb.String(), "phase 3") {
		t.Fatalf("ssh method: %d %s", code, errb)
	}
	cfgPath := filepath.Join(xdg, "sahconnect", "config.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`method = ["ssh"]`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 2 || !strings.Contains(errb.String(), "phase 3") {
		t.Fatalf("config ssh: %d %s", code, errb)
	}
	a, _, _, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1", "--method", "telnet"}); code != 2 {
		t.Fatal("bad method accepted")
	}
	if err := os.Chmod(cfgPath, 0o666); err != nil {
		t.Fatal(err)
	}
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 2 || !strings.Contains(errb.String(), "writable") {
		t.Fatalf("insecure config: %d %s", code, errb)
	}
	a, _, _, _ = testApp(t, env, "", false)
	for _, args := range [][]string{{"-x"}, {"connect"}, {"connect", "a", "b"}} {
		if code := a.run(args); code != 2 {
			t.Fatalf("%v: %d", args, code)
		}
	}
	// Plain http to a non-loopback host is refused before any request.
	env["SYSTEMAPI_URL"] = "http://cp.example"
	if err := os.Chmod(cfgPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`method = "agent"`), 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, _, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 2 {
		t.Fatal("plain http accepted")
	}
}

func count(f *cp) int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.auths) }

func TestBearerStaysWithItsOrigin(t *testing.T) {
	prod := &cp{exit: 0}
	prodSrv := httptest.NewServer(prod)
	defer prodSrv.Close()
	staging := &cp{exit: 0}
	stagingSrv := httptest.NewServer(staging)
	defer stagingSrv.Close()
	xdg := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": xdg, "USER": "user-1"}

	a, _, errb, _ := testApp(t, env, "", false)
	if code := a.run([]string{"login", "--url", prodSrv.URL}); code != 0 {
		t.Fatalf("login %d %s", code, errb)
	}
	// Prod token, staging URL, no key: refused, nothing reaches staging.
	env["SYSTEMAPI_URL"] = stagingSrv.URL
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 2 || !strings.Contains(errb.String(), "token file is for") {
		t.Fatalf("mismatch connect %d %s", code, errb)
	}
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.cmdAPI([]string{"GET", "/api/v1/fleet"}); code != 2 {
		t.Fatalf("mismatch api %d %s", code, errb)
	}
	if count(staging) != 0 {
		t.Fatal("a request reached staging")
	}
	// Prod token, staging URL, explicit key: the key is used, never the bearer.
	env["SYSTEMAPI_API_KEY"] = "KEY-SENTINEL"
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 0 || !strings.Contains(errb.String(), "credential: SYSTEMAPI_API_KEY") {
		t.Fatalf("key fallback %d %s", code, errb)
	}
	staging.mu.Lock()
	for _, au := range staging.auths {
		if au != "|KEY-SENTINEL" {
			t.Fatalf("staging saw %q", au)
		}
	}
	staging.mu.Unlock()
	// Same origin with both set: bearer wins and the choice is stated.
	env["SYSTEMAPI_URL"] = prodSrv.URL
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 0 || !strings.Contains(errb.String(), "credential: bearer") {
		t.Fatalf("same origin %d %s", code, errb)
	}
}

func TestBrokenTokenFileNeverFallsBackToKey(t *testing.T) {
	f := &cp{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	xdg := t.TempDir()
	env := map[string]string{"XDG_CONFIG_HOME": xdg, "HOME": xdg, "SYSTEMAPI_URL": srv.URL, "SYSTEMAPI_API_KEY": "KEY-SENTINEL", "USER": "user-1"}
	a, _, errb, _ := testApp(t, env, "", false)
	if code := a.run([]string{"login"}); code != 0 {
		t.Fatalf("login %d %s", code, errb)
	}
	before := count(f)
	tok := filepath.Join(xdg, "sahconnect", "token")
	if err := os.Chmod(tok, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"web1"}, {"api", "GET", "/api/v1/fleet"}} {
		a, _, errb, _ = testApp(t, env, "", false)
		if code := a.run(args); code != 2 || strings.Contains(errb.String(), testBearer) {
			t.Fatalf("0644 %v: %d %s", args, code, errb)
		}
	}
	if err := os.WriteFile(tok, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tok, 0o600); err != nil {
		t.Fatal(err)
	}
	a, _, _, _ = testApp(t, env, "", false)
	if code := a.run([]string{"web1"}); code != 2 {
		t.Fatalf("corrupt token: %d", code)
	}
	if count(f) != before {
		t.Fatal("a request was sent despite a broken token file")
	}
}

func TestTokenFileOnANonTokenFile(t *testing.T) {
	f := &cp{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(sshDir, "id_ed25519")
	keyBody := "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(key, []byte(keyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgDir := filepath.Join(home, ".config", "sahconnect")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(`token_file = "~/.ssh/id_ed25519"`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"HOME": home, "SYSTEMAPI_URL": srv.URL, "USER": "user-1"}
	a, _, errb, _ := testApp(t, env, "", false)
	if code := a.run([]string{"login"}); code == 0 {
		t.Fatalf("login clobbered a key: %s", errb)
	}
	a, _, errb, _ = testApp(t, env, "", false)
	if code := a.run([]string{"logout"}); code == 0 {
		t.Fatalf("logout deleted a key: %s", errb)
	}
	if b, err := os.ReadFile(key); err != nil || string(b) != keyBody {
		t.Fatal("the key file changed")
	}
}

func TestTicketRateLimitedExitsOne(t *testing.T) {
	f := &cp{rateLimited: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir(), "HOME": t.TempDir(), "SYSTEMAPI_URL": srv.URL, "SYSTEMAPI_API_KEY": "KEY-SENTINEL"}
	a, _, errb, rec := testApp(t, env, "", true)
	if code := a.run([]string{"web1"}); code != 1 || !strings.Contains(errb.String(), "too many terminal requests for this host; try again shortly") || rec.raw != 0 {
		t.Fatalf("429: %d %s %+v", code, errb, rec)
	}
	if n := count(f); n != 2 { // resolve + one ticket attempt, no retry
		t.Fatalf("requests %d", n)
	}
}

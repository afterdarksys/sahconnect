package terminal

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/afterdarksys/sahconnect/internal/client"
)

const ticket = "stk_TESTTICKET0123456789"

// fakeServer implements the server side of the terminal protocol.
type fakeServer struct {
	mu       sync.Mutex
	input    bytes.Buffer
	resizes  []string
	eof      bool
	query    url.Values
	path     string
	behavior string // ok | status_error | max_duration | drop | nocode
	exitCode int
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.query = r.URL.Query()
	f.path = r.URL.Path
	f.mu.Unlock()
	if r.URL.Query().Get("ticket") != ticket {
		http.Error(w, "no", http.StatusUnauthorized)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	c.SetReadLimit(64 << 10)
	ctx := r.Context()
	text := func(v string) { _ = c.Write(ctx, websocket.MessageText, []byte(v)) }
	text(`{"type":"pty_status","payload":{"status":"starting"}}`)
	switch f.behavior {
	case "status_error":
		text(`{"type":"pty_status","payload":{"error":"agent_offline"}}`)
		_ = c.Close(websocket.StatusInternalError, "")
		return
	case "drop":
		_ = c.Close(websocket.StatusGoingAway, "")
		return
	case "max_duration":
		text(`{"type":"pty_exit","payload":{"session_id":"s1","code":-1,"reason":"max_duration"}}`)
		_ = c.Close(websocket.StatusNormalClosure, "")
		return
	}
	text(`{"type":"pty_status","payload":{"status":"started","session_id":"s1"}}`)
	text(`{"type":"something_new","payload":{}}`) // unknown types are ignored
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			_ = c.Close(websocket.StatusUnsupportedData, "")
			return
		}
		var m struct {
			Type    string `json:"type"`
			DataB64 string `json:"data_b64"`
			Rows    int    `json:"rows"`
			Cols    int    `json:"cols"`
		}
		if json.Unmarshal(data, &m) != nil {
			return
		}
		f.mu.Lock()
		switch m.Type {
		case "pty_input":
			raw, err := base64.StdEncoding.DecodeString(m.DataB64)
			if err != nil {
				f.mu.Unlock()
				return
			}
			f.input.Write(raw)
			f.mu.Unlock()
			_ = c.Write(ctx, websocket.MessageBinary, append([]byte("out:"), raw...))
			continue
		case "pty_resize":
			f.resizes = append(f.resizes, strings.Join([]string{itoa(m.Rows), itoa(m.Cols)}, "x"))
		case "pty_eof":
			f.eof = true
			code := f.exitCode
			f.mu.Unlock()
			if f.behavior == "nocode" {
				text(`{"type":"pty_exit","payload":{"session_id":"s1","code":-1,"reason":"exited"}}`)
			} else {
				text(`{"type":"pty_exit","payload":{"session_id":"s1","code":` + itoa(code) + `,"reason":"exited"}}`)
			}
			_ = c.Close(websocket.StatusNormalClosure, "")
			return
		}
		f.mu.Unlock()
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func setup(t *testing.T, f *fakeServer, purpose string) (*url.URL, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	base, err := client.ValidateBase(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	u, err := client.TerminalURL(base, "host-1", ticket, purpose, 40, 120)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return u, client.NewHTTPClient(pool, 0)
}

// slowReader yields its chunks one at a time, pausing so resizes interleave,
// then EOF.
type slowReader struct {
	chunks [][]byte
	wait   chan struct{}
}

func (s *slowReader) Read(p []byte) (int, error) {
	if len(s.chunks) == 0 {
		<-s.wait
		return 0, io.EOF
	}
	n := copy(p, s.chunks[0])
	s.chunks = s.chunks[1:]
	return n, nil
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestSessionRoundTrip(t *testing.T) {
	f := &fakeServer{exitCode: 7}
	u, hc := setup(t, f, client.PurposeRoot)
	binary := []byte{0x00, 0xff, 0x1b, '[', 'A', '\r', 0x03, 0x80}
	in := &slowReader{chunks: [][]byte{[]byte("ls -l\r"), binary}, wait: make(chan struct{})}
	resize := make(chan Size, 3)
	resize <- Size{Rows: 50, Cols: 132}
	resize <- Size{Rows: 0, Cols: 132} // invalid: dropped
	resize <- Size{Rows: 1000, Cols: 1}
	go func() { time.Sleep(200 * time.Millisecond); close(in.wait) }()
	out := &syncBuf{}
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: in, Stdout: out, Resize: resize})
	if err != nil || code != 7 {
		t.Fatalf("code %d err %v", code, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if want := append([]byte("ls -l\r"), binary...); !bytes.Equal(f.input.Bytes(), want) {
		t.Fatalf("server got %q", f.input.Bytes())
	}
	if !strings.Contains(out.String(), "out:ls -l\r") || !strings.Contains(out.String(), "out:"+string(binary)) {
		t.Fatalf("stdout %q", out.String())
	}
	if !f.eof {
		t.Fatal("no pty_eof")
	}
	if strings.Join(f.resizes, ",") != "50x132,1000x1" {
		t.Fatalf("resizes %v", f.resizes)
	}
	if f.path != "/api/v1/systems/terminal/host-1" || f.query.Get("purpose") != "terminal:root" ||
		f.query.Get("rows") != "40" || f.query.Get("cols") != "120" {
		t.Fatalf("path %s query %v", f.path, f.query)
	}
	for k := range f.query {
		if k != "ticket" && k != "purpose" && k != "rows" && k != "cols" {
			t.Fatalf("unexpected query key %s", k)
		}
	}
}

func TestPipedStdinExitZero(t *testing.T) {
	f := &fakeServer{exitCode: 0}
	u, hc := setup(t, f, client.PurposeOpen)
	out := &syncBuf{}
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: strings.NewReader("echo hi\n"), Stdout: out})
	if err != nil || code != 0 {
		t.Fatalf("code %d err %v", code, err)
	}
	if out.String() != "out:echo hi\n" {
		t.Fatalf("stdout %q", out.String())
	}
}

func blockForever() io.Reader { r, _ := io.Pipe(); return r }

func TestFailuresAreNonZero(t *testing.T) {
	cases := []struct {
		behavior string
		want     string
	}{
		{"status_error", "agent_offline"},
		{"max_duration", "maximum session duration"},
		{"drop", "closed before the session ended"},
	}
	for _, tc := range cases {
		f := &fakeServer{behavior: tc.behavior}
		u, hc := setup(t, f, client.PurposeOpen)
		code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: blockForever(), Stdout: io.Discard})
		if code != ExitFailure || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: code %d err %v", tc.behavior, code, err)
		}
		if strings.Contains(err.Error(), ticket) {
			t.Fatal("error leaked the ticket")
		}
	}
	f := &fakeServer{behavior: "nocode"}
	u, hc := setup(t, f, client.PurposeOpen)
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: strings.NewReader(""), Stdout: io.Discard})
	if code != ExitFailure || err == nil {
		t.Fatalf("exit -1: code %d err %v", code, err)
	}
}

func TestHandshakeRefusalsDoNotLeakTicket(t *testing.T) {
	f := &fakeServer{}
	srv := httptest.NewTLSServer(f)
	defer srv.Close()
	base, _ := client.ValidateBase(srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	wrong, _ := client.TerminalURL(base, "host-1", "stk_WRONGTICKET000000", client.PurposeOpen, 0, 0)
	code, err := Run(context.Background(), Options{URL: wrong, HTTP: client.NewHTTPClient(pool, 0), Stdin: blockForever(), Stdout: io.Discard})
	if code != ExitFailure || err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "WRONGTICKET") {
		t.Fatalf("401: %d %v", code, err)
	}
	// System CA pool: the test certificate is not trusted.
	good, _ := client.TerminalURL(base, "host-1", ticket, client.PurposeOpen, 0, 0)
	_, err = Run(context.Background(), Options{URL: good, HTTP: client.NewHTTPClient(nil, 0), Stdin: blockForever(), Stdout: io.Discard})
	if err == nil || strings.Contains(err.Error(), ticket) || strings.Contains(err.Error(), srv.URL) {
		t.Fatalf("untrusted cert: %v", err)
	}
}

func TestTLS12Refused(t *testing.T) {
	f := &fakeServer{}
	srv := httptest.NewUnstartedServer(f)
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	base, _ := client.ValidateBase(srv.URL)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	u, _ := client.TerminalURL(base, "host-1", ticket, client.PurposeOpen, 0, 0)
	code, err := Run(context.Background(), Options{URL: u, HTTP: client.NewHTTPClient(pool, 0), Stdin: blockForever(), Stdout: io.Discard})
	if code != ExitFailure || err == nil {
		t.Fatal("TLS 1.2 server accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path != "" {
		t.Fatal("request reached the TLS 1.2 server")
	}
}

func TestURLGuards(t *testing.T) {
	bad := []string{
		"ws://cp.example/api/v1/systems/terminal/h?ticket=x",
		"ws://10.0.0.5/api/v1/systems/terminal/h?ticket=x",
		"wss://169.254.169.254/api/v1/systems/terminal/h?ticket=x",
		"wss://metadata.google.internal/api/v1/systems/terminal/h?ticket=x",
		"wss://[fd00:ec2::254]/x",
		"wss://user:pw@cp.example/x",
		"https://cp.example/x",
		"http://127.0.0.1/x",
	}
	for _, raw := range bad {
		u, _ := url.Parse(raw)
		code, err := Run(context.Background(), Options{URL: u, HTTP: client.NewHTTPClient(nil, 0), Stdin: blockForever(), Stdout: io.Discard})
		if err == nil || code != ExitFailure {
			t.Fatalf("accepted %s", raw)
		}
	}
	for _, raw := range []string{"ws://127.0.0.1:1/x", "ws://localhost:1/x", "ws://[::1]:1/x", "wss://cp.example/x"} {
		u, _ := url.Parse(raw)
		if err := client.ValidateWS(u); err != nil {
			t.Fatalf("refused %s", raw)
		}
	}
}

// exitServer sends one scripted text or binary frame after the socket opens.
func exitServer(t *testing.T, frame []byte, binary bool) (*url.URL, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		typ := websocket.MessageText
		if binary {
			typ = websocket.MessageBinary
		}
		_ = c.Write(r.Context(), typ, frame)
		_, _, _ = c.Read(r.Context())
	}))
	t.Cleanup(srv.Close)
	base, _ := client.ValidateBase(srv.URL)
	u, _ := client.TerminalURL(base, "host-1", ticket, client.PurposeOpen, 0, 0)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return u, client.NewHTTPClient(pool, 0)
}

func TestBadExitFramesAreFailures(t *testing.T) {
	for _, frame := range []string{
		`{"type":"pty_exit","payload":{"session_id":"s","code":300,"reason":"exited"}}`,
		`{"type":"pty_exit","payload":{"session_id":"s","reason":"exited"}}`,
		`{"type":"pty_exit","payload":{"session_id":"s","code":-1,"reason":"exited"}}`,
		`{"type":"pty_exit","payload":{"session_id":"s","code":0,"reason":"stopped"}}`,
		`{"type":"pty_exit","payload":{"session_id":"s","code":0,"reason":"<script>"}}`,
	} {
		u, hc := exitServer(t, []byte(frame), false)
		code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: blockForever(), Stdout: io.Discard})
		if code != ExitFailure || err == nil {
			t.Fatalf("%s: code %d err %v", frame, code, err)
		}
		if strings.Contains(err.Error(), "<script>") {
			t.Fatal("server text echoed unsanitized")
		}
	}
}

func TestOversizeServerFrameRefused(t *testing.T) {
	u, hc := exitServer(t, bytes.Repeat([]byte("A"), maxServerFrame+1), true)
	out := &syncBuf{}
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: blockForever(), Stdout: out})
	if code != ExitFailure || err == nil {
		t.Fatalf("oversize: code %d err %v", code, err)
	}
	if out.String() != "" {
		t.Fatal("oversize frame written to stdout")
	}
}

func TestStartFailedHintsSessionLimit(t *testing.T) {
	u, hc := exitServer(t, []byte(`{"type":"pty_status","payload":{"error":"pty_start_failed"}}`), false)
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: blockForever(), Stdout: io.Discard})
	if code != ExitFailure || err == nil || !strings.Contains(err.Error(), "session limit") {
		t.Fatalf("pty_start_failed: %d %v", code, err)
	}
}

func TestRootUnavailable(t *testing.T) {
	u, hc := exitServer(t, []byte(`{"type":"pty_status","payload":{"error":"root_unavailable"}}`), false)
	code, err := Run(context.Background(), Options{URL: u, HTTP: hc, Stdin: blockForever(), Stdout: io.Discard})
	want := "this host's agent cannot open root shells (agent not running as root, or recording is not enforced)"
	if code != ExitFailure || err == nil || !strings.Contains(err.Error(), want) || strings.Contains(err.Error(), "session limit") {
		t.Fatalf("root_unavailable: %d %v", code, err)
	}
}

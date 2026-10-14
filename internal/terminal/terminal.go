// Package terminal is the sahconnect side of the SystemAPI terminal protocol
// (systemapi.io/docs/sahconnect-terminal-protocol.md, phase 1).
//
// Threats: the URL carries a single-use, 60 s, host- and purpose-bound ticket,
// so it is never printed and dial errors are reduced to fixed text. The URL
// passes client.ValidateWS (wss anywhere, ws only to loopback, no metadata or
// link-local host) and is dialed with the guarded HTTP client (TLS 1.3, system
// CAs, no proxy, no redirects). Input frames stay far below the server's
// 64 KiB limit; server frames are capped at 1 MiB. A pty_status error, a close
// without pty_exit, or any reason other than "exited" ends with a non-zero
// exit.
//
// Does NOT filter remote output. Binary frames are written to the local
// terminal unchanged, exactly as ssh does. A compromised host or control
// plane can therefore send terminal escape sequences: OSC 52 can set (and on
// some terminals read) the local clipboard, an answerback/DECRQSS/title
// report can inject bytes into the local input stream, and sequences can
// repaint the screen to mislead. Use a terminal that disables OSC 52 reads
// and answerback for sessions to hosts you do not trust. Does NOT
// authenticate the remote shell beyond TLS to the control plane.
//
// Run is meant for a CLI that calls it once per process: its stdin goroutine
// stays blocked in Stdin.Read after Run returns (a blocking read cannot be
// interrupted portably). Bytes that read returns after Run has returned are
// dropped, so a caller that keeps reading stdin afterwards would lose them.
package terminal

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/coder/websocket"

	"github.com/afterdarksys/sahconnect/internal/client"
)

const (
	inputChunk     = 16 << 10 // raw bytes per pty_input; ~22 KiB once base64'd
	maxServerFrame = 1 << 20
	// ExitFailure is the exit code for any failure that is not the remote
	// shell's own status (as ssh does).
	ExitFailure = 255
)

// Size is a terminal size in character cells.
type Size struct{ Rows, Cols int }

// Valid reports whether both sides are within the protocol's 1-1000.
func (s Size) Valid() bool { return s.Rows >= 1 && s.Rows <= 1000 && s.Cols >= 1 && s.Cols <= 1000 }

// Options configures one session.
type Options struct {
	URL              *url.URL     // from client.TerminalURL
	HTTP             *http.Client // guarded client with Timeout 0
	Stdin            io.Reader    // read until EOF; see the package note on reuse
	Stdout           io.Writer
	Resize           <-chan Size // window changes; may be nil
	HandshakeTimeout time.Duration
}

// StatusError is a pty_status failure from the server.
type StatusError struct{ Code string }

var statusText = map[string]string{
	"ticket_invalid":        "the ticket was refused (expired or already used); run the command again",
	"scope_denied":          "your credential lacks the scope for this terminal (terminal:root is admin only)",
	"agent_offline":         "the host's agent is offline",
	"lease_required":        "the host requires a lease for this session",
	"pty_user_unset":        "the host has no pty_user configured",
	"recording_unavailable": "session recording is required but adssh is missing on the host; the session was refused",
	"pty_start_failed":      "the agent could not start the shell (this may be your concurrent session limit; close another session and retry)",
	"internal":              "internal server error",
}

func (e *StatusError) Error() string {
	if t, ok := statusText[e.Code]; ok {
		return "terminal refused: " + e.Code + ": " + t
	}
	return "terminal refused: " + e.Code
}

// EndedError is a session that ended for a reason other than the shell
// exiting, or exited without a usable status.
type EndedError struct {
	Reason string
	Code   int
}

func (e *EndedError) Error() string {
	switch e.Reason {
	case "exited":
		return fmt.Sprintf("remote shell exited without a usable status (%d)", e.Code)
	case "max_duration":
		return "session ended: the maximum session duration was reached"
	case "agent_disconnected":
		return "session ended: the host's agent disconnected"
	case "stopped":
		return "session ended: the session was stopped"
	}
	return "session ended: " + e.Reason
}

var codeRE = regexp.MustCompile(`^[a-z_]{1,64}$`)

func clean(s string) string {
	if codeRE.MatchString(s) {
		return s
	}
	return "unknown"
}

type inFrame struct {
	Type    string `json:"type"`
	Payload struct {
		Status    string `json:"status"`
		Error     string `json:"error"`
		SessionID string `json:"session_id"`
		Code      *int   `json:"code"`
		Reason    string `json:"reason"`
	} `json:"payload"`
}

type inputFrame struct {
	Type    string `json:"type"`
	DataB64 string `json:"data_b64"`
}

type resizeFrame struct {
	Type string `json:"type"`
	Rows int    `json:"rows"`
	Cols int    `json:"cols"`
}

// Run opens the terminal and pumps stdin, resizes and output until the
// session ends. It returns the exit code for the process and, when that code
// is not the remote shell's own status, an error that explains it.
func Run(ctx context.Context, o Options) (int, error) {
	if err := client.ValidateWS(o.URL); err != nil {
		return ExitFailure, err
	}
	if o.HTTP == nil || o.Stdin == nil || o.Stdout == nil {
		return ExitFailure, errors.New("terminal: incomplete options")
	}
	ht := o.HandshakeTimeout
	if ht <= 0 {
		ht = 20 * time.Second
	}
	hctx, cancel := context.WithTimeout(ctx, ht)
	conn, resp, err := websocket.Dial(hctx, o.URL.String(), &websocket.DialOptions{HTTPClient: o.HTTP})
	cancel()
	if err != nil {
		return ExitFailure, dialError(resp, err)
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxServerFrame)

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		return conn.Write(sctx, websocket.MessageText, b)
	}

	go func() {
		buf := make([]byte, inputChunk)
		for {
			n, rerr := o.Stdin.Read(buf)
			if n > 0 {
				if send(inputFrame{Type: "pty_input", DataB64: base64.StdEncoding.EncodeToString(buf[:n])}) != nil {
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					_ = send(map[string]string{"type": "pty_eof"}) // a dead socket ends the session in the read loop
				}
				return
			}
		}
	}()
	if o.Resize != nil {
		go func() {
			for {
				select {
				case <-sctx.Done():
					return
				case s, ok := <-o.Resize:
					if !ok {
						return
					}
					if !s.Valid() {
						continue
					}
					if send(resizeFrame{Type: "pty_resize", Rows: s.Rows, Cols: s.Cols}) != nil {
						return
					}
				}
			}
		}()
	}

	for {
		typ, data, err := conn.Read(sctx)
		if err != nil {
			if ctx.Err() != nil {
				return ExitFailure, errors.New("session interrupted")
			}
			if cs := websocket.CloseStatus(err); cs != -1 {
				return ExitFailure, fmt.Errorf("connection closed before the session ended (close code %d)", int(cs))
			}
			return ExitFailure, errors.New("connection lost before the session ended")
		}
		if typ == websocket.MessageBinary {
			if _, werr := o.Stdout.Write(data); werr != nil {
				return ExitFailure, errors.New("cannot write to stdout")
			}
			continue
		}
		var f inFrame
		if json.Unmarshal(data, &f) != nil {
			continue // not a protocol frame; the contract only defines JSON text frames
		}
		switch f.Type {
		case "pty_status":
			if f.Payload.Error != "" {
				return ExitFailure, &StatusError{Code: clean(f.Payload.Error)}
			}
		case "pty_exit":
			_ = conn.Close(websocket.StatusNormalClosure, "") // the server closes too; the outcome is already known
			return exitFrom(f)
		}
	}
}

func exitFrom(f inFrame) (int, error) {
	code := -1
	if f.Payload.Code != nil {
		code = *f.Payload.Code
	}
	reason := clean(f.Payload.Reason)
	if reason == "exited" && code >= 0 && code <= 255 {
		return code, nil
	}
	return ExitFailure, &EndedError{Reason: reason, Code: code}
}

// dialError never includes the URL: it holds the ticket.
func dialError(resp *http.Response, err error) error {
	if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("terminal handshake refused (HTTP %d)", resp.StatusCode)
	}
	var cv *tls.CertificateVerificationError
	if errors.As(err, &cv) {
		return errors.New("terminal connection failed: TLS certificate verification failed")
	}
	var rh tls.RecordHeaderError
	if errors.As(err, &rh) {
		return errors.New("terminal connection failed: TLS handshake failed")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("terminal connection failed: handshake timed out")
	}
	return errors.New("terminal connection failed")
}

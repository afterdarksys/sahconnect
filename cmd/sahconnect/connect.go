package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/afterdarksys/sahconnect/internal/client"
	"github.com/afterdarksys/sahconnect/internal/config"
	"github.com/afterdarksys/sahconnect/internal/login"
	"github.com/afterdarksys/sahconnect/internal/terminal"
	"github.com/afterdarksys/sahconnect/internal/token"
	"github.com/afterdarksys/sahconnect/internal/tty"
)

// app holds the process's stdio so tests can drive commands.
type app struct {
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	stdinFd int
	sizeFd  int
	tty     tty.Ops
	env     config.Env
	sleep   func(context.Context, time.Duration) error // login poll wait; nil is a timer
}

func defaultApp() *app {
	sizeFd := int(os.Stdout.Fd())
	if !term.IsTerminal(sizeFd) {
		sizeFd = int(os.Stdin.Fd())
	}
	return &app{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr,
		stdinFd: int(os.Stdin.Fd()), sizeFd: sizeFd,
		tty: tty.System(), env: os.Getenv,
	}
}

func (a *app) errorf(format string, args ...any) {
	fmt.Fprintf(a.stderr, "sahconnect: "+format+"\n", args...)
}

// loadAuth picks the one credential for base.
//
//   - A token file that exists but is unsafe or invalid is an error. It is
//     never silently replaced by the API key.
//   - The bearer is used only for the origin that issued it.
//   - Token for this origin: the bearer wins over SYSTEMAPI_API_KEY.
//   - Token for another origin: SYSTEMAPI_API_KEY if set, else an error. The
//     bearer is never sent.
//
// note names the credential when the choice was not obvious ("" otherwise).
func loadAuth(cfg *config.Config, base *url.URL) (auth client.Auth, note string, err error) {
	tf, found, err := token.Read(cfg.TokenFile)
	if err != nil {
		return client.Auth{}, "", err
	}
	origin := token.Origin(base)
	switch {
	case found && tf.Origin == origin:
		if cfg.APIKey != "" {
			note = "credential: bearer from the token file (it wins over SYSTEMAPI_API_KEY)"
		}
		return client.Auth{Bearer: tf.Token, BearerOrigin: tf.Origin}, note, nil
	case found && cfg.APIKey != "":
		return client.Auth{APIKey: cfg.APIKey}, "credential: SYSTEMAPI_API_KEY (the token file is for " + tf.Origin + ", not " + origin + ")", nil
	case found:
		return client.Auth{}, "", fmt.Errorf("the token file is for %s, not %s: run sahconnect login --url %s, or set SYSTEMAPI_API_KEY", tf.Origin, origin, origin)
	case cfg.APIKey != "":
		return client.Auth{APIKey: cfg.APIKey}, "", nil
	}
	return client.Auth{}, "", errors.New("not logged in: run sahconnect login, or set SYSTEMAPI_API_KEY")
}

// parseOne parses flags placed before or after exactly one positional arg.
func parseOne(fs *flag.FlagSet, args []string) (string, error) {
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() == 0 {
		return "", errors.New("missing host name")
	}
	name := fs.Arg(0)
	if err := fs.Parse(fs.Args()[1:]); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", errors.New("one host name only")
	}
	return name, nil
}

// signalContext cancels on SIGINT, SIGTERM or SIGHUP and calls onSignal
// first (the tty restore). stop releases the handler.
func signalContext(onSignal func()) (context.Context, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case <-ch:
			if onSignal != nil {
				onSignal()
			}
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		signal.Stop(ch)
		close(done)
		cancel()
	}
}

// cmdConnect runs connect. bare is the `sahconnect [flags] <host>` form, where
// a subcommand name is never accepted as the host.
func (a *app) cmdConnect(args []string, bare bool) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	root := fs.Bool("root", false, "open a root shell (purpose terminal:root, admin scope)")
	method := fs.String("method", "", "agent, ssh, or agent,ssh (overrides config)")
	name, err := parseOne(fs, args)
	if err != nil {
		a.errorf("%v", err)
		return 2
	}
	if bare && reserved[name] {
		a.errorf("%q is a subcommand name; use sahconnect connect %s", name, name)
		return 2
	}
	cfg, err := config.Load(a.env)
	if err != nil {
		a.errorf("%v", err)
		return 2
	}
	methods := cfg.Methods
	if *method != "" {
		if methods, err = config.ParseMethods([]string{*method}); err != nil {
			a.errorf("%v", err)
			return 2
		}
	}
	if !hasMethod(methods, config.MethodAgent) {
		a.errorf("method ssh is not available until phase 3 (it needs a signed connect policy); use --method agent")
		return 2
	}
	if cfg.SystemAPIURL == "" {
		a.errorf("missing systemapi_url (config file) or SYSTEMAPI_URL")
		return 2
	}
	base, err := client.ValidateBase(cfg.SystemAPIURL)
	if err != nil {
		a.errorf("systemapi_url: %v", err)
		return 2
	}
	auth, note, err := loadAuth(cfg, base)
	if err != nil {
		a.errorf("%v", err)
		return 2
	}
	if note != "" {
		a.errorf("%s", note)
	}
	return a.connectAgent(base, auth, name, *root)
}

func hasMethod(ms []string, m string) bool {
	for _, x := range ms {
		if x == m {
			return true
		}
	}
	return false
}

// connectAgent is Method A. Phase 2 inserts the signed policy check before
// the ticket; phase 3 adds Method B beside it. Neither falls back here.
func (a *app) connectAgent(base *url.URL, auth client.Auth, name string, root bool) int {
	c := &client.Client{Base: base, Auth: auth, HTTP: client.NewHTTPClient(nil, 20*time.Second)}
	purpose := client.PurposeOpen
	if root {
		purpose = client.PurposeRoot
	}
	var mu sync.Mutex
	var restoreTTY func()
	ctx, stop := signalContext(func() {
		mu.Lock()
		r := restoreTTY
		mu.Unlock()
		if r != nil {
			r()
		}
	})
	defer stop()
	host, err := c.Resolve(ctx, name)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	tk, err := c.Ticket(ctx, host.HostID, purpose)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	rows, cols := 0, 0
	if w, h, err := term.GetSize(a.sizeFd); err == nil {
		rows, cols = h, w
	}
	u, err := client.TerminalURL(base, host.HostID, tk.Value, purpose, rows, cols)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	code, err := tty.WithRaw(a.stdinFd, a.tty, func(restore func()) (int, error) {
		mu.Lock()
		restoreTTY = restore
		mu.Unlock()
		resize := make(chan terminal.Size, 1)
		stopResize := watchResize(a.sizeFd, resize)
		defer stopResize()
		return terminal.Run(ctx, terminal.Options{
			URL: u, HTTP: client.NewHTTPClient(nil, 0),
			Stdin: a.stdin, Stdout: a.stdout, Resize: resize,
		})
	})
	if err != nil {
		a.errorf("%v", err)
		if code == 0 {
			code = terminal.ExitFailure
		}
	}
	return code
}

func (a *app) cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	rawURL := fs.String("url", "", "systemapi origin (overrides SYSTEMAPI_URL and config)")
	username := fs.String("username", "", "member user id (default $USER)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	cfg, err := config.Load(a.env)
	if err != nil {
		a.errorf("%v", err)
		return 2
	}
	target := cfg.SystemAPIURL
	if *rawURL != "" {
		target = *rawURL
	}
	if target == "" {
		a.errorf("missing --url, SYSTEMAPI_URL, or systemapi_url")
		return 2
	}
	base, err := client.ValidateBase(target)
	if err != nil {
		a.errorf("url: %v", err)
		return 2
	}
	user := *username
	if user == "" {
		user = a.env("USER")
	}
	if !login.ValidUsername(user) {
		a.errorf("invalid or missing --username")
		return 2
	}
	ctx, stop := signalContext(nil)
	defer stop()
	flow := &login.Flow{
		Base: base, Username: user, HTTP: client.NewHTTPClient(nil, 20*time.Second), Sleep: a.sleep,
		Show: func(p login.Prompt) {
			fmt.Fprintf(a.stderr, "Open %s, sign in with After Dark SSO, and enter code %s\n(signing in as %s; the code expires in %s)\nWaiting for approval...\n",
				p.VerificationURI, p.Code, user, p.ExpiresIn.Round(time.Second))
		},
	}
	res, err := flow.Run(ctx)
	if err != nil {
		a.errorf("login failed: %v", err)
		return 1
	}
	managed, err := config.Dir(a.env)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	if err := token.Write(cfg.TokenFile, token.Origin(base), res.Token, managed); err != nil {
		a.errorf("%v", err)
		return 1
	}
	fmt.Fprintf(a.stderr, "Logged in as %s at %s. Token saved to %s (sha256 %s), valid for %s.\n",
		user, token.Origin(base), cfg.TokenFile, token.Fingerprint(res.Token), res.ExpiresIn.Round(time.Second))
	return 0
}

func (a *app) cmdLogout(args []string) int {
	if len(args) != 0 {
		usage()
		return 2
	}
	cfg, err := config.Load(a.env)
	if err != nil {
		a.errorf("%v", err)
		return 2
	}
	removed, err := token.Delete(cfg.TokenFile)
	if err != nil {
		a.errorf("%v", err)
		return 1
	}
	if removed {
		fmt.Fprintf(a.stderr, "Logged out: removed %s.\n", cfg.TokenFile)
	} else {
		fmt.Fprintf(a.stderr, "Not logged in: %s does not exist.\n", cfg.TokenFile)
	}
	return 0
}

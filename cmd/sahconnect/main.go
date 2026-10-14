package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/sahconnect/internal/client"
	"github.com/afterdarksys/sahconnect/internal/config"
)

const version = "0.2.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

// reserved are the subcommand names. A host with one of these names is
// reached with `sahconnect connect <name>`; the bare form never shadows them.
var reserved = map[string]bool{
	"version": true, "help": true, "api": true, "ssh": true,
	"login": true, "logout": true, "connect": true,
}

func run(args []string) int {
	return defaultApp().run(args)
}

func (a *app) run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Println("sahconnect " + version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	case "api":
		return a.cmdAPI(args[1:])
	case "ssh":
		return cmdSSH(args[1:])
	case "login":
		return a.cmdLogin(args[1:])
	case "logout":
		return a.cmdLogout(args[1:])
	case "connect":
		return a.cmdConnect(args[1:])
	}
	if strings.HasPrefix(args[0], "-") || reserved[args[0]] {
		usage()
		return 2
	}
	return a.cmdConnect(args)
}

func usage() {
	fmt.Fprint(os.Stderr, `sahconnect `+version+` — SSH and systemapi client

  sahconnect <host> [--root] [--method agent]
  sahconnect connect <host> [--root] [--method agent]
  sahconnect login [--url URL] [--username USER]
  sahconnect logout
  sahconnect api METHOD /path [?query]
  sahconnect ssh -- [adssh arguments]
  sahconnect version

<host> is a hostname or host_id. A host named like a subcommand
(version, help, api, ssh, login, logout, connect) needs "connect <host>".

Config: $XDG_CONFIG_HOME/sahconnect/config.toml (default ~/.config/sahconnect),
or SAHCONNECT_CONFIG. SYSTEMAPI_URL overrides systemapi_url.
Credentials: the token file from "sahconnect login" (Authorization: Bearer),
else SYSTEMAPI_API_KEY (X-API-Key). Neither is printed.
http and ws are accepted only for loopback. ssh executes the adssh binary.
`)
}

func (a *app) cmdAPI(args []string) int {
	if len(args) < 2 || len(args) > 3 {
		usage()
		return 2
	}
	cfg, err := config.Load(a.env)
	if err != nil {
		fmt.Fprintln(a.stderr, err.Error())
		return 2
	}
	if strings.TrimSpace(cfg.SystemAPIURL) == "" {
		fmt.Fprintln(a.stderr, "missing SYSTEMAPI_URL")
		return 2
	}
	base, err := client.ValidateBase(cfg.SystemAPIURL)
	if err != nil {
		fmt.Fprintln(a.stderr, err.Error())
		return 2
	}
	auth, note, err := loadAuth(cfg, base)
	if err != nil {
		fmt.Fprintln(a.stderr, err.Error())
		return 2
	}
	if note != "" {
		fmt.Fprintln(a.stderr, note)
	}
	path := args[1]
	query := ""
	if i := strings.Index(path, "?"); i >= 0 {
		query = path[i+1:]
		path = path[:i]
	}
	if len(args) == 3 {
		if query != "" {
			fmt.Fprintln(a.stderr, "usage")
			return 2
		}
		query = strings.TrimPrefix(args[2], "?")
	}
	var body []byte
	if strings.ToUpper(args[0]) != "GET" && strings.ToUpper(args[0]) != "DELETE" {
		st, statErr := os.Stdin.Stat()
		if statErr == nil && st.Mode()&os.ModeCharDevice == 0 {
			body, err = io.ReadAll(io.LimitReader(os.Stdin, (256<<10)+1))
			if err != nil || len(body) > 256<<10 {
				fmt.Fprintln(a.stderr, "too_large")
				return 1
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := &client.Client{Base: base, Auth: auth}
	status, resp, err := c.Do(ctx, args[0], path, query, body)
	if err != nil {
		fmt.Fprintln(a.stderr, err.Error())
		return 1
	}
	fmt.Fprintf(a.stderr, "status=%d\n", status)
	_, _ = a.stdout.Write(resp)
	if len(resp) == 0 || resp[len(resp)-1] != '\n' {
		fmt.Fprintln(a.stdout)
	}
	if status >= 400 {
		return 1
	}
	return 0
}

func cmdSSH(args []string) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	bin := os.Getenv("SAHCONNECT_ADSSH")
	path, err := client.LookAdssh(bin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "adssh_missing")
		return 2
	}
	err = client.RunAdssh(context.Background(), path, args, os.Stdin, os.Stdout, os.Stderr)
	if err == nil {
		return 0
	}
	if code, ok := exitCode(err); ok {
		return code
	}
	fmt.Fprintln(os.Stderr, "adssh_failed")
	return 1
}

func exitCode(err error) (int, bool) {
	type coder interface{ ExitCode() int }
	if c, ok := err.(coder); ok {
		return c.ExitCode(), true
	}
	return 0, false
}

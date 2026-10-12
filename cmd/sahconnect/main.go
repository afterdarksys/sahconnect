package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/afterdarksys/sahconnect/internal/client"
)

const version = "0.1.0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
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
		return cmdAPI(args[1:])
	case "ssh":
		return cmdSSH(args[1:])
	default:
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sahconnect `+version+` — SSH and systemapi client

  sahconnect version
  sahconnect api METHOD /path [?query]
  sahconnect ssh -- [adssh arguments]

SYSTEMAPI_URL and SYSTEMAPI_API_KEY are required for api.
The key is sent as X-API-Key and is not printed.
http is accepted only for loopback. ssh executes the adssh binary.
`)
}

func cmdAPI(args []string) int {
	if len(args) < 2 || len(args) > 3 {
		usage()
		return 2
	}
	baseRaw := os.Getenv("SYSTEMAPI_URL")
	key := os.Getenv("SYSTEMAPI_API_KEY")
	if strings.TrimSpace(baseRaw) == "" {
		fmt.Fprintln(os.Stderr, "missing SYSTEMAPI_URL")
		return 2
	}
	if strings.TrimSpace(key) == "" {
		fmt.Fprintln(os.Stderr, "missing SYSTEMAPI_API_KEY")
		return 2
	}
	base, err := client.ValidateBase(baseRaw)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	path := args[1]
	query := ""
	if i := strings.Index(path, "?"); i >= 0 {
		query = path[i+1:]
		path = path[:i]
	}
	if len(args) == 3 {
		if query != "" {
			fmt.Fprintln(os.Stderr, "usage")
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
				fmt.Fprintln(os.Stderr, "too_large")
				return 1
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	status, resp, err := client.Do(ctx, base, key, args[0], path, query, body)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}
	fmt.Fprintf(os.Stderr, "status=%d\n", status)
	_, _ = os.Stdout.Write(resp)
	if len(resp) == 0 || resp[len(resp)-1] != '\n' {
		fmt.Println()
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

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestVersionUsageAndURLGuards(t *testing.T) {
	if run([]string{"version"}) != 0 {
		t.Fatal("version")
	}
	if run(nil) != 2 {
		t.Fatal("usage")
	}
	t.Setenv("XDG_CONFIG_HOME", t.TempDir()) // no token file, no config file
	t.Setenv("SAHCONNECT_CONFIG", "")
	t.Setenv("SYSTEMAPI_URL", "")
	t.Setenv("SYSTEMAPI_API_KEY", "secret-key-value")
	if run([]string{"api", "GET", "/api/v1/fleet"}) != 2 {
		t.Fatal("missing url")
	}
	t.Setenv("SYSTEMAPI_URL", "http://cp.example")
	t.Setenv("SYSTEMAPI_API_KEY", "")
	if run([]string{"api", "GET", "/api/v1/fleet"}) != 2 {
		t.Fatal("missing key")
	}
	t.Setenv("SYSTEMAPI_URL", "http://cp.example")
	t.Setenv("SYSTEMAPI_API_KEY", "secret-key-value")
	if run([]string{"api", "GET", "/api/v1/fleet"}) != 2 {
		t.Fatal("public http accepted")
	}
	t.Setenv("SYSTEMAPI_URL", "https://cp.example")
	if run([]string{"api", "GET", "/api/v1/fleet?api_key=secret-key-value"}) != 1 {
		t.Fatal("api_key query accepted")
	}
}

func TestSSHExecutesNamedBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "adssh")
	out := filepath.Join(dir, "out")
	script := "#!/bin/sh\nprintf '%s\\n' \"$1\" > '" + out + "'\nexit 3\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SAHCONNECT_ADSSH", bin)
	if code := run([]string{"ssh", "--", "version"}); code != 3 {
		t.Fatalf("code %d", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "version\n" {
		t.Fatalf("arg %q", got)
	}
	t.Setenv("SAHCONNECT_ADSSH", filepath.Join(dir, "missing"))
	if run([]string{"ssh", "--", "version"}) != 2 {
		t.Fatal("missing binary")
	}
	_ = exec.Command("true").Run()
}

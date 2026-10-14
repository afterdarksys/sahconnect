package token

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const secret = "SENTINEL-TOKEN-0123456789abcdef"

func TestWriteIsPrivateAndAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg", "sahconnect")
	path := filepath.Join(dir, "token")
	if err := Write(path, secret); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("token mode %o", st.Mode().Perm())
	}
	dst, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dst.Mode().Perm())
	}
	got, found, err := Read(path)
	if err != nil || !found || got != secret {
		t.Fatalf("read %q %v %v", got, found, err)
	}
	// Overwrite replaces the file by rename: a new inode, no temp left behind.
	before, _ := os.Stat(path)
	if err := Write(path, secret+"X"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) {
		t.Fatal("overwrite was in place, not an atomic rename")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left: %v", entries)
	}
	// A failed write leaves the previous token intact and no temp file.
	if err := Write(path, "short"); err == nil {
		t.Fatal("invalid token written")
	}
	got, _, _ = Read(path)
	if got != secret+"X" {
		t.Fatal("failed write clobbered the token")
	}
	entries, _ = os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left after failure: %v", entries)
	}
}

func TestErrorsNeverContainToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(secret), 0o644); err != nil {
		t.Fatal(err)
	}
	_, found, err := Read(path)
	if err == nil || !found {
		t.Fatal("world-readable token accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("error leaked the token")
	}
	if err := os.WriteFile(path, []byte("bad token with spaces"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err = Read(path)
	if err == nil || strings.Contains(err.Error(), "spaces") {
		t.Fatalf("bad token: %v", err)
	}
	if strings.Contains(Fingerprint(secret), secret) || len(Fingerprint(secret)) != 16 {
		t.Fatal("fingerprint")
	}
}

func TestRefusesInsecureDirAndSymlink(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "shared")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(dir, "token"), secret); err == nil {
		t.Fatal("world-writable dir accepted")
	}
	real := filepath.Join(t.TempDir(), "real")
	if err := os.WriteFile(real, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(link); err == nil {
		t.Fatal("symlinked token accepted")
	}
	if err := Write("relative/token", secret); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestMissingAndDelete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if _, found, err := Read(path); found || err != nil {
		t.Fatalf("missing: %v %v", found, err)
	}
	if removed, err := Delete(path); removed || err != nil {
		t.Fatalf("delete missing: %v %v", removed, err)
	}
	if err := Write(path, secret); err != nil {
		t.Fatal(err)
	}
	if removed, err := Delete(path); !removed || err != nil {
		t.Fatalf("delete: %v %v", removed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("still present")
	}
}

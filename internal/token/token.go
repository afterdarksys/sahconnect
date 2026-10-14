// Package token stores the device-login bearer token.
//
// Threats: the bearer is a session for its TTL (one hour server side). It is
// written 0600 under a 0700 directory, atomically (temp file in the same
// directory, fsync, rename), so a crash never leaves a partial or
// world-readable token. A token file or directory that other users can read
// or write is refused rather than used. The token is never printed or logged:
// callers show Fingerprint, a truncated SHA-256. Does NOT encrypt the token at
// rest and does NOT protect it from the account's own user or root.
package token

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// MaxLen bounds a stored token.
const MaxLen = 512

// Valid reports whether s is a plausible opaque bearer: 16-512 printable
// ASCII characters with no whitespace.
func Valid(s string) bool {
	if len(s) < 16 || len(s) > MaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Fingerprint is the first 16 hex characters of SHA-256(token): safe to show.
func Fingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])[:16]
}

// Write stores tok at path with mode 0600, atomically. The parent directory
// is created 0700 when missing and refused when group- or world-writable.
func Write(path, tok string) error {
	if !filepath.IsAbs(path) {
		return errors.New("token file path must be absolute")
	}
	if !Valid(tok) {
		return errors.New("token rejected")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("token directory: %w", err)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("token directory %s is group- or world-writable", dir)
	}
	tmp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if _, err := tmp.WriteString(tok); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("token file: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync() // best effort: persist the rename; the token is already in place
		_ = d.Close()
	}
	return nil
}

// Read returns the stored token. found is false when no file exists. A file
// that is not regular, is readable or writable by group or others, or does
// not hold a valid token is an error: the caller must not fall back silently.
func Read(path string) (tok string, found bool, err error) {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("token file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return "", true, fmt.Errorf("token file %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", true, fmt.Errorf("token file %s is readable or writable by others (chmod 600, then sahconnect login)", path)
	}
	if st.Size() > MaxLen+2 {
		return "", true, fmt.Errorf("token file %s is too large", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", true, fmt.Errorf("token file: %w", err)
	}
	s := string(b)
	if n := len(s); n > 0 && s[n-1] == '\n' {
		s = s[:n-1]
	}
	if !Valid(s) {
		return "", true, fmt.Errorf("token file %s does not hold a valid token (run sahconnect login)", path)
	}
	return s, true, nil
}

// Delete removes the token file. removed is false when there was none.
func Delete(path string) (removed bool, err error) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("token file: %w", err)
	}
	return true, nil
}

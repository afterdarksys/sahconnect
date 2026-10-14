//go:build !unix

package main

import "github.com/afterdarksys/sahconnect/internal/terminal"

// watchResize is a no-op where SIGWINCH does not exist.
func watchResize(int, chan<- terminal.Size) (stop func()) { return func() {} }

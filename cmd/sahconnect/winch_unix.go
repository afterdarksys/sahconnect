//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/afterdarksys/sahconnect/internal/terminal"
)

// watchResize sends the window size on every SIGWINCH until stop is called.
func watchResize(fd int, out chan<- terminal.Size) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ch:
				w, h, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				select {
				case out <- terminal.Size{Rows: h, Cols: w}:
				default: // a resize is already queued; the next SIGWINCH carries the latest size
				}
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

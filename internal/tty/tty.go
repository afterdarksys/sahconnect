// Package tty puts the local terminal in raw mode for a session and always
// restores it.
//
// Threats: a terminal left in raw mode after a crash, a signal, or an error
// is a usability failure that hides later input. Restore runs on return, on
// error, on panic (the deferred restore runs while panicking, then the panic
// continues), and when a signal handler calls the restore func early. Restore
// is idempotent. Does NOT handle panics in other goroutines, which end the
// process without running defers; the session goroutines do not panic on
// input.
package tty

import (
	"sync"

	"golang.org/x/term"
)

// Ops abstracts golang.org/x/term so tests can observe raw and restore.
type Ops struct {
	IsTerminal func(fd int) bool
	MakeRaw    func(fd int) (*term.State, error)
	Restore    func(fd int, st *term.State) error
}

// System is the real terminal.
func System() Ops {
	return Ops{IsTerminal: term.IsTerminal, MakeRaw: term.MakeRaw, Restore: term.Restore}
}

// WithRaw runs body with fd in raw mode when fd is a terminal, and as-is when
// it is not (piped stdin). body receives an idempotent restore func for
// signal handlers. The terminal is restored before WithRaw returns or panics.
func WithRaw(fd int, ops Ops, body func(restore func()) (int, error)) (int, error) {
	if !ops.IsTerminal(fd) {
		return body(func() {})
	}
	st, err := ops.MakeRaw(fd)
	if err != nil {
		return 0, err
	}
	var once sync.Once
	restore := func() {
		once.Do(func() { _ = ops.Restore(fd, st) }) // nothing more can be done if the tty refuses
	}
	defer restore()
	return body(restore)
}

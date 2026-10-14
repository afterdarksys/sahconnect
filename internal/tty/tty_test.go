package tty

import (
	"errors"
	"testing"

	"golang.org/x/term"
)

type rec struct{ raw, restored int }

func fakeOps(r *rec, isTTY bool) Ops {
	return Ops{
		IsTerminal: func(int) bool { return isTTY },
		MakeRaw:    func(int) (*term.State, error) { r.raw++; return &term.State{}, nil },
		Restore:    func(int, *term.State) error { r.restored++; return nil },
	}
}

func TestRestoredOnError(t *testing.T) {
	r := &rec{}
	code, err := WithRaw(0, fakeOps(r, true), func(func()) (int, error) {
		if r.raw != 1 || r.restored != 0 {
			t.Fatal("not raw inside body")
		}
		return 255, errors.New("boom")
	})
	if code != 255 || err == nil || r.restored != 1 {
		t.Fatalf("code %d err %v restored %d", code, err, r.restored)
	}
}

func TestRestoredOnPanic(t *testing.T) {
	r := &rec{}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("panic swallowed")
			}
		}()
		_, _ = WithRaw(0, fakeOps(r, true), func(func()) (int, error) { panic("boom") })
	}()
	if r.restored != 1 {
		t.Fatalf("restored %d", r.restored)
	}
}

func TestEarlyRestoreIsIdempotent(t *testing.T) {
	r := &rec{}
	_, _ = WithRaw(0, fakeOps(r, true), func(restore func()) (int, error) {
		restore() // a signal handler
		restore()
		return 0, nil
	})
	if r.restored != 1 {
		t.Fatalf("restored %d", r.restored)
	}
}

func TestNotATerminalSkipsRaw(t *testing.T) {
	r := &rec{}
	code, err := WithRaw(0, fakeOps(r, false), func(restore func()) (int, error) { restore(); return 7, nil })
	if code != 7 || err != nil || r.raw != 0 || r.restored != 0 {
		t.Fatalf("%d %v %+v", code, err, r)
	}
	failing := fakeOps(r, true)
	failing.MakeRaw = func(int) (*term.State, error) { return nil, errors.New("no tty") }
	ran := false
	if _, err := WithRaw(0, failing, func(func()) (int, error) { ran = true; return 0, nil }); err == nil || ran {
		t.Fatal("body ran after MakeRaw failed")
	}
}

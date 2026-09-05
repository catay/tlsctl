package cmd

import (
	"io"
	"os"
	"time"
)

// Runtime holds shared runtime dependencies for CLI commands.
type Runtime struct {
	Stdin       io.Reader
	Stdout      io.Writer
	Stderr      io.Writer
	Now         func() time.Time
	ExitTracker *ExitTracker
}

func NewRuntime() *Runtime {
	return &Runtime{
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		Now:         func() time.Time { return time.Now().UTC() },
		ExitTracker: NewExitTracker(),
	}
}

func (r *Runtime) NowFunc() time.Time {
	if r == nil || r.Now == nil {
		return time.Now().UTC()
	}
	return r.Now()
}

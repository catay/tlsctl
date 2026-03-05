package cmd

import (
	"bytes"
	"testing"
)

func TestVersionCmdWritesToRuntimeStdout(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	version, commit, date = "1.2.3", "abc123", "2026-03-05"
	defer func() {
		version, commit, date = origVersion, origCommit, origDate
	}()

	var out bytes.Buffer
	rt := &Runtime{Stdout: &out}
	cmd := newVersionCmd(rt)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error executing version command: %v", err)
	}

	const want = "tlsctl version 1.2.3 (commit: abc123, built: 2026-03-05)\n"
	if got := out.String(); got != want {
		t.Fatalf("unexpected version output:\n got: %q\nwant: %q", got, want)
	}
}

package cmd

import (
	"time"

	"github.com/catay/tlsctl/internal/revocation"
	"github.com/catay/tlsctl/internal/tlsquery"
)

const (
	ExitOK              = 0
	ExitRuntimeError    = 1
	ExitInsecure        = 2
	ExitRevocationError = 3
)

func setExitCode(code int) {
	if exitCode == ExitRuntimeError {
		return
	}
	if code == ExitRuntimeError || code > exitCode {
		exitCode = code
	}
}

func updateExitCodeForChain(chain *tlsquery.ChainInfo, now time.Time) {
	if chain == nil {
		return
	}
	leaf, err := chain.Leaf()
	if err != nil {
		return
	}

	if leaf.Revocation != nil && leaf.Revocation.OverallStatus == revocation.StatusError {
		setExitCode(ExitRevocationError)
		return
	}

	if leaf.Revocation != nil && leaf.Revocation.OverallStatus == revocation.StatusRevoked {
		setExitCode(ExitInsecure)
		return
	}

	if !chain.Verified {
		setExitCode(ExitInsecure)
		return
	}

	notAfter, err := leaf.NotAfterTime()
	if err != nil {
		return
	}
	if now.After(notAfter) {
		setExitCode(ExitInsecure)
	}
}

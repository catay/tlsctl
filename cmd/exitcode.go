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
	ExitExpiring        = 4
)

// exitPriority defines the escalation order for exit codes.
// Higher priority wins; once set, a lower-priority code cannot replace it.
var exitPriority = map[int]int{
	ExitOK:              0,
	ExitExpiring:        1,
	ExitInsecure:        2,
	ExitRevocationError: 3,
	ExitRuntimeError:    4,
}

func setExitCode(code int) {
	if exitPriority[code] > exitPriority[exitCode] {
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
		return
	}
	daysUntilExpiry := int(notAfter.Sub(now).Hours() / 24)
	if daysUntilExpiry <= 30 {
		setExitCode(ExitExpiring)
	}
}

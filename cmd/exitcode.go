package cmd

import (
	"sync"
	"time"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
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

type ExitTracker struct {
	mu   sync.Mutex
	code int
}

func NewExitTracker() *ExitTracker {
	return &ExitTracker{code: ExitOK}
}

func (t *ExitTracker) Code() int {
	if t == nil {
		return ExitOK
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.code
}

func (t *ExitTracker) Reset() {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.code = ExitOK
	t.mu.Unlock()
}

func (t *ExitTracker) Set(code int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if exitPriority[code] > exitPriority[t.code] {
		t.code = code
	}
}

func updateExitCodeForChain(tracker *ExitTracker, chain *tlsquery.ChainInfo, now time.Time, warningDays ...int) {
	if chain == nil || tracker == nil {
		return
	}
	threshold := 30
	if len(warningDays) > 0 {
		threshold = warningDays[0]
	}
	switch chain.Health(now, threshold).Status {
	case "insecure":
		tracker.Set(ExitInsecure)
	case "revocation_error":
		tracker.Set(ExitRevocationError)
	case "expiring":
		tracker.Set(ExitExpiring)
	}
}

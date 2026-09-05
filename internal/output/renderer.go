package output

import (
	"io"
	"time"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

type Renderer interface {
	Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error
}

type MultiRenderer interface {
	RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error
}

type Options struct {
	Now               func() time.Time
	ExpiryWarningDays int
}

func (o Options) NowFunc() time.Time {
	if o.Now == nil {
		return time.Now().UTC()
	}
	return o.Now()
}

func (o Options) WarningDays() int {
	if o.ExpiryWarningDays <= 0 {
		return 30
	}
	return o.ExpiryWarningDays
}

func resultsFromChains(chains []*tlsquery.ChainInfo) []TargetResult {
	results := make([]TargetResult, 0, len(chains))
	for _, chain := range chains {
		if chain != nil {
			results = append(results, TargetResult{Target: chain.InputName, Result: chain})
		}
	}
	return results
}

// checkedWriter retains the first write error across formatted output calls.
type checkedWriter struct {
	writer io.Writer
	err    error
}

func (w *checkedWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.writer.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	w.err = err
	return n, err
}

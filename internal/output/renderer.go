package output

import (
	"io"
	"time"

	"github.com/catay/tlsctl/internal/tlsquery"
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

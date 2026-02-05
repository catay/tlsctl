package output

import (
	"io"
	"time"

	"github.com/tlsctl/internal/tlsquery"
)

type Renderer interface {
	Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error
}

type Options struct {
	Insecure bool
	Now      func() time.Time
}

func (o Options) NowFunc() time.Time {
	if o.Now == nil {
		return time.Now().UTC()
	}
	return o.Now()
}

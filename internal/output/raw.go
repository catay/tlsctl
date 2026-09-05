package output

import (
	"fmt"
	"io"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

type RawPEMRenderer struct{}

func (RawPEMRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	out := &checkedWriter{writer: w}
	w = out
	for _, cert := range chain.Certificates {
		fmt.Fprint(w, cert.PEM)
	}
	return out.err
}

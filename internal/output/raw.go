package output

import (
	"fmt"
	"io"

	"github.com/tlsctl/internal/tlsquery"
)

type RawPEMRenderer struct{}

func (RawPEMRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	for _, cert := range chain.Certificates {
		fmt.Fprint(w, cert.PEM)
	}
	return nil
}

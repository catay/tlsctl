package output

import (
	"fmt"
	"io"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

type RawPEMRenderer struct{}

func (RawPEMRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	for _, cert := range chain.Certificates {
		fmt.Fprint(w, cert.PEM)
	}
	return nil
}

package output

import (
	"encoding/json"
	"io"

	"github.com/catay/tlsctl/internal/tlsquery"
)

type JSONRenderer struct{}

func (JSONRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	outputData := chain.WithoutPEM()
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(outputData)
}

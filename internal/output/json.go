package output

import (
	"encoding/json"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"io"
)

type JSONRenderer struct{}

func (r JSONRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	return r.RenderAll(w, []*tlsquery.ChainInfo{chain}, opts)
}
func (r JSONRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	return r.RenderBatch(w, resultsFromChains(chains), opts)
}
func (JSONRenderer) RenderBatch(w io.Writer, results []TargetResult, opts Options) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(toBatchEnvelope(results, opts))
}

package output

import (
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"gopkg.in/yaml.v3"
	"io"
)

type YAMLRenderer struct{}

func (r YAMLRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	return r.RenderAll(w, []*tlsquery.ChainInfo{chain}, opts)
}
func (r YAMLRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	return r.RenderBatch(w, resultsFromChains(chains), opts)
}
func (YAMLRenderer) RenderBatch(w io.Writer, results []TargetResult, opts Options) error {
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(toBatchEnvelope(results, opts))
}

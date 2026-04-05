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

func (JSONRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	clean := make([]tlsquery.ChainInfo, len(chains))
	for i, chain := range chains {
		clean[i] = *chain.WithoutPEM()
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(clean)
}

func (JSONRenderer) RenderBatch(w io.Writer, results []TargetResult, opts Options) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if opts.FormatVersionOrDefault() >= 2 {
		return encoder.Encode(toBatchEnvelopeV2(results, opts))
	}
	return encoder.Encode(toBatchResultsV1(results))
}

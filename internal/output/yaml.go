package output

import (
	"io"

	"github.com/catay/tlsctl/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

type YAMLRenderer struct{}

func (YAMLRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	outputData := chain.WithoutPEM()
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(outputData)
}

func (YAMLRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	clean := make([]tlsquery.ChainInfo, len(chains))
	for i, chain := range chains {
		clean[i] = *chain.WithoutPEM()
	}
	encoder := yaml.NewEncoder(w)
	encoder.SetIndent(2)
	return encoder.Encode(clean)
}

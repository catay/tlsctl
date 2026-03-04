package output

import "fmt"

type Format string

const (
	FormatDefault Format = ""
	FormatHuman   Format = "human"
	FormatJSON    Format = "json"
	FormatYAML    Format = "yaml"
	FormatText    Format = "text"
	FormatRaw     Format = "raw"
)

func New(format Format) (Renderer, error) {
	switch format {
	case FormatDefault, FormatHuman:
		return HumanRenderer{}, nil
	case FormatJSON:
		return JSONRenderer{}, nil
	case FormatYAML:
		return YAMLRenderer{}, nil
	case FormatText:
		return VerboseTextRenderer{}, nil
	case FormatRaw:
		return RawPEMRenderer{}, nil
	default:
		return nil, fmt.Errorf("invalid output format: %q (valid: human, json, yaml, text, raw)", format)
	}
}

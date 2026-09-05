package output

import (
	"io"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

type ResultStatus string
type TLSStatus string

const (
	StatusSuccess        ResultStatus = "success"
	StatusFailure        ResultStatus = "failure"
	StatusPartialSuccess ResultStatus = "partial_success"

	TLSStatusSecure          TLSStatus = "secure"
	TLSStatusInsecure        TLSStatus = "insecure"
	TLSStatusExpiring        TLSStatus = "expiring"
	TLSStatusRevocationError TLSStatus = "revocation_error"
)

type TargetResult struct {
	Target string
	Error  string
	Result *tlsquery.ChainInfo
}

type Summary struct {
	Total     int `json:"total" yaml:"total"`
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	Failed    int `json:"failed" yaml:"failed"`
}

type BatchEnvelope struct {
	Status  ResultStatus  `json:"status" yaml:"status"`
	Summary Summary       `json:"summary" yaml:"summary"`
	Results []BatchResult `json:"results" yaml:"results"`
}

type BatchResult struct {
	Target    string              `json:"target" yaml:"target"`
	Status    ResultStatus        `json:"status" yaml:"status"`
	TLSStatus TLSStatus           `json:"tls_status,omitempty" yaml:"tls_status,omitempty"`
	Error     string              `json:"error,omitempty" yaml:"error,omitempty"`
	Result    *tlsquery.ChainInfo `json:"result,omitempty" yaml:"result,omitempty"`
}

// BatchRenderer renders per-target results, including failed targets.
type BatchRenderer interface {
	RenderBatch(w io.Writer, results []TargetResult, opts Options) error
}

func (r TargetResult) Status() ResultStatus {
	if r.Error != "" {
		return StatusFailure
	}
	return StatusSuccess
}

func (r TargetResult) TLSStatus(opts Options) TLSStatus {
	if r.Error != "" || r.Result == nil {
		return ""
	}
	return TLSStatus(r.Result.Health(opts.NowFunc(), opts.WarningDays()).Status)
}

func (r TargetResult) WithoutPEM() TargetResult {
	out := r
	if r.Result != nil {
		out.Result = r.Result.WithoutPEM()
	}
	return out
}

func cleanTargetResults(results []TargetResult) []TargetResult {
	clean := make([]TargetResult, len(results))
	for i, result := range results {
		clean[i] = result.WithoutPEM()
	}
	return clean
}

func toBatchEnvelope(results []TargetResult, opts Options) BatchEnvelope {
	clean := cleanTargetResults(results)
	out := BatchEnvelope{
		Summary: Summary{
			Total: len(clean),
		},
		Results: make([]BatchResult, len(clean)),
	}

	for i, result := range clean {
		status := result.Status()
		if status == StatusSuccess {
			out.Summary.Succeeded++
		} else {
			out.Summary.Failed++
		}

		out.Results[i] = BatchResult{
			Target:    result.Target,
			Status:    status,
			TLSStatus: result.TLSStatus(opts),
			Error:     result.Error,
			Result:    result.Result,
		}
	}

	switch {
	case out.Summary.Total == 0:
		out.Status = StatusSuccess
	case out.Summary.Failed == 0:
		out.Status = StatusSuccess
	case out.Summary.Succeeded == 0:
		out.Status = StatusFailure
	default:
		out.Status = StatusPartialSuccess
	}

	return out
}

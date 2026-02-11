package revocation

import (
	"crypto/x509"
	"net/http"
	"time"
)

type Checker struct {
	client HTTPDoer
	now    func() time.Time
}

func NewChecker(client HTTPDoer, now func() time.Time) *Checker {
	if client == nil {
		client = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}
	return &Checker{client: client, now: now}
}

func (c *Checker) CheckCert(leaf, issuer *x509.Certificate, opts Options) *RevocationInfo {
	now := c.now()
	info := &RevocationInfo{
		CheckedAt: now.UTC().Format(time.RFC3339),
	}

	methods := opts.Methods
	if len(methods) == 0 {
		methods = []Method{MethodCRL}
	}

	for _, method := range methods {
		var results []Result
		switch method {
		case MethodCRL:
			results = c.checkCRL(leaf, issuer, opts)
		case MethodOCSP:
			results = c.checkOCSP(leaf, issuer, opts)
		}
		for _, r := range results {
			info.Results = append(info.Results, resultToRevocationResult(r))
		}
	}

	info.OverallStatus = computeOverallStatus(info.Results)
	return info
}

func resultToRevocationResult(r Result) RevocationResult {
	rr := RevocationResult{
		Method:       string(r.Method),
		Status:       string(r.Status),
		ResponderURL: r.ResponderURL,
		Reason:       r.Reason,
		Error:        r.Error,
	}
	if r.RevokedAt != nil {
		rr.RevokedAt = r.RevokedAt.UTC().Format(time.RFC3339)
	}
	return rr
}

func computeOverallStatus(results []RevocationResult) string {
	if len(results) == 0 {
		return string(StatusNotChecked)
	}

	hasGood := false
	hasError := false
	for _, r := range results {
		switch Status(r.Status) {
		case StatusRevoked:
			return string(StatusRevoked)
		case StatusGood:
			hasGood = true
		case StatusError:
			hasError = true
		}
	}

	if hasGood {
		return string(StatusGood)
	}
	if hasError {
		return string(StatusError)
	}
	return string(StatusUnknown)
}

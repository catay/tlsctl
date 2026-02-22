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
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Checker{client: client, now: now}
}

func (c *Checker) CheckCert(leaf, issuer *x509.Certificate, opts Options) *Info {
	nowFunc := c.now
	if opts.Now != nil {
		nowFunc = opts.Now
	}
	now := nowFunc()
	info := &Info{
		CheckedAt: now.Format(time.RFC3339),
	}

	methods := opts.Methods
	if len(methods) == 0 {
		methods = []Method{MethodCRL}
	}

	for _, method := range methods {
		var results []Result
		switch method {
		case MethodCRL:
			results = c.checkCRL(leaf, issuer, opts, now)
		case MethodOCSP:
			results = c.checkOCSP(leaf, issuer, opts, now)
		}
		info.Results = append(info.Results, results...)
	}

	info.OverallStatus = computeOverallStatus(info.Results)
	return info
}

func computeOverallStatus(results []Result) Status {
	if len(results) == 0 {
		return StatusNotChecked
	}

	hasGood := false
	hasError := false
	for _, r := range results {
		switch r.Status {
		case StatusRevoked:
			return StatusRevoked
		case StatusGood:
			hasGood = true
		case StatusError:
			hasError = true
		}
	}

	if hasGood {
		return StatusGood
	}
	if hasError {
		return StatusError
	}
	return StatusUnknown
}

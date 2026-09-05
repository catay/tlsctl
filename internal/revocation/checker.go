package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
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

	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	methods := opts.Methods
	if len(methods) == 0 {
		methods = []Method{MethodCRL}
	}

	for _, method := range methods {
		var results []Result
		if leaf == nil {
			results = []Result{{Method: method, Status: StatusNotChecked, Error: "no certificate available"}}
		} else {
			switch method {
			case MethodCRL:
				results = c.checkCRL(leaf, issuer, opts, now)
			case MethodOCSP:
				results = c.checkOCSP(leaf, issuer, opts, now)
			}
		}
		info.Results = append(info.Results, results...)
	}

	info.OverallStatus = computeOverallStatus(info.Results)
	if info.OverallStatus != StatusGood && info.OverallStatus != StatusRevoked {
		if !opts.SoftFail {
			info.OverallStatus = StatusError
		} else if info.OverallStatus == StatusError {
			info.OverallStatus = StatusUnknown
		}
	}
	return info
}

// ValidateIssuer checks the name and signature relationship, not the issuer's
// trust in the system root store. Trust is reported by certificate verification.
func ValidateIssuer(leaf, issuer *x509.Certificate) error {
	if issuer == nil {
		return fmt.Errorf("no issuer certificate available")
	}
	if !bytes.Equal(leaf.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("issuer name does not match certificate")
	}
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("invalid issuer: %w", err)
	}
	return nil
}

// Responses without NextUpdate are accepted for at most 24 hours. A five-minute
// clock skew allowance applies to ThisUpdate only.
func checkFreshness(thisUpdate, nextUpdate, now time.Time, kind string) error {
	if thisUpdate.IsZero() || thisUpdate.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("invalid %s: ThisUpdate is missing or in the future", kind)
	}
	if !nextUpdate.IsZero() {
		if !nextUpdate.After(thisUpdate) {
			return fmt.Errorf("invalid %s: NextUpdate must follow ThisUpdate", kind)
		}
		if !now.Before(nextUpdate) {
			return fmt.Errorf("stale %s: past NextUpdate time", kind)
		}
	} else if now.Sub(thisUpdate) > 24*time.Hour {
		return fmt.Errorf("stale %s: ThisUpdate is older than 24 hours without NextUpdate", kind)
	}
	return nil
}

func computeOverallStatus(results []Result) Status {
	if len(results) == 0 {
		return StatusNotChecked
	}

	hasGood := false
	hasError := false
	allNotSupported := true
	for _, r := range results {
		if r.Status != StatusNotSupported {
			allNotSupported = false
		}
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
	if allNotSupported {
		return StatusNotSupported
	}
	if hasError {
		return StatusError
	}
	return StatusUnknown
}

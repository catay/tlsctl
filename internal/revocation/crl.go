package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

func (c *Checker) checkCRL(leaf, issuer *x509.Certificate, opts Options, now time.Time) []Result {
	if len(leaf.CRLDistributionPoints) == 0 {
		return []Result{{
			Method: MethodCRL,
			Status: StatusNotSupported,
			Error:  "no CRL distribution points",
		}}
	}

	if err := ValidateIssuer(leaf, issuer); err != nil {
		return []Result{{Method: MethodCRL, Status: StatusNotChecked, Error: err.Error()}}
	}
	var results []Result
	for _, dp := range leaf.CRLDistributionPoints {
		result := c.fetchAndCheckCRL(opts.Context, leaf, issuer, dp, opts.Timeout, now)
		results = append(results, result)
		if result.Status == StatusGood || result.Status == StatusRevoked {
			break
		}
		if opts.Context.Err() != nil {
			break
		}
	}
	return results
}

func (c *Checker) fetchAndCheckCRL(parent context.Context, leaf, issuer *x509.Certificate, dpURL string, timeout time.Duration, now time.Time) Result {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, dpURL, nil)
	if err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("invalid CRL URL: %v", err),
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("failed to fetch CRL: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("CRL server returned HTTP %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("failed to read CRL response: %v", err),
		}
	}

	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("failed to parse CRL: %v", err),
		}
	}

	if issuer == nil || !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return Result{Method: MethodCRL, Status: StatusError, ResponderURL: dpURL, Error: "CRL issuer does not match certificate issuer"}
	}
	for _, ext := range crl.Extensions {
		if ext.Critical {
			return Result{Method: MethodCRL, Status: StatusError, ResponderURL: dpURL, Error: "unsupported critical CRL extension"}
		}
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusError,
			ResponderURL: dpURL,
			Error:        fmt.Sprintf("CRL signature verification failed: %v", err),
		}
	}

	if err := checkFreshness(crl.ThisUpdate, crl.NextUpdate, now, "CRL"); err != nil {
		return Result{
			Method:       MethodCRL,
			Status:       StatusUnknown,
			ResponderURL: dpURL,
			Error:        err.Error(),
		}
	}

	for _, entry := range crl.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical {
				return Result{Method: MethodCRL, Status: StatusError, ResponderURL: dpURL, Error: "unsupported critical CRL entry extension"}
			}
		}
		if entry.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			revokedAt := entry.RevocationTime
			return Result{
				Method:       MethodCRL,
				Status:       StatusRevoked,
				ResponderURL: dpURL,
				RevokedAt:    &revokedAt,
				Reason:       formatRevocationReason(entry.ReasonCode),
			}
		}
	}

	return Result{
		Method:       MethodCRL,
		Status:       StatusGood,
		ResponderURL: dpURL,
	}
}

func formatRevocationReason(code int) string {
	switch code {
	case 0:
		return "unspecified"
	case 1:
		return "key compromise"
	case 2:
		return "CA compromise"
	case 3:
		return "affiliation changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation of operation"
	case 6:
		return "certificate hold"
	case 8:
		return "remove from CRL"
	case 9:
		return "privilege withdrawn"
	case 10:
		return "AA compromise"
	default:
		return fmt.Sprintf("unknown (%d)", code)
	}
}

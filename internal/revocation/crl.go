package revocation

import (
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
			Status: StatusNotChecked,
			Error:  "no CRL distribution points",
		}}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	for _, dp := range leaf.CRLDistributionPoints {
		result := c.fetchAndCheckCRL(leaf, issuer, dp, timeout, now)
		if result.Status == StatusGood || result.Status == StatusRevoked {
			return []Result{result}
		}
		if result.Status == StatusError || result.Status == StatusUnknown {
			if opts.SoftFail {
				return []Result{result}
			}
			continue
		}
	}

	return []Result{{
		Method: MethodCRL,
		Status: StatusUnknown,
		Error:  "all CRL distribution points failed",
	}}
}

func (c *Checker) fetchAndCheckCRL(leaf, issuer *x509.Certificate, dpURL string, timeout time.Duration, now time.Time) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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

	if issuer != nil {
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			return Result{
				Method:       MethodCRL,
				Status:       StatusError,
				ResponderURL: dpURL,
				Error:        fmt.Sprintf("CRL signature verification failed: %v", err),
			}
		}
	}

	if now.After(crl.NextUpdate) && !crl.NextUpdate.IsZero() {
		return Result{
			Method:       MethodCRL,
			Status:       StatusUnknown,
			ResponderURL: dpURL,
			Error:        "stale CRL: past NextUpdate time",
		}
	}

	for _, entry := range crl.RevokedCertificateEntries {
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

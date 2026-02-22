package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (c *Checker) checkOCSP(leaf, issuer *x509.Certificate, opts Options, now time.Time) []Result {
	if issuer == nil {
		return []Result{{
			Method: MethodOCSP,
			Status: StatusNotChecked,
			Error:  "no issuer certificate available",
		}}
	}

	if len(leaf.OCSPServer) == 0 {
		return []Result{{
			Method: MethodOCSP,
			Status: StatusNotChecked,
			Error:  "no OCSP responder URL in certificate",
		}}
	}

	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	for _, responderURL := range leaf.OCSPServer {
		result := c.fetchAndCheckOCSP(leaf, issuer, responderURL, timeout, now)
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
		Method: MethodOCSP,
		Status: StatusUnknown,
		Error:  "all OCSP responders failed",
	}}
}

func (c *Checker) fetchAndCheckOCSP(leaf, issuer *x509.Certificate, responderURL string, timeout time.Duration, now time.Time) Result {
	ocspReq, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("failed to create OCSP request: %v", err),
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(ocspReq))
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("invalid OCSP responder URL: %v", err),
		}
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("failed to send OCSP request: %v", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("OCSP responder returned HTTP %d", resp.StatusCode),
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("failed to read OCSP response: %v", err),
		}
	}

	ocspResp, err := ocsp.ParseResponseForCert(body, leaf, issuer)
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("failed to parse OCSP response: %v", err),
		}
	}

	if now.After(ocspResp.NextUpdate) && !ocspResp.NextUpdate.IsZero() {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusUnknown,
			ResponderURL: responderURL,
			Error:        "stale OCSP response: past NextUpdate time",
		}
	}

	switch ocspResp.Status {
	case ocsp.Good:
		return Result{
			Method:       MethodOCSP,
			Status:       StatusGood,
			ResponderURL: responderURL,
		}
	case ocsp.Revoked:
		revokedAt := ocspResp.RevokedAt
		return Result{
			Method:       MethodOCSP,
			Status:       StatusRevoked,
			ResponderURL: responderURL,
			RevokedAt:    &revokedAt,
			Reason:       formatRevocationReason(ocspResp.RevocationReason),
		}
	default:
		return Result{
			Method:       MethodOCSP,
			Status:       StatusUnknown,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("OCSP responder returned status: %d", ocspResp.Status),
		}
	}
}

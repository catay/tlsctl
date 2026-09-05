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

	if len(leaf.OCSPServer) == 0 {
		return []Result{{
			Method: MethodOCSP,
			Status: StatusNotSupported,
			Error:  "no OCSP responder URL in certificate",
		}}
	}

	if err := ValidateIssuer(leaf, issuer); err != nil {
		return []Result{{Method: MethodOCSP, Status: StatusNotChecked, Error: err.Error()}}
	}
	var results []Result
	for _, responderURL := range leaf.OCSPServer {
		result := c.fetchAndCheckOCSP(opts.Context, leaf, issuer, responderURL, opts.Timeout, now)
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

func (c *Checker) fetchAndCheckOCSP(parent context.Context, leaf, issuer *x509.Certificate, responderURL string, timeout time.Duration, now time.Time) Result {
	ocspReq, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusError,
			ResponderURL: responderURL,
			Error:        fmt.Sprintf("failed to create OCSP request: %v", err),
		}
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
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

	if responder := ocspResp.Certificate; responder != nil && !bytes.Equal(responder.Raw, issuer.Raw) {
		authorized := false
		for _, usage := range responder.ExtKeyUsage {
			if usage == x509.ExtKeyUsageOCSPSigning {
				authorized = true
			}
		}
		if !authorized || len(responder.UnhandledCriticalExtensions) != 0 || now.Before(responder.NotBefore) || now.After(responder.NotAfter) ||
			(responder.KeyUsage != 0 && responder.KeyUsage&x509.KeyUsageDigitalSignature == 0) {
			return Result{Method: MethodOCSP, Status: StatusError, ResponderURL: responderURL, Error: "OCSP responder certificate is not authorized or is outside its validity period"}
		}
	}
	if err := checkFreshness(ocspResp.ThisUpdate, ocspResp.NextUpdate, now, "OCSP response"); err != nil {
		return Result{
			Method:       MethodOCSP,
			Status:       StatusUnknown,
			ResponderURL: responderURL,
			Error:        err.Error(),
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

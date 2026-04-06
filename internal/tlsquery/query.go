package tlsquery

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// Query connects to the given endpoint and retrieves certificate chain information.
func Query(endpoint string, opts QueryOptions) (*ChainInfo, error) {
	config, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}

	probeVersions := opts.TLSVersions
	startTLS := opts.StartTLS
	connectTimeout, handshakeTimeout := resolveTimeouts(opts)

	host, _, _ := net.SplitHostPort(endpoint)
	if config.ServerName == "" && host != "" {
		config.ServerName = host
	}

	proxyURL, err := resolveProxy(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}

	certs, err := dialAndHandshake(endpoint, proxyURL, config, startTLS, connectTimeout, handshakeTimeout)
	if err != nil {
		if !isVerificationError(err) {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		verifyErr := err

		insecureConfig := config.Clone()
		insecureConfig.InsecureSkipVerify = true
		certs, err = dialAndHandshake(endpoint, proxyURL, insecureConfig, startTLS, connectTimeout, handshakeTimeout)
		if err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		chain := buildChain(certs)
		chain.Verified = false
		chain.VerificationError = abbreviateVerifyErrorWithChain(verifyErr, certs)
		chain.InputName = endpoint
		chain.InputLabel = "target"
		if probeVersions {
			chain.TLSVersions = probeTLSVersions(endpoint, proxyURL, config, true, startTLS, connectTimeout, handshakeTimeout)
		}
		return chain, nil
	}

	chain := buildChain(certs)
	chain.Verified = true
	chain.InputName = endpoint
	chain.InputLabel = "target"
	if probeVersions {
		chain.TLSVersions = probeTLSVersions(endpoint, proxyURL, config, false, startTLS, connectTimeout, handshakeTimeout)
	}
	return chain, nil
}

func resolveTimeouts(opts QueryOptions) (time.Duration, time.Duration) {
	connectTimeout := opts.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = DefaultConnectTimeout
	}

	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = DefaultHandshakeTimeout
	}

	return connectTimeout, handshakeTimeout
}

func buildConfig(opts QueryOptions) (*tls.Config, error) {
	config := &tls.Config{}

	if opts.ServerName != "" {
		config.ServerName = opts.ServerName
	}

	if opts.CACertFile != "" {
		caCert, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool, err := x509.SystemCertPool()
		if err != nil {
			caCertPool = x509.NewCertPool()
		}
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	return config, nil
}

func buildChain(certs []*x509.Certificate) *ChainInfo {
	chain := &ChainInfo{
		Certificates: make([]CertInfo, 0, len(certs)),
	}
	for _, cert := range certs {
		chain.Certificates = append(chain.Certificates, CertInfoFromCert(cert))
	}
	return chain
}

func isVerificationError(err error) bool {
	var hostErr x509.HostnameError
	var unknownAuth x509.UnknownAuthorityError
	var certInvalid x509.CertificateInvalidError
	var sysRoots x509.SystemRootsError
	return errors.As(err, &hostErr) ||
		errors.As(err, &unknownAuth) ||
		errors.As(err, &certInvalid) ||
		errors.As(err, &sysRoots)
}

func abbreviateVerifyErrorWithChain(err error, certs []*x509.Certificate) string {
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) && len(certs) > 0 {
		top := certs[len(certs)-1]
		if !isSelfSigned(top) {
			return "incomplete chain"
		}
	}
	return abbreviateVerifyError(err)
}

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject)
}

func abbreviateVerifyError(err error) string {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "hostname mismatch"
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return "unknown authority"
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		switch certInvalid.Reason {
		case x509.Expired:
			return "certificate expired"
		case x509.NotAuthorizedToSign:
			return "not authorized to sign"
		case x509.NameMismatch:
			return "name mismatch"
		default:
			return "invalid certificate"
		}
	}
	var sysRoots x509.SystemRootsError
	if errors.As(err, &sysRoots) {
		return "system roots unavailable"
	}
	return strings.TrimPrefix(err.Error(), "x509: ")
}

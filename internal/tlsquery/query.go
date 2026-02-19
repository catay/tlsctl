package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// TLSConfig allows customizing the TLS configuration for testing.
var TLSConfig *tls.Config

// Query connects to the given endpoint and retrieves certificate chain information.
func Query(endpoint string, opts QueryOptions) (*ChainInfo, error) {
	config, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}

	probeVersions := !opts.DisableTLSProbe

	host, _, _ := net.SplitHostPort(endpoint)
	if config.ServerName == "" && host != "" {
		config.ServerName = host
	}

	proxyURL, err := resolveProxy(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}

	verifiedConfig := config.Clone()
	verifiedConfig.InsecureSkipVerify = false
	certs, err := dialAndHandshake(endpoint, proxyURL, verifiedConfig)
	if err != nil {
		var cve *tls.CertificateVerificationError
		if !errors.As(err, &cve) {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		fallbackConfig := config.Clone()
		fallbackConfig.InsecureSkipVerify = true
		certs, err2 := dialAndHandshake(endpoint, proxyURL, fallbackConfig)
		if err2 != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err2)
		}
		chain := buildChain(certs)
		chain.Verified = false
		chain.VerificationError = abbreviateVerifyError(cve.Err)
		if probeVersions {
			chain.TLSVersions = probeTLSVersions(endpoint, proxyURL, config)
		}
		return chain, nil
	}

	chain := buildChain(certs)
	chain.Verified = true
	if probeVersions {
		chain.TLSVersions = probeTLSVersions(endpoint, proxyURL, config)
	}
	return chain, nil
}

func buildConfig(opts QueryOptions) (*tls.Config, error) {
	config := TLSConfig
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}

	if opts.ServerName != "" {
		config.ServerName = opts.ServerName
	}

	if opts.CACertFile != "" {
		caCert, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
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

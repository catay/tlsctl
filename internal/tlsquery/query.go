package tlsquery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ParseALPNProtocols normalizes a comma-separated ALPN protocol list.
func ParseALPNProtocols(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}

	parts := strings.Split(value, ",")
	protocols := make([]string, 0, len(parts))
	for _, part := range parts {
		proto := strings.TrimSpace(part)
		if proto == "" {
			return nil, fmt.Errorf("empty ALPN protocol in %q", value)
		}
		if len(proto) > 255 {
			return nil, fmt.Errorf("ALPN protocol exceeds 255 bytes")
		}
		protocols = append(protocols, proto)
	}

	return protocols, nil
}

// Query connects to an endpoint using a background context.
func Query(endpoint string, opts QueryOptions) (*ChainInfo, error) {
	return QueryContext(context.Background(), endpoint, opts)
}

// QueryContext retrieves and verifies the certificates from the same connection.
// No application data is exchanged. Verification is performed explicitly so
// invalid certificates can still be inspected without reconnecting.
func QueryContext(ctx context.Context, endpoint string, opts QueryOptions) (*ChainInfo, error) {
	config, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if config.ServerName == "" {
		config.ServerName = strings.Split(host, "%")[0]
	}
	proxyURL, err := resolveProxy(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}
	connectTimeout, handshakeTimeout := resolveTimeouts(opts)
	config.InsecureSkipVerify = true // Explicit x509 verification below.
	if opts.TLSVersions {
		config.MinVersion = tls.VersionTLS10
		config.CipherSuites = cipherSuiteIDsForVersion(tls.VersionTLS12)
	}
	certs, handshake, err := dialAndHandshake(ctx, endpoint, proxyURL, config, opts.StartTLS, connectTimeout, handshakeTimeout)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	chain := buildChain(certs)
	inter := x509.NewCertPool()
	for _, cert := range certs[1:] {
		inter.AddCert(cert)
	}
	verified, verifyErr := certs[0].Verify(x509.VerifyOptions{DNSName: config.ServerName, Roots: config.RootCAs, Intermediates: inter})
	chain.Verified = verifyErr == nil
	if verifyErr != nil {
		chain.VerificationError = abbreviateVerifyError(verifyErr)
	}
	if len(verified) > 0 && len(verified[0]) > 1 {
		chain.issuer = verified[0][1]
	}
	chain.NegotiatedTLS, chain.InputName, chain.InputLabel = handshake, endpoint, "target"
	if opts.TLSVersions {
		chain.TLSVersions = probeTLSVersions(ctx, endpoint, proxyURL, config, true, opts.StartTLS, connectTimeout, handshakeTimeout)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
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
	if len(opts.ALPNProtocols) > 0 {
		config.NextProtos = append([]string(nil), opts.ALPNProtocols...)
	}

	config.RootCAs = opts.RootCAs
	if config.RootCAs == nil && opts.CACertFile != "" {
		var err error
		config.RootCAs, err = LoadRootCAs(opts.CACertFile)
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

func buildChain(certs []*x509.Certificate) *ChainInfo {
	chain := &ChainInfo{
		Certificates: make([]CertInfo, 0, len(certs)),
		parsed:       certs,
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
			if certInvalid.Cert != nil && time.Now().Before(certInvalid.Cert.NotBefore) {
				return "certificate not yet valid"
			}
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

// LoadRootCAs prepares an immutable trust pool. A nil pool uses system trust.
// An explicitly configured CA file must be readable and contain certificates.
func LoadRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate %q: %w", path, err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA certificate %q", path)
	}
	return roots, nil
}

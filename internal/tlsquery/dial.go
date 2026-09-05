package tlsquery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"
)

func dialAndHandshake(ctx context.Context, endpoint string, proxyURL *url.URL, config *tls.Config, startTLSProto string, connectTimeout, handshakeTimeout time.Duration) ([]*x509.Certificate, *HandshakeInfo, error) {
	conn, err := dialTLS(ctx, endpoint, proxyURL, config, connectTimeout, handshakeTimeout, startTLSProto)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificate returned by server")
	}

	return certs, negotiatedHandshakeInfo(state), nil
}

// tlsVersionName returns the human-readable name for a TLS version constant.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func negotiatedHandshakeInfo(state tls.ConnectionState) *HandshakeInfo {
	return &HandshakeInfo{
		TLSVersion:  tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
}

// probeTLSVersions tests which TLS versions the server supports by attempting
// a handshake with each version individually, and enumerates the supported
// cipher suites in server-preferred order for each version.
func probeTLSVersions(ctx context.Context, endpoint string, proxyURL *url.URL, baseConfig *tls.Config, insecure bool, startTLSProto string, connectTimeout, handshakeTimeout time.Duration) []TLSVersionInfo {
	versions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	var supported []TLSVersionInfo
	for _, v := range versions {
		if ctx.Err() != nil {
			break
		}
		cfg := baseConfig.Clone()
		cfg.MinVersion = v
		cfg.MaxVersion = v
		cfg.InsecureSkipVerify = insecure

		conn, err := dialTLS(ctx, endpoint, proxyURL, cfg, connectTimeout, handshakeTimeout, startTLSProto)
		if err != nil {
			continue
		}
		negotiated := tls.CipherSuiteName(conn.ConnectionState().CipherSuite)
		conn.Close()

		var ciphers []string
		if v == tls.VersionTLS13 {
			ciphers = []string{negotiated}
		} else {
			ciphers = probeCipherSuites(ctx, endpoint, proxyURL, baseConfig, v, insecure, startTLSProto, connectTimeout, handshakeTimeout)
		}
		secureCiphers, insecureCiphers := SplitCipherSuitesBySecurity(ciphers)
		supported = append(supported, TLSVersionInfo{
			Version:              tlsVersionName(v),
			CipherSuites:         ciphers,
			SecureCipherSuites:   secureCiphers,
			InsecureCipherSuites: insecureCiphers,
		})
	}

	return supported
}

// probeCipherSuites enumerates the cipher suites supported by the server for
// the given TLS version in server-preferred order.
//
// For TLS 1.0–1.2 it performs repeated handshakes, each time removing the
// previously negotiated cipher suite, so the result reflects the server's
// preference. TLS 1.3 is handled directly by probeTLSVersions because Go does
// not permit configuring TLS 1.3 suites individually.
func probeCipherSuites(ctx context.Context, endpoint string, proxyURL *url.URL, baseConfig *tls.Config, version uint16, insecure bool, startTLSProto string, connectTimeout, handshakeTimeout time.Duration) []string {

	available := cipherSuiteIDsForVersion(version)
	var result []string

	for len(available) > 0 {
		if ctx.Err() != nil {
			break
		}
		cfg := baseConfig.Clone()
		cfg.MinVersion = version
		cfg.MaxVersion = version
		cfg.InsecureSkipVerify = insecure
		cfg.CipherSuites = available

		conn, err := dialTLS(ctx, endpoint, proxyURL, cfg, connectTimeout, handshakeTimeout, startTLSProto)
		if err != nil {
			break
		}
		negotiated := conn.ConnectionState().CipherSuite
		conn.Close()

		result = append(result, tls.CipherSuiteName(negotiated))

		newAvailable := make([]uint16, 0, len(available)-1)
		for _, id := range available {
			if id != negotiated {
				newAvailable = append(newAvailable, id)
			}
		}
		available = newAvailable
	}

	return result
}

// cipherSuiteIDsForVersion returns all cipher suite IDs (secure and insecure)
// that support the given TLS version.
func cipherSuiteIDsForVersion(version uint16) []uint16 {
	var ids []uint16
	for _, cs := range tls.CipherSuites() {
		for _, v := range cs.SupportedVersions {
			if v == version {
				ids = append(ids, cs.ID)
				break
			}
		}
	}
	for _, cs := range tls.InsecureCipherSuites() {
		for _, v := range cs.SupportedVersions {
			if v == version {
				ids = append(ids, cs.ID)
				break
			}
		}
	}
	return ids
}

func dialTLS(ctx context.Context, endpoint string, proxyURL *url.URL, config *tls.Config, connectTimeout, handshakeTimeout time.Duration, startTLSProto string) (*tls.Conn, error) {
	rawConn, err := dialTCP(ctx, endpoint, proxyURL, connectTimeout, handshakeTimeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	stop := context.AfterFunc(ctx, func() { _ = rawConn.Close() })
	defer stop()
	if err := rawConn.SetDeadline(phaseDeadline(ctx, handshakeTimeout)); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to configure handshake timeout: %w", err)
	}
	if startTLSProto != "" {
		if err := negotiateStartTLS(rawConn, startTLSProto); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("STARTTLS negotiation failed: %w", err)
		}
	}

	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	if err := rawConn.SetDeadline(time.Time{}); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to clear handshake timeout: %w", err)
	}

	return conn, nil
}

func dialTCP(ctx context.Context, endpoint string, proxyURL *url.URL, connectTimeout, handshakeTimeout time.Duration) (net.Conn, error) {
	if proxyURL != nil {
		return dialViaProxyContext(ctx, endpoint, proxyURL, connectTimeout, handshakeTimeout)
	}
	return (&net.Dialer{Timeout: connectTimeout}).DialContext(ctx, "tcp", endpoint)
}

func phaseDeadline(ctx context.Context, timeout time.Duration) time.Time {
	deadline := time.Now().Add(timeout)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		return parent
	}
	return deadline
}

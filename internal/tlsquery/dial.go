package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"
)

const (
	defaultDialTimeout = 10 * time.Second
	probeDialTimeout   = 5 * time.Second
)

func dialAndHandshake(endpoint string, proxyURL *url.URL, config *tls.Config, startTLS ...string) ([]*x509.Certificate, error) {
	proto := startTLSProtocol(startTLS)
	conn, err := dialTLS(endpoint, proxyURL, config, defaultDialTimeout, proto)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate returned by server")
	}

	return certs, nil
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

// probeTLSVersions tests which TLS versions the server supports by attempting
// a handshake with each version individually.
func probeTLSVersions(endpoint string, proxyURL *url.URL, baseConfig *tls.Config, insecure bool, startTLSProto ...string) []string {
	versions := []uint16{
		tls.VersionTLS10,
		tls.VersionTLS11,
		tls.VersionTLS12,
		tls.VersionTLS13,
	}

	proto := startTLSProtocol(startTLSProto)

	var supported []string
	for _, v := range versions {
		cfg := baseConfig.Clone()
		cfg.MinVersion = v
		cfg.MaxVersion = v
		cfg.InsecureSkipVerify = insecure

		conn, err := dialTLS(endpoint, proxyURL, cfg, probeDialTimeout, proto)
		if err != nil {
			continue
		}
		conn.Close()
		supported = append(supported, tlsVersionName(v))
	}

	return supported
}

func dialTLS(endpoint string, proxyURL *url.URL, config *tls.Config, timeout time.Duration, startTLSProto string) (*tls.Conn, error) {
	rawConn, err := dialTCP(endpoint, proxyURL, timeout)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	if startTLSProto != "" {
		if err := negotiateStartTLS(rawConn, startTLSProto); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("STARTTLS negotiation failed: %w", err)
		}
	}

	conn := tls.Client(rawConn, config)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}

func dialTCP(endpoint string, proxyURL *url.URL, timeout time.Duration) (net.Conn, error) {
	if proxyURL != nil {
		return dialViaProxy(endpoint, proxyURL, timeout)
	}
	return (&net.Dialer{Timeout: timeout}).Dial("tcp", endpoint)
}

func startTLSProtocol(protocols []string) string {
	if len(protocols) > 0 {
		return protocols[0]
	}
	return ""
}

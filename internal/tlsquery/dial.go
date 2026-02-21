package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"
)

func dialAndHandshake(endpoint string, proxyURL *url.URL, config *tls.Config, startTLS ...string) ([]*x509.Certificate, error) {
	var rawConn net.Conn
	var err error
	if proxyURL != nil {
		rawConn, err = dialViaProxy(endpoint, proxyURL, 10*time.Second)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", endpoint)
	}
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	if len(startTLS) > 0 && startTLS[0] != "" {
		if err := negotiateStartTLS(rawConn, startTLS[0]); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("STARTTLS negotiation failed: %w", err)
		}
	}

	conn := tls.Client(rawConn, config)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
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

	proto := ""
	if len(startTLSProto) > 0 {
		proto = startTLSProto[0]
	}

	var supported []string
	for _, v := range versions {
		cfg := baseConfig.Clone()
		cfg.MinVersion = v
		cfg.MaxVersion = v
		cfg.InsecureSkipVerify = insecure

		var rawConn net.Conn
		var err error
		if proxyURL != nil {
			rawConn, err = dialViaProxy(endpoint, proxyURL, 5*time.Second)
		} else {
			rawConn, err = (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", endpoint)
		}
		if err != nil {
			continue
		}

		if proto != "" {
			if err := negotiateStartTLS(rawConn, proto); err != nil {
				rawConn.Close()
				continue
			}
		}

		conn := tls.Client(rawConn, cfg)
		err = conn.Handshake()
		conn.Close()
		if err == nil {
			supported = append(supported, tlsVersionName(v))
		}
	}

	return supported
}

package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"time"
)

func dialAndHandshake(endpoint string, proxyURL *url.URL, config *tls.Config) ([]*x509.Certificate, error) {
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

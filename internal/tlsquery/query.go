package tlsquery

import (
	"crypto/tls"
	"fmt"
	"time"
)

// CertInfo holds the extracted certificate metadata.
type CertInfo struct {
	CommonName          string   `json:"common_name"`
	Issuer              string   `json:"issuer"`
	NotBefore           string   `json:"not_before"`
	NotAfter            string   `json:"not_after"`
	SubjectAltNames     []string `json:"subject_alternative_names"`
}

// Query connects to the given endpoint and retrieves certificate information.
func Query(endpoint string) (*CertInfo, error) {
	conn, err := tls.Dial("tcp", endpoint, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate returned by server")
	}

	leaf := certs[0]

	return &CertInfo{
		CommonName:      leaf.Subject.CommonName,
		Issuer:          leaf.Issuer.CommonName,
		NotBefore:       leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:        leaf.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames: leaf.DNSNames,
	}, nil
}

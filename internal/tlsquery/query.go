package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// CertInfo holds the extracted certificate metadata.
type CertInfo struct {
	CommonName      string   `json:"common_name"`
	Issuer          string   `json:"issuer"`
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	SubjectAltNames []string `json:"subject_alternative_names,omitempty"`
	Type            string   `json:"type"`
}

// ChainInfo holds the full certificate chain.
type ChainInfo struct {
	Certificates []CertInfo `json:"certificates"`
}

// Query connects to the given endpoint and retrieves certificate chain information.
func Query(endpoint string) (*ChainInfo, error) {
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

	chain := &ChainInfo{
		Certificates: make([]CertInfo, 0, len(certs)),
	}

	for i, cert := range certs {
		info := CertInfo{
			CommonName: cert.Subject.CommonName,
			Issuer:     cert.Issuer.CommonName,
			NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
			Type:       certType(i, cert),
		}
		if i == 0 {
			info.SubjectAltNames = cert.DNSNames
		}
		chain.Certificates = append(chain.Certificates, info)
	}

	return chain, nil
}

func certType(index int, cert *x509.Certificate) string {
	if index == 0 {
		return "leaf"
	}
	if cert.IsCA && cert.Subject.String() == cert.Issuer.String() {
		return "root"
	}
	return "intermediate"
}

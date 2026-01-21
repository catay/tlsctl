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

// TLSConfig allows customizing the TLS configuration for testing.
var TLSConfig *tls.Config

// Query connects to the given endpoint and retrieves certificate chain information.
func Query(endpoint string) (*ChainInfo, error) {
	config := TLSConfig
	if config == nil {
		config = &tls.Config{}
	}
	conn, err := tls.Dial("tcp", endpoint, config)
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

// CertTypeFromCert determines the certificate type based on its properties.
func CertTypeFromCert(cert *x509.Certificate) string {
	if cert.IsCA {
		if cert.Subject.String() == cert.Issuer.String() {
			return "root"
		}
		return "intermediate"
	}
	return "leaf"
}

// CertInfoFromCert creates a CertInfo from an x509.Certificate.
func CertInfoFromCert(cert *x509.Certificate) CertInfo {
	return CertInfo{
		CommonName:      cert.Subject.CommonName,
		Issuer:          cert.Issuer.CommonName,
		NotBefore:       cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:        cert.NotAfter.UTC().Format(time.RFC3339),
		SubjectAltNames: cert.DNSNames,
		Type:            CertTypeFromCert(cert),
	}
}

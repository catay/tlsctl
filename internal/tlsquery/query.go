package tlsquery

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds the extracted certificate metadata.
type CertInfo struct {
	Type               string            `json:"type"`
	Version            int               `json:"version"`
	SerialNumber       string            `json:"serial_number"`
	SignatureAlgorithm string            `json:"signature_algorithm"`
	Issuer             string            `json:"issuer"`
	Subject            string            `json:"subject"`
	CommonName         string            `json:"common_name"`
	NotBefore          string            `json:"not_before"`
	NotAfter           string            `json:"not_after"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm"`
	KeyUsage           []string          `json:"key_usage,omitempty"`
	ExtKeyUsage        []string          `json:"extended_key_usage,omitempty"`
	BasicConstraints   *BasicConstraints `json:"basic_constraints,omitempty"`
	SubjectKeyID       string            `json:"subject_key_id,omitempty"`
	AuthorityKeyID     string            `json:"authority_key_id,omitempty"`
	SubjectAltNames    []string          `json:"subject_alternative_names,omitempty"`
	EmailAddresses     []string          `json:"email_addresses,omitempty"`
	IPAddresses        []string          `json:"ip_addresses,omitempty"`
	OCSPServers        []string          `json:"ocsp_servers,omitempty"`
	IssuingCertURL     []string          `json:"issuing_cert_url,omitempty"`
	CRLDistPoints      []string          `json:"crl_distribution_points,omitempty"`
	PEM                string            `json:"pem"`
}

// BasicConstraints holds CA constraint information.
type BasicConstraints struct {
	IsCA       bool `json:"is_ca"`
	MaxPathLen int  `json:"max_path_len,omitempty"`
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
		chain.Certificates = append(chain.Certificates, CertInfoFromCert(cert))
		if i == 0 {
			chain.Certificates[i].Type = "leaf"
		}
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
	info := CertInfo{
		Type:               CertTypeFromCert(cert),
		Version:            cert.Version,
		SerialNumber:       formatSerialNumber(cert.SerialNumber.Bytes()),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		Issuer:             cert.Issuer.String(),
		Subject:            cert.Subject.String(),
		CommonName:         cert.Subject.CommonName,
		NotBefore:          cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:           cert.NotAfter.UTC().Format(time.RFC3339),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		KeyUsage:           formatKeyUsage(cert.KeyUsage),
		ExtKeyUsage:        formatExtKeyUsage(cert.ExtKeyUsage),
		SubjectKeyID:       formatKeyID(cert.SubjectKeyId),
		AuthorityKeyID:     formatKeyID(cert.AuthorityKeyId),
		SubjectAltNames:    cert.DNSNames,
		EmailAddresses:     cert.EmailAddresses,
		IPAddresses:        formatIPs(cert.IPAddresses),
		OCSPServers:        cert.OCSPServer,
		IssuingCertURL:     cert.IssuingCertificateURL,
		CRLDistPoints:      cert.CRLDistributionPoints,
		PEM:                encodePEM(cert.Raw),
	}

	if cert.BasicConstraintsValid {
		info.BasicConstraints = &BasicConstraints{
			IsCA:       cert.IsCA,
			MaxPathLen: cert.MaxPathLen,
		}
	}

	return info
}

func formatSerialNumber(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func formatKeyID(id []byte) string {
	if len(id) == 0 {
		return ""
	}
	parts := make([]string, len(id))
	for i, v := range id {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func formatIPs(ips []net.IP) []string {
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result
}

func formatKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Non Repudiation")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return usages
}

func formatExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "E-mail Protection")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		default:
			usages = append(usages, fmt.Sprintf("Unknown(%d)", u))
		}
	}
	return usages
}

func encodePEM(raw []byte) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: raw,
	}
	return string(pem.EncodeToMemory(block))
}


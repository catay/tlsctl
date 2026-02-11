package tlsquery

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

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
		Fingerprint:        computeFingerprint(cert.Raw),
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

func computeFingerprint(der []byte) Fingerprint {
	sha1Sum := sha1.Sum(der)
	sha256Sum := sha256.Sum256(der)
	return Fingerprint{
		SHA1:   formatFingerprint(sha1Sum[:]),
		SHA256: formatFingerprint(sha256Sum[:]),
	}
}

func formatFingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02x", b)
	}
	return strings.Join(parts, ":")
}

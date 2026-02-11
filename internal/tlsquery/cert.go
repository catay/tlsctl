package tlsquery

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func ParseCertPEM(pemText string) (*x509.Certificate, error) {
	if pemText == "" {
		return nil, fmt.Errorf("empty PEM data")
	}
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (ci *CertInfo) NotAfterTime() (time.Time, error) {
	return time.Parse(time.RFC3339, ci.NotAfter)
}

func (ci *CertInfo) NotBeforeTime() (time.Time, error) {
	return time.Parse(time.RFC3339, ci.NotBefore)
}

func (ci *CertInfo) DisplayName() string {
	if ci.CommonName != "" {
		return ci.CommonName
	}
	if len(ci.SubjectAltNames) > 0 {
		return ci.SubjectAltNames[0]
	}
	if ci.Subject != "" {
		return ci.Subject
	}
	return "(unknown)"
}

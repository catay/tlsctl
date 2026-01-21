package tlsquery

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// ParsePEMFile reads a PEM file and returns certificate information for all certificates found.
func ParsePEMFile(path string) (*ChainInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParsePEM(data)
}

// ParsePEM parses PEM-encoded certificate data and returns certificate information.
func ParsePEM(data []byte) (*ChainInfo, error) {
	var certs []*x509.Certificate

	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		data = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	chain := &ChainInfo{
		Certificates: make([]CertInfo, 0, len(certs)),
	}

	for _, cert := range certs {
		chain.Certificates = append(chain.Certificates, CertInfoFromCert(cert))
	}

	return chain, nil
}

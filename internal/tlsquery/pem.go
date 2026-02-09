package tlsquery

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// PEMOptions configures PEM parsing and verification behavior.
type PEMOptions struct {
	CACertFile string // Path to custom CA certificate file (PEM format)
}

// ParsePEMFile reads a PEM file and returns certificate information for all certificates found.
func ParsePEMFile(path string, opts ...PEMOptions) (*ChainInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return ParsePEM(data, opts...)
}

// ParsePEM parses PEM-encoded certificate data and returns certificate information.
func ParsePEM(data []byte, opts ...PEMOptions) (*ChainInfo, error) {
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

	chain := buildChain(certs)

	var o PEMOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	verifyPEMChain(chain, certs, o)

	return chain, nil
}

func verifyPEMChain(chain *ChainInfo, certs []*x509.Certificate, opts PEMOptions) {
	leaf := certs[0]

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}

	if opts.CACertFile != "" {
		caCert, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			chain.Verified = false
			chain.VerificationError = fmt.Sprintf("failed to read CA certificate: %s", err)
			return
		}
		if !roots.AppendCertsFromPEM(caCert) {
			chain.Verified = false
			chain.VerificationError = "failed to parse CA certificate"
			return
		}
	}

	inter := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		inter.AddCert(certs[i])
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	if _, err := leaf.Verify(verifyOpts); err != nil {
		chain.Verified = false
		chain.VerificationError = abbreviateVerifyError(err)
	} else {
		chain.Verified = true
	}
}

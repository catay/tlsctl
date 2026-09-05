package tlsquery

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// PEMOptions configures PEM parsing and verification behavior.
type PEMOptions struct {
	RootCAs    *x509.CertPool
	CACertFile string // Path to custom CA certificate file (PEM format)
}

// ParsePEMFile reads a PEM file and returns certificate information for all certificates found.
func ParsePEMFile(path string, opts PEMOptions) (*ChainInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	chain, err := ParsePEM(data, opts)
	if err != nil {
		return nil, err
	}
	chain.InputName = path
	chain.InputLabel = "source"
	return chain, nil
}

// ParsePEM parses PEM-encoded certificate data and returns certificate information.
func ParsePEM(data []byte, opts PEMOptions) (*ChainInfo, error) {
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

	if err := verifyPEMChain(chain, certs, opts); err != nil {
		return nil, err
	}

	return chain, nil
}

func verifyPEMChain(chain *ChainInfo, certs []*x509.Certificate, opts PEMOptions) error {
	leaf := certs[0]

	roots := opts.RootCAs
	if roots == nil && opts.CACertFile != "" {
		var err error
		roots, err = LoadRootCAs(opts.CACertFile)
		if err != nil {
			return err
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

	if verified, err := leaf.Verify(verifyOpts); err != nil {
		chain.Verified = false
		chain.VerificationError = abbreviateVerifyError(err)
	} else {
		chain.Verified = true
		if len(verified) > 0 && len(verified[0]) > 1 {
			chain.issuer = verified[0][1]
		}
	}
	return nil
}

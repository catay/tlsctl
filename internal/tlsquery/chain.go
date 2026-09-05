package tlsquery

import (
	"crypto/x509"
	"fmt"
	"github.com/catay/tlsctl/v2/internal/revocation"
)

func (c *ChainInfo) Leaf() (*CertInfo, error) {
	if c == nil || len(c.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates in chain")
	}
	return &c.Certificates[0], nil
}

func (c *ChainInfo) WithoutPEM() *ChainInfo {
	out := &ChainInfo{
		Certificates:      make([]CertInfo, len(c.Certificates)),
		Verified:          c.Verified,
		VerificationError: c.VerificationError,
		NegotiatedTLS:     c.NegotiatedTLS,
		TLSVersions:       c.TLSVersions,
		InputName:         c.InputName,
		InputLabel:        c.InputLabel,
	}
	for i := range c.Certificates {
		out.Certificates[i] = c.Certificates[i]
		out.Certificates[i].PEM = ""
	}
	return out
}

func (c *ChainInfo) ChainNames() []string {
	names := make([]string, len(c.Certificates))
	for i, cert := range c.Certificates {
		names[i] = cert.DisplayName()
	}
	return names
}

// RevocationCertificates returns the inspected leaf and its actual issuer.
// Verified-chain issuers can include a root not sent by the peer.
func (c *ChainInfo) RevocationCertificates() (*x509.Certificate, *x509.Certificate) {
	certs := c.parsed
	if len(certs) == 0 {
		for _, info := range c.Certificates {
			cert, err := ParseCertPEM(info.PEM)
			if err != nil {
				return nil, nil
			}
			certs = append(certs, cert)
		}
	}
	if len(certs) == 0 {
		return nil, nil
	}
	leaf := certs[0]
	if c.issuer != nil && revocation.ValidateIssuer(leaf, c.issuer) == nil {
		return leaf, c.issuer
	}
	for _, candidate := range certs {
		if revocation.ValidateIssuer(leaf, candidate) == nil {
			return leaf, candidate
		}
	}
	return leaf, nil
}

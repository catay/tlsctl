package tlsquery

import "fmt"

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

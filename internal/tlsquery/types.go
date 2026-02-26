package tlsquery

import (
	"github.com/catay/tlsctl/internal/revocation"
)

// CertInfo holds the extracted certificate metadata.
type CertInfo struct {
	Type               string            `json:"type" yaml:"type"`
	Version            int               `json:"version" yaml:"version"`
	SerialNumber       string            `json:"serial_number" yaml:"serial_number"`
	SignatureAlgorithm string            `json:"signature_algorithm" yaml:"signature_algorithm"`
	Issuer             string            `json:"issuer" yaml:"issuer"`
	Subject            string            `json:"subject" yaml:"subject"`
	CommonName         string            `json:"common_name" yaml:"common_name"`
	NotBefore          string            `json:"not_before" yaml:"not_before"`
	NotAfter           string            `json:"not_after" yaml:"not_after"`
	PublicKeyAlgorithm string            `json:"public_key_algorithm" yaml:"public_key_algorithm"`
	KeyLength          int               `json:"key_length" yaml:"key_length"`
	KeyUsage           []string          `json:"key_usage,omitempty" yaml:"key_usage,omitempty"`
	ExtKeyUsage        []string          `json:"extended_key_usage,omitempty" yaml:"extended_key_usage,omitempty"`
	BasicConstraints   *BasicConstraints `json:"basic_constraints,omitempty" yaml:"basic_constraints,omitempty"`
	SubjectKeyID       string            `json:"subject_key_id,omitempty" yaml:"subject_key_id,omitempty"`
	AuthorityKeyID     string            `json:"authority_key_id,omitempty" yaml:"authority_key_id,omitempty"`
	SubjectAltNames    []string          `json:"subject_alternative_names,omitempty" yaml:"subject_alternative_names,omitempty"`
	EmailAddresses     []string          `json:"email_addresses,omitempty" yaml:"email_addresses,omitempty"`
	IPAddresses        []string          `json:"ip_addresses,omitempty" yaml:"ip_addresses,omitempty"`
	OCSPServers        []string          `json:"ocsp_servers,omitempty" yaml:"ocsp_servers,omitempty"`
	IssuingCertURL     []string          `json:"issuing_cert_url,omitempty" yaml:"issuing_cert_url,omitempty"`
	CRLDistPoints      []string          `json:"crl_distribution_points,omitempty" yaml:"crl_distribution_points,omitempty"`
	Fingerprint        Fingerprint       `json:"fingerprint" yaml:"fingerprint"`
	PEM                string            `json:"pem,omitempty" yaml:"pem,omitempty"`
	Revocation         *revocation.Info  `json:"revocation,omitempty" yaml:"revocation,omitempty"`
}

// Fingerprint holds SHA1 and SHA256 fingerprints of a certificate.
type Fingerprint struct {
	SHA1   string `json:"sha1" yaml:"sha1"`
	SHA256 string `json:"sha256" yaml:"sha256"`
}

// BasicConstraints holds CA constraint information.
type BasicConstraints struct {
	IsCA       bool `json:"is_ca" yaml:"is_ca"`
	MaxPathLen int  `json:"max_path_len,omitempty" yaml:"max_path_len,omitempty"`
}

// TLSVersionInfo holds a TLS version and its supported cipher suites in server-preferred order.
type TLSVersionInfo struct {
	Version      string   `json:"version" yaml:"version"`
	CipherSuites []string `json:"cipher_suites" yaml:"cipher_suites"`
}

// ChainInfo holds the full certificate chain.
type ChainInfo struct {
	Certificates      []CertInfo       `json:"certificates" yaml:"certificates"`
	Verified          bool             `json:"verified" yaml:"verified"`
	VerificationError string           `json:"verification_error,omitempty" yaml:"verification_error,omitempty"`
	TLSVersions       []TLSVersionInfo `json:"tls_versions,omitempty" yaml:"tls_versions,omitempty"`
}

// QueryOptions configures the TLS query behavior.
type QueryOptions struct {
	CACertFile  string // Path to custom CA certificate file (PEM format)
	Proxy       string // Proxy URL (e.g. http://proxy:8080). If empty, HTTPS_PROXY/HTTP_PROXY env vars are used.
	TLSVersions bool   // Probe and display supported TLS versions.
	ServerName  string // SNI override for TLS handshake (useful when connecting by IP).
	StartTLS    string // STARTTLS protocol: smtp, imap, pop3, ldap.
	Insecure    bool   // Skip TLS certificate verification.
}

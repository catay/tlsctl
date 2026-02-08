package tlsquery

import (
	"bufio"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
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

// ChainInfo holds the full certificate chain.
type ChainInfo struct {
	Certificates      []CertInfo `json:"certificates" yaml:"certificates"`
	Verified          bool       `json:"verified" yaml:"verified"`
	VerificationError string     `json:"verification_error,omitempty" yaml:"verification_error,omitempty"`
}

// TLSConfig allows customizing the TLS configuration for testing.
var TLSConfig *tls.Config

// QueryOptions configures the TLS query behavior.
type QueryOptions struct {
	CACertFile string // Path to custom CA certificate file (PEM format)
	Proxy      string // Proxy URL (e.g. http://proxy:8080). If empty, HTTPS_PROXY/HTTP_PROXY env vars are used.
}

// Query connects to the given endpoint and retrieves certificate chain information.
func Query(endpoint string, opts ...QueryOptions) (*ChainInfo, error) {
	config, err := buildConfig(opts)
	if err != nil {
		return nil, err
	}

	host, _, _ := net.SplitHostPort(endpoint)
	if config.ServerName == "" && host != "" {
		config.ServerName = host
	}

	proxyURL, err := resolveProxy(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy configuration: %w", err)
	}

	verifiedConfig := config.Clone()
	verifiedConfig.InsecureSkipVerify = false
	certs, err := dialAndHandshake(endpoint, proxyURL, verifiedConfig)
	if err != nil {
		var cve *tls.CertificateVerificationError
		if !errors.As(err, &cve) {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		fallbackConfig := config.Clone()
		fallbackConfig.InsecureSkipVerify = true
		certs, err2 := dialAndHandshake(endpoint, proxyURL, fallbackConfig)
		if err2 != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		chain := buildChain(certs)
		chain.Verified = false
		chain.VerificationError = abbreviateVerifyError(cve.Err)
		return chain, nil
	}

	chain := buildChain(certs)
	chain.Verified = true
	return chain, nil
}

func buildConfig(opts []QueryOptions) (*tls.Config, error) {
	config := TLSConfig
	if config == nil {
		config = &tls.Config{}
	} else {
		config = config.Clone()
	}

	if len(opts) > 0 && opts[0].CACertFile != "" {
		caCert, err := os.ReadFile(opts[0].CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	return config, nil
}

func dialAndHandshake(endpoint string, proxyURL *url.URL, config *tls.Config) ([]*x509.Certificate, error) {
	var rawConn net.Conn
	var err error
	if proxyURL != nil {
		rawConn, err = dialViaProxy(endpoint, proxyURL, 10*time.Second)
	} else {
		rawConn, err = (&net.Dialer{Timeout: 10 * time.Second}).Dial("tcp", endpoint)
	}
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	conn := tls.Client(rawConn, config)
	if err := conn.Handshake(); err != nil {
		rawConn.Close()
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificate returned by server")
	}

	return certs, nil
}

func buildChain(certs []*x509.Certificate) *ChainInfo {
	chain := &ChainInfo{
		Certificates: make([]CertInfo, 0, len(certs)),
	}
	for i, cert := range certs {
		chain.Certificates = append(chain.Certificates, CertInfoFromCert(cert))
		if i == 0 {
			chain.Certificates[i].Type = "leaf"
		}
	}
	return chain
}

func abbreviateVerifyError(err error) string {
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "hostname mismatch"
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return "unknown authority"
	}
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certInvalid) {
		switch certInvalid.Reason {
		case x509.Expired:
			return "certificate expired"
		case x509.NotAuthorizedToSign:
			return "not authorized to sign"
		case x509.NameMismatch:
			return "name mismatch"
		default:
			return "invalid certificate"
		}
	}
	var sysRoots x509.SystemRootsError
	if errors.As(err, &sysRoots) {
		return "system roots unavailable"
	}
	return strings.TrimPrefix(err.Error(), "x509: ")
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

func resolveProxy(endpoint string, opts []QueryOptions) (*url.URL, error) {
	var proxyStr string
	if len(opts) > 0 {
		proxyStr = opts[0].Proxy
	}

	if proxyStr != "" {
		if !strings.Contains(proxyStr, "://") {
			proxyStr = "http://" + proxyStr
		}
		return url.Parse(proxyStr)
	}

	req := &http.Request{URL: &url.URL{Scheme: "https", Host: endpoint}}
	return http.ProxyFromEnvironment(req)
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func dialViaProxy(endpoint string, proxyURL *url.URL, timeout time.Duration) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		port := "8080"
		if proxyURL.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(proxyAddr, port)
	}

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %s: %w", proxyAddr, err)
	}

	if proxyURL.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: proxyURL.Hostname()})
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
		}
		conn = tlsConn
	}

	br := bufio.NewReader(conn)

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: endpoint},
		Host:   endpoint,
		Header: make(http.Header),
	}

	if proxyURL.User != nil {
		user := proxyURL.User.Username()
		pass, _ := proxyURL.User.Password()
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}

	return &bufferedConn{Conn: conn, r: br}, nil
}

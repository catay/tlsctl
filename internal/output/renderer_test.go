package output

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/catay/tlsctl/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

func testChain() *tlsquery.ChainInfo {
	return &tlsquery.ChainInfo{
		Certificates: []tlsquery.CertInfo{
			{
				Type:               "leaf",
				Version:            3,
				SerialNumber:       "01:02:03",
				SignatureAlgorithm: "SHA256-RSA",
				Issuer:             "CN=Test CA",
				Subject:            "CN=test.example.com",
				CommonName:         "test.example.com",
				NotBefore:          "2025-01-01T00:00:00Z",
				NotAfter:           "2027-01-01T00:00:00Z",
				PublicKeyAlgorithm: "RSA",
				SubjectAltNames:    []string{"test.example.com", "www.example.com"},
				PEM:                "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
			},
		},
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 2, 5, 12, 0, 0, 0, time.UTC)
}

func sampleCipherSuites(t *testing.T) (secure string, insecure string) {
	t.Helper()

	secureSuites := tls.CipherSuites()
	if len(secureSuites) == 0 {
		t.Fatal("expected at least one secure cipher suite")
	}

	insecureSuites := tls.InsecureCipherSuites()
	if len(insecureSuites) == 0 {
		t.Fatal("expected at least one insecure cipher suite")
	}

	return secureSuites[0].Name, insecureSuites[0].Name
}

func TestNewFactory(t *testing.T) {
	tests := []struct {
		format    Format
		wantType  string
		wantError bool
	}{
		{FormatDefault, "HumanRenderer", false},
		{FormatHuman, "HumanRenderer", false},
		{FormatJSON, "JSONRenderer", false},
		{FormatYAML, "YAMLRenderer", false},
		{FormatText, "VerboseTextRenderer", false},
		{FormatRaw, "RawPEMRenderer", false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(string(tt.format), func(t *testing.T) {
			r, err := New(tt.format)
			if tt.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if r == nil {
					t.Error("expected renderer, got nil")
				}
			}
		})
	}
}

func TestJSONRenderer(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	secureCipher, insecureCipher := sampleCipherSuites(t)
	chain.TLSVersions = []tlsquery.TLSVersionInfo{
		{
			Version:              "TLS 1.2",
			CipherSuites:         []string{secureCipher, insecureCipher},
			SecureCipherSuites:   []string{secureCipher},
			InsecureCipherSuites: []string{insecureCipher},
		},
	}
	var buf bytes.Buffer
	r := JSONRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var result tlsquery.ChainInfo
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(result.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(result.Certificates))
	}
	if result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from JSON output")
	}
	if len(result.TLSVersions) != 1 {
		t.Fatalf("expected 1 tls version entry, got %d", len(result.TLSVersions))
	}
	if len(result.TLSVersions[0].SecureCipherSuites) != 1 {
		t.Errorf("expected secure cipher suites in JSON output")
	}
	if len(result.TLSVersions[0].InsecureCipherSuites) != 1 {
		t.Errorf("expected insecure cipher suites in JSON output")
	}
}

func TestYAMLRenderer(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	secureCipher, insecureCipher := sampleCipherSuites(t)
	chain.TLSVersions = []tlsquery.TLSVersionInfo{
		{
			Version:              "TLS 1.2",
			CipherSuites:         []string{secureCipher, insecureCipher},
			SecureCipherSuites:   []string{secureCipher},
			InsecureCipherSuites: []string{insecureCipher},
		},
	}
	var buf bytes.Buffer
	r := YAMLRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var result tlsquery.ChainInfo
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal YAML: %v", err)
	}

	if len(result.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(result.Certificates))
	}
	if result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from YAML output")
	}
	if len(result.TLSVersions) != 1 {
		t.Fatalf("expected 1 tls version entry, got %d", len(result.TLSVersions))
	}
	if len(result.TLSVersions[0].SecureCipherSuites) != 1 {
		t.Errorf("expected secure cipher suites in YAML output")
	}
	if len(result.TLSVersions[0].InsecureCipherSuites) != 1 {
		t.Errorf("expected insecure cipher suites in YAML output")
	}
}

func TestRawPEMRenderer(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := RawPEMRenderer{}

	err := r.Render(&buf, chain, Options{})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if !strings.Contains(buf.String(), "BEGIN CERTIFICATE") {
		t.Error("expected PEM output")
	}
}

func TestHumanRenderer(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := HumanRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test.example.com") {
		t.Error("expected common name in output")
	}
	if !strings.Contains(output, "Subject:") {
		t.Error("expected Subject in output")
	}
	if !strings.Contains(output, "secure") {
		t.Error("expected secure label in output")
	}
	if !strings.Contains(output, "expires in") {
		t.Error("expected expiry info in output")
	}
}

func TestHumanRendererExpired(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	chain.Certificates[0].NotAfter = "2025-12-01T00:00:00Z"
	var buf bytes.Buffer
	r := HumanRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "expired 66 days ago") {
		t.Errorf("expected 'expired 66 days ago' in output, got: %s", output)
	}
}

func TestFormatExpiryMsg(t *testing.T) {
	tests := []struct {
		days    int
		expired bool
		want    string
	}{
		{90, false, "expires in 90 days"},
		{1, false, "expires in 1 day"},
		{0, false, "expires in 0 days"},
		{-1, true, "expired 1 day ago"},
		{-30, true, "expired 30 days ago"},
	}
	for _, tt := range tests {
		got := formatExpiryMsg(tt.days, tt.expired)
		if got != tt.want {
			t.Errorf("formatExpiryMsg(%d, %v) = %q, want %q", tt.days, tt.expired, got, tt.want)
		}
	}
}

func TestHumanRendererInsecure(t *testing.T) {
	chain := testChain()
	chain.Verified = false
	chain.VerificationError = "unknown authority"
	var buf bytes.Buffer
	r := HumanRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "insecure") {
		t.Error("expected insecure label in output")
	}
	if !strings.Contains(output, "unknown authority") {
		t.Error("expected unknown authority warning in output")
	}
}

func TestHumanRendererTLSCipherSecurity(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	secureCipher, insecureCipher := sampleCipherSuites(t)
	chain.TLSVersions = []tlsquery.TLSVersionInfo{
		{
			Version:              "TLS 1.2",
			CipherSuites:         []string{secureCipher, insecureCipher},
			SecureCipherSuites:   []string{secureCipher},
			InsecureCipherSuites: []string{insecureCipher},
		},
	}
	var buf bytes.Buffer
	r := HumanRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Ciphers (TLS 1.2)") {
		t.Error("expected cipher section in output")
	}
	if !strings.Contains(output, secureCipher) {
		t.Error("expected secure cipher in output")
	}
	if !strings.Contains(output, insecureCipher+" (insecure)") {
		t.Error("expected insecure cipher marker in output")
	}
}

func TestVerboseTextRenderer(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := VerboseTextRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "[LEAF]") {
		t.Error("expected [LEAF] header in output")
	}
	if !strings.Contains(output, "Version:") {
		t.Error("expected Version in output")
	}
	if !strings.Contains(output, "Serial Number:") {
		t.Error("expected Serial Number in output")
	}
}

func TestVerboseTextRendererInsecure(t *testing.T) {
	chain := testChain()
	chain.Verified = false
	chain.VerificationError = "unknown authority"
	var buf bytes.Buffer
	r := VerboseTextRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "verification failed") {
		t.Error("expected verification failed warning in output")
	}
}

func TestVerboseTextRendererTLSCipherSecurity(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	secureCipher, insecureCipher := sampleCipherSuites(t)
	chain.TLSVersions = []tlsquery.TLSVersionInfo{
		{
			Version:      "TLS 1.2",
			CipherSuites: []string{secureCipher, insecureCipher},
		},
	}
	var buf bytes.Buffer
	r := VerboseTextRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Secure Cipher Suites (TLS 1.2)") {
		t.Error("expected secure cipher section in output")
	}
	if !strings.Contains(output, "Insecure Cipher Suites (TLS 1.2)") {
		t.Error("expected insecure cipher section in output")
	}
	if !strings.Contains(output, secureCipher) {
		t.Error("expected secure cipher in output")
	}
	if !strings.Contains(output, insecureCipher) {
		t.Error("expected insecure cipher in output")
	}
}

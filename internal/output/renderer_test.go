package output

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/catay/tlsctl/v2/internal/revocation"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

type batchResultV1Doc struct {
	Target string              `json:"target" yaml:"target"`
	OK     bool                `json:"ok" yaml:"ok"`
	Error  string              `json:"error,omitempty" yaml:"error,omitempty"`
	Result *tlsquery.ChainInfo `json:"result,omitempty" yaml:"result,omitempty"`
}

func testChain() *tlsquery.ChainInfo {
	return &tlsquery.ChainInfo{
		InputName:  "test.example.com:443",
		InputLabel: "target",
		NegotiatedTLS: &tlsquery.HandshakeInfo{
			TLSVersion:  "TLS 1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			ALPN:        "h2",
		},
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
				Fingerprint: tlsquery.Fingerprint{
					SHA1:   "11:22:33",
					SHA256: "aa:bb:cc",
				},
				PEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n",
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
		{FormatCSV, "CSVRenderer", false},
		{FormatCSVFull, "CSVFullRenderer", false},
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
	if result.NegotiatedTLS == nil || result.NegotiatedTLS.TLSVersion != "TLS 1.3" {
		t.Fatalf("expected negotiated tls details in JSON output, got %+v", result.NegotiatedTLS)
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
	if result.NegotiatedTLS == nil || result.NegotiatedTLS.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("expected negotiated tls details in YAML output, got %+v", result.NegotiatedTLS)
	}
	if len(result.TLSVersions[0].SecureCipherSuites) != 1 {
		t.Errorf("expected secure cipher suites in YAML output")
	}
	if len(result.TLSVersions[0].InsecureCipherSuites) != 1 {
		t.Errorf("expected insecure cipher suites in YAML output")
	}
}

func TestJSONRendererBatch(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := JSONRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	var got []batchResultV1Doc
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal batch JSON: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(got))
	}
	if !got[0].OK || got[0].Result == nil {
		t.Fatalf("expected first batch result to contain a successful chain")
	}
	if got[0].Result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from batch JSON output")
	}
	if got[1].OK {
		t.Error("expected second batch result to be marked as failed")
	}
	if got[1].Error != "connection failed" {
		t.Errorf("unexpected batch error: %q", got[1].Error)
	}
	if got[1].Result != nil {
		t.Error("expected failed batch result to omit the chain result")
	}
}

func TestYAMLRendererBatch(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := YAMLRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	var got []batchResultV1Doc
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal batch YAML: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(got))
	}
	if !got[0].OK || got[0].Result == nil {
		t.Fatalf("expected first batch result to contain a successful chain")
	}
	if got[0].Result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from batch YAML output")
	}
	if got[1].Error != "connection failed" {
		t.Errorf("unexpected batch error: %q", got[1].Error)
	}
}

func TestJSONRendererBatchV2(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := JSONRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow, FormatVersion: 2}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	var got BatchEnvelope
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal batch JSON v2: %v", err)
	}

	if got.Status != StatusPartialSuccess {
		t.Fatalf("expected partial_success envelope status, got %q", got.Status)
	}
	if got.Summary.Total != 2 || got.Summary.Succeeded != 1 || got.Summary.Failed != 1 {
		t.Fatalf("unexpected batch summary: %+v", got.Summary)
	}
	if len(got.Results) != 2 {
		t.Fatalf("expected 2 batch results, got %d", len(got.Results))
	}
	if got.Results[0].Status != StatusSuccess || got.Results[0].Result == nil {
		t.Fatalf("expected successful first batch result, got %+v", got.Results[0])
	}
	if got.Results[0].TLSStatus != TLSStatusSecure {
		t.Fatalf("expected secure tls_status for first result, got %q", got.Results[0].TLSStatus)
	}
	if got.Results[0].Result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from batch JSON v2 output")
	}
	if got.Results[1].Status != StatusFailure || got.Results[1].Error != "connection failed" {
		t.Fatalf("unexpected failed batch result: %+v", got.Results[1])
	}
	if got.Results[1].TLSStatus != "" {
		t.Fatalf("expected empty tls_status for failed result, got %q", got.Results[1].TLSStatus)
	}
}

func TestYAMLRendererBatchV2(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := YAMLRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow, FormatVersion: 2}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	var got BatchEnvelope
	if err := yaml.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("failed to unmarshal batch YAML v2: %v", err)
	}

	if got.Status != StatusPartialSuccess {
		t.Fatalf("expected partial_success envelope status, got %q", got.Status)
	}
	if got.Summary.Total != 2 || got.Summary.Succeeded != 1 || got.Summary.Failed != 1 {
		t.Fatalf("unexpected batch summary: %+v", got.Summary)
	}
	if got.Results[0].Status != StatusSuccess || got.Results[1].Status != StatusFailure {
		t.Fatalf("unexpected per-result statuses: %+v", got.Results)
	}
	if got.Results[0].TLSStatus != TLSStatusSecure || got.Results[1].TLSStatus != "" {
		t.Fatalf("unexpected per-result tls statuses: %+v", got.Results)
	}
}

func TestTargetResultTLSStatus(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*TargetResult)
		want   TLSStatus
	}{
		{
			name:   "secure",
			mutate: func(result *TargetResult) {},
			want:   TLSStatusSecure,
		},
		{
			name: "expiring",
			mutate: func(result *TargetResult) {
				result.Result.Certificates[0].NotAfter = "2026-02-20T00:00:00Z"
			},
			want: TLSStatusExpiring,
		},
		{
			name: "insecure verification",
			mutate: func(result *TargetResult) {
				result.Result.Verified = false
			},
			want: TLSStatusInsecure,
		},
		{
			name: "revocation error",
			mutate: func(result *TargetResult) {
				result.Result.Certificates[0].Revocation = &revocation.Info{OverallStatus: revocation.StatusError}
			},
			want: TLSStatusRevocationError,
		},
		{
			name: "query failure",
			mutate: func(result *TargetResult) {
				result.Error = "connection failed"
				result.Result = nil
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TargetResult{
				Target: "test.example.com:443",
				Result: testChain(),
			}
			result.Result.Verified = true
			tt.mutate(&result)
			if got := result.TLSStatus(Options{Now: fixedNow, FormatVersion: 2}); got != tt.want {
				t.Fatalf("TLSStatus() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCSVRenderer(t *testing.T) {
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
	r := CSVRenderer{}

	if err := r.Render(&buf, chain, Options{Now: fixedNow}); err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected header plus one row, got %d rows", len(rows))
	}

	record := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		record[header] = rows[1][i]
	}

	if record["target"] != "test.example.com:443" {
		t.Errorf("expected target=test.example.com:443, got %q", record["target"])
	}
	if record["common_name"] != "test.example.com" {
		t.Errorf("expected common_name=test.example.com, got %q", record["common_name"])
	}
	if record["tls_version"] != "TLS 1.3" {
		t.Errorf("expected tls_version=TLS 1.3, got %q", record["tls_version"])
	}
	if record["cipher_suite"] != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("expected cipher_suite in CSV output, got %q", record["cipher_suite"])
	}
	if record["alpn"] != "h2" {
		t.Errorf("expected alpn=h2, got %q", record["alpn"])
	}
	if record["issuer"] != "CN=Test CA" {
		t.Errorf("expected issuer=CN=Test CA, got %q", record["issuer"])
	}
	if record["days_remaining"] != "329" {
		t.Errorf("expected days_remaining=329, got %q", record["days_remaining"])
	}
	if record["sha256"] == "" {
		t.Error("expected SHA256 fingerprint in CSV output")
	}
	if record["subject_alternative_names"] != "test.example.com; www.example.com" {
		t.Errorf("unexpected SAN value: %q", record["subject_alternative_names"])
	}

	fullBuf := bytes.Buffer{}
	full := CSVFullRenderer{}
	if err := full.Render(&fullBuf, chain, Options{Now: fixedNow}); err != nil {
		t.Fatalf("CSVFull Render failed: %v", err)
	}

	fullRows, err := csv.NewReader(bytes.NewReader(fullBuf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV full output: %v", err)
	}
	if len(fullRows) != 2 {
		t.Fatalf("expected header plus one full row, got %d rows", len(fullRows))
	}

	fullRecord := make(map[string]string, len(fullRows[0]))
	for i, header := range fullRows[0] {
		fullRecord[header] = fullRows[1][i]
	}
	if fullRecord["certificate_type"] != "leaf" {
		t.Errorf("expected certificate_type=leaf in csv-full, got %q", fullRecord["certificate_type"])
	}
	if fullRecord["tls_version"] != "TLS 1.3" || fullRecord["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || fullRecord["alpn"] != "h2" {
		t.Errorf("expected negotiated tls columns in csv-full, got tls_version=%q cipher_suite=%q alpn=%q", fullRecord["tls_version"], fullRecord["cipher_suite"], fullRecord["alpn"])
	}
	if !strings.Contains(fullRecord["secure_cipher_suites"], "TLS 1.2: "+secureCipher) {
		t.Errorf("expected secure cipher suites to include version-qualified entry, got %q", fullRecord["secure_cipher_suites"])
	}
	if !strings.Contains(fullRecord["insecure_cipher_suites"], "TLS 1.2: "+insecureCipher) {
		t.Errorf("expected insecure cipher suites to include version-qualified entry, got %q", fullRecord["insecure_cipher_suites"])
	}
}

func TestCSVRendererBatch(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := CSVRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse batch CSV: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}

	record1 := make(map[string]string, len(rows[0]))
	record2 := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		record1[header] = rows[1][i]
		record2[header] = rows[2][i]
	}

	if record1["ok"] != "true" || record1["error"] != "" {
		t.Fatalf("expected successful batch row, got ok=%q error=%q", record1["ok"], record1["error"])
	}
	if record1["common_name"] != "test.example.com" {
		t.Errorf("unexpected common_name for success row: %q", record1["common_name"])
	}
	if record1["tls_version"] != "TLS 1.3" || record1["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || record1["alpn"] != "h2" {
		t.Errorf("expected negotiated tls fields for success row, got tls_version=%q cipher_suite=%q alpn=%q", record1["tls_version"], record1["cipher_suite"], record1["alpn"])
	}
	if record2["target"] != "missing.example.com:443" {
		t.Errorf("unexpected target for error row: %q", record2["target"])
	}
	if record2["ok"] != "false" || record2["error"] != "connection failed" {
		t.Fatalf("expected failed batch row, got ok=%q error=%q", record2["ok"], record2["error"])
	}
	if record2["common_name"] != "" {
		t.Errorf("expected empty common_name for failed row, got %q", record2["common_name"])
	}
	if record2["tls_version"] != "" || record2["cipher_suite"] != "" || record2["alpn"] != "" {
		t.Errorf("expected empty negotiated tls fields for failed row, got tls_version=%q cipher_suite=%q alpn=%q", record2["tls_version"], record2["cipher_suite"], record2["alpn"])
	}
}

func TestCSVRendererBatchV2(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := CSVRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow, FormatVersion: 2}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse batch CSV v2: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}

	record1 := make(map[string]string, len(rows[0]))
	record2 := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		record1[header] = rows[1][i]
		record2[header] = rows[2][i]
	}

	if record1["status"] != "success" || record1["tls_status"] != "secure" || record1["error"] != "" {
		t.Fatalf("expected successful batch row, got status=%q tls_status=%q error=%q", record1["status"], record1["tls_status"], record1["error"])
	}
	if record1["common_name"] != "test.example.com" {
		t.Errorf("unexpected common_name for success row: %q", record1["common_name"])
	}
	if record1["tls_version"] != "TLS 1.3" || record1["cipher_suite"] != "TLS_AES_128_GCM_SHA256" || record1["alpn"] != "h2" {
		t.Errorf("expected negotiated tls fields for success row, got tls_version=%q cipher_suite=%q alpn=%q", record1["tls_version"], record1["cipher_suite"], record1["alpn"])
	}
	if record2["target"] != "missing.example.com:443" {
		t.Errorf("unexpected target for error row: %q", record2["target"])
	}
	if record2["status"] != "failure" || record2["tls_status"] != "" || record2["error"] != "connection failed" {
		t.Fatalf("expected failed batch row, got status=%q tls_status=%q error=%q", record2["status"], record2["tls_status"], record2["error"])
	}
	if record2["common_name"] != "" {
		t.Errorf("expected empty common_name for failed row, got %q", record2["common_name"])
	}
	if record2["tls_version"] != "" || record2["cipher_suite"] != "" || record2["alpn"] != "" {
		t.Errorf("expected empty negotiated tls fields for failed row, got tls_version=%q cipher_suite=%q alpn=%q", record2["tls_version"], record2["cipher_suite"], record2["alpn"])
	}
}

func TestCSVFullRendererBatch(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := CSVFullRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse batch CSV full output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}

	record1 := make(map[string]string, len(rows[0]))
	record2 := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		record1[header] = rows[1][i]
		record2[header] = rows[2][i]
	}

	if record1["ok"] != "true" || record1["certificate_type"] != "leaf" {
		t.Fatalf("unexpected success row in batch csv-full: ok=%q certificate_type=%q", record1["ok"], record1["certificate_type"])
	}
	if record2["ok"] != "false" || record2["error"] != "connection failed" {
		t.Fatalf("unexpected error row in batch csv-full: ok=%q error=%q", record2["ok"], record2["error"])
	}
	if record2["certificate_type"] != "" {
		t.Errorf("expected empty certificate_type for failed row, got %q", record2["certificate_type"])
	}
}

func TestCSVFullRendererBatchV2(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := CSVFullRenderer{}

	results := []TargetResult{
		{
			Target: "test.example.com:443",
			Result: chain,
		},
		{
			Target: "missing.example.com:443",
			Error:  "connection failed",
		},
	}

	if err := r.RenderBatch(&buf, results, Options{Now: fixedNow, FormatVersion: 2}); err != nil {
		t.Fatalf("RenderBatch failed: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse batch CSV full v2 output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}

	record1 := make(map[string]string, len(rows[0]))
	record2 := make(map[string]string, len(rows[0]))
	for i, header := range rows[0] {
		record1[header] = rows[1][i]
		record2[header] = rows[2][i]
	}

	if record1["status"] != "success" || record1["tls_status"] != "secure" || record1["certificate_type"] != "leaf" {
		t.Fatalf("unexpected success row in batch csv-full v2: status=%q tls_status=%q certificate_type=%q", record1["status"], record1["tls_status"], record1["certificate_type"])
	}
	if record2["status"] != "failure" || record2["tls_status"] != "" || record2["error"] != "connection failed" {
		t.Fatalf("unexpected error row in batch csv-full v2: status=%q tls_status=%q error=%q", record2["status"], record2["tls_status"], record2["error"])
	}
	if record2["certificate_type"] != "" {
		t.Errorf("expected empty certificate_type for failed row, got %q", record2["certificate_type"])
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
	if !strings.Contains(output, "Handshake: TLS 1.3 / TLS_AES_128_GCM_SHA256 / h2") {
		t.Fatalf("expected handshake summary in human output, got %q", output)
	}
}

func TestVerboseTextRendererNegotiatedTLS(t *testing.T) {
	chain := testChain()
	chain.Verified = true
	var buf bytes.Buffer
	r := VerboseTextRenderer{}

	err := r.Render(&buf, chain, Options{Now: fixedNow})
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Negotiated TLS Version: TLS 1.3") {
		t.Fatalf("expected negotiated tls version in verbose output, got %q", output)
	}
	if !strings.Contains(output, "Negotiated Cipher Suite: TLS_AES_128_GCM_SHA256") {
		t.Fatalf("expected negotiated cipher suite in verbose output, got %q", output)
	}
	if !strings.Contains(output, "Negotiated ALPN:       h2") {
		t.Fatalf("expected negotiated ALPN in verbose output, got %q", output)
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

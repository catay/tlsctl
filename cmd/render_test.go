package cmd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/catay/tlsctl/v2/internal/output"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

func testChains() []*tlsquery.ChainInfo {
	return []*tlsquery.ChainInfo{
		{
			InputName:  "a.example.com:443",
			InputLabel: "target",
			Verified:   true,
			NegotiatedTLS: &tlsquery.HandshakeInfo{
				TLSVersion:  "TLS 1.3",
				CipherSuite: "TLS_AES_128_GCM_SHA256",
				ALPN:        "h2",
			},
			Certificates: []tlsquery.CertInfo{
				{
					Type:       "leaf",
					CommonName: "a.example.com",
					Subject:    "CN=a.example.com",
					Issuer:     "CN=Test CA",
					NotBefore:  "2025-01-01T00:00:00Z",
					NotAfter:   "2027-01-01T00:00:00Z",
					PEM:        "-----BEGIN CERTIFICATE-----\ntest-a\n-----END CERTIFICATE-----\n",
				},
			},
		},
		{
			InputName:  "b.example.com:443",
			InputLabel: "target",
			Verified:   true,
			NegotiatedTLS: &tlsquery.HandshakeInfo{
				TLSVersion:  "TLS 1.2",
				CipherSuite: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			},
			Certificates: []tlsquery.CertInfo{
				{
					Type:       "leaf",
					CommonName: "b.example.com",
					Subject:    "CN=b.example.com",
					Issuer:     "CN=Test CA",
					NotBefore:  "2025-01-01T00:00:00Z",
					NotAfter:   "2027-01-01T00:00:00Z",
					PEM:        "-----BEGIN CERTIFICATE-----\ntest-b\n-----END CERTIFICATE-----\n",
				},
			},
		},
	}
}

func testTargetResults() []targetResult {
	chains := testChains()
	return []targetResult{
		{
			endpoint: "a.example.com:443",
			chain:    chains[0],
		},
		{
			endpoint: "missing.example.com:443",
			err:      assertError("connection failed"),
		},
	}
}

type assertError string

func (e assertError) Error() string { return string(e) }

func TestRenderChains_Empty(t *testing.T) {
	var buf bytes.Buffer
	err := renderChains(&buf, output.FormatJSON, nil, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected empty output, got %q", buf.String())
	}
}

func TestRenderChains_MultiJSON(t *testing.T) {
	chains := testChains()
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatJSON, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope output.BatchEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to unmarshal JSON array: %v", err)
	}
	result := envelope.Results
	if len(result) != 2 {
		t.Errorf("expected 2 chains, got %d", len(result))
	}
	for i, r := range result {
		if len(r.Result.Certificates) > 0 && r.Result.Certificates[0].PEM != "" {
			t.Errorf("chain %d: PEM should be stripped in JSON output", i)
		}
	}
}

func TestRenderChains_MultiYAML(t *testing.T) {
	chains := testChains()
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatYAML, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope output.BatchEnvelope
	if err := yaml.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to unmarshal YAML array: %v", err)
	}
	result := envelope.Results
	if len(result) != 2 {
		t.Errorf("expected 2 chains, got %d", len(result))
	}
}

func TestRenderChains_MultiCSV(t *testing.T) {
	chains := testChains()
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatCSV, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}

	if rows[0][0] != "target" {
		t.Fatalf("expected CSV header row, got %q", rows[0][0])
	}
	if rows[1][0] != "a.example.com:443" || rows[2][0] != "b.example.com:443" {
		t.Fatalf("expected target values for both rows, got %q and %q", rows[1][0], rows[2][0])
	}
}

func TestRenderChains_MultiCSVFull(t *testing.T) {
	chains := testChains()
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatCSVFull, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV full output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}
	if rows[0][0] != "target" {
		t.Fatalf("expected CSV full header row, got %q", rows[0][0])
	}
	if rows[1][5] != "leaf" || rows[2][5] != "leaf" {
		t.Fatalf("expected leaf certificate rows, got %q and %q", rows[1][5], rows[2][5])
	}
}

func TestRenderChains_SingleJSON(t *testing.T) {
	chains := testChains()[:1]
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatJSON, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var envelope output.BatchEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to unmarshal single JSON object: %v", err)
	}
	if len(envelope.Results) != 1 {
		t.Fatalf("expected one result: %+v", envelope)
	}
	if envelope.Results[0].Result.Certificates[0].PEM != "" {
		t.Error("PEM should be stripped from JSON output")
	}
}

func TestRenderChains_InvalidFormat(t *testing.T) {
	chains := testChains()[:1]
	var buf bytes.Buffer

	err := renderChains(&buf, output.Format("invalid"), chains, output.Options{})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestRenderChains_RawNoSeparator(t *testing.T) {
	chains := testChains()
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatRaw, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	output := buf.String()
	if strings.Count(output, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("expected 2 PEM blocks, got %d", strings.Count(output, "BEGIN CERTIFICATE"))
	}
	// Raw format should NOT have blank separator lines between certs
	if strings.Contains(output, "\n\n-----BEGIN") {
		t.Error("raw format should not have blank separators between PEM blocks")
	}
}

func TestRenderTargetResults_SingleJSONBatch(t *testing.T) {
	results := testTargetResults()[:1]
	var buf bytes.Buffer

	renderedErrors, err := renderTargetResults(&buf, output.FormatJSON, results, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renderedErrors {
		t.Fatal("expected json v2 output to render through the batch envelope even for a single target")
	}

	var envelope output.BatchEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatalf("failed to unmarshal batch envelope: %v", err)
	}
	if envelope.Status != output.StatusSuccess {
		t.Fatalf("expected success envelope status, got %q", envelope.Status)
	}
	if envelope.Summary.Total != 1 || envelope.Summary.Succeeded != 1 || envelope.Summary.Failed != 0 {
		t.Fatalf("unexpected batch summary: %+v", envelope.Summary)
	}
	if len(envelope.Results) != 1 || envelope.Results[0].Status != output.StatusSuccess {
		t.Fatalf("unexpected batch results: %+v", envelope.Results)
	}
	if envelope.Results[0].TLSStatus != output.TLSStatusSecure {
		t.Fatalf("expected secure tls_status, got %+v", envelope.Results[0])
	}
}

func TestRenderTargetResults_MultiCSVBatch(t *testing.T) {
	results := testTargetResults()
	var buf bytes.Buffer

	renderedErrors, err := renderTargetResults(&buf, output.FormatCSV, results, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !renderedErrors {
		t.Fatal("expected format-version 2 CSV output to render runtime errors inline")
	}

	rows, err := csv.NewReader(bytes.NewReader(buf.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("failed to parse CSV v2 output: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header plus two rows, got %d rows", len(rows))
	}
	if rows[0][0] != "target" || rows[0][1] != "status" || rows[0][2] != "tls_status" || rows[0][3] != "error" {
		t.Fatalf("unexpected CSV v2 headers: %v", rows[0][:4])
	}
	if rows[0][4] != "tls_version" || rows[0][5] != "cipher_suite" || rows[0][6] != "alpn" {
		t.Fatalf("unexpected CSV v2 negotiated tls headers: %v", rows[0][:7])
	}
	if rows[1][0] != "a.example.com:443" || rows[1][1] != "success" || rows[1][2] != "secure" || rows[1][3] != "" {
		t.Fatalf("unexpected success row: %v", rows[1][:4])
	}
	if rows[1][4] != "TLS 1.3" || rows[1][5] != "TLS_AES_128_GCM_SHA256" || rows[1][6] != "h2" {
		t.Fatalf("unexpected negotiated tls values in success row: %v", rows[1][:7])
	}
	if rows[2][0] != "missing.example.com:443" || rows[2][1] != "failure" || rows[2][2] != "" || rows[2][3] != "connection failed" {
		t.Fatalf("unexpected failed row: %v", rows[2][:4])
	}
	if rows[2][4] != "" || rows[2][5] != "" || rows[2][6] != "" {
		t.Fatalf("expected empty negotiated tls values in failed row: %v", rows[2][:7])
	}
}

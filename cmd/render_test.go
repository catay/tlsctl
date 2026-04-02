package cmd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"

	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

func testChains() []*tlsquery.ChainInfo {
	return []*tlsquery.ChainInfo{
		{
			InputName:  "a.example.com:443",
			InputLabel: "target",
			Verified:   true,
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

	var result []tlsquery.ChainInfo
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal JSON array: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 chains, got %d", len(result))
	}
	for i, r := range result {
		if len(r.Certificates) > 0 && r.Certificates[0].PEM != "" {
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

	var result []tlsquery.ChainInfo
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal YAML array: %v", err)
	}
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
	if rows[1][2] != "leaf" || rows[2][2] != "leaf" {
		t.Fatalf("expected leaf certificate rows, got %q and %q", rows[1][2], rows[2][2])
	}
}

func TestRenderChains_SingleJSON(t *testing.T) {
	chains := testChains()[:1]
	var buf bytes.Buffer

	err := renderChains(&buf, output.FormatJSON, chains, output.Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var result tlsquery.ChainInfo
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("failed to unmarshal single JSON object: %v", err)
	}
	if result.Certificates[0].PEM != "" {
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

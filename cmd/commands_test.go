package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/catay/tlsctl/v2/internal/output"
	"gopkg.in/yaml.v3"
)

func pemFixture(t *testing.T) (string, string) {
	t.Helper()
	return pemFixtureWithRevocation(t, "")
}

func pemFixtureWithRevocation(t *testing.T, revocationStatus string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "example.test"},
		DNSNames: []string{"example.test"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	if revocationStatus != "" {
		crl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}
		if revocationStatus == "revoked" {
			crl.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}
		}
		crlDER, err := x509.CreateRevocationList(rand.Reader, crl, ca, key)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if revocationStatus == "unavailable" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write(crlDER)
		}))
		t.Cleanup(server.Close)
		leaf.CRLDistributionPoints = []string{server.URL}
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), root...)
	return string(chain), string(root)
}

func writeFixture(t *testing.T, name, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func invoke(t *testing.T, stdin string, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	rt := NewRuntime()
	rt.Stdout, rt.Stderr, rt.Stdin = &stdout, &stderr, strings.NewReader(stdin)
	root := newRootCmd(rt)
	root.SetArgs(args)
	err := root.Execute()
	code := rt.ExitTracker.Code()
	if err != nil {
		code = ExitRuntimeError
	}
	return stdout.String(), stderr.String(), code
}

func TestPEMStructuredContract(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	chain, root := pemFixture(t)
	caPath := writeFixture(t, "ca.pem", root)
	chainPath := writeFixture(t, "chain.pem", chain)
	for _, format := range []string{"json", "yaml", "csv", "csv-full"} {
		for _, input := range []string{chainPath, "-"} {
			t.Run(format+"/"+input, func(t *testing.T) {
				stdout, stderr, code := invoke(t, chain, "pem", "--cacert", caPath, "-o", format, input)
				if code != 0 || stderr != "" {
					t.Fatalf("code=%d stderr=%s stdout=%s", code, stderr, stdout)
				}
				target := input
				if target == "-" {
					target = "stdin"
				}
				if format == "json" || format == "yaml" {
					var envelope output.BatchEnvelope
					var err error
					if format == "json" {
						err = json.Unmarshal([]byte(stdout), &envelope)
					} else {
						err = yaml.Unmarshal([]byte(stdout), &envelope)
					}
					if err != nil {
						t.Fatal(err)
					}
					if envelope.Status != output.StatusSuccess || envelope.Summary.Total != 1 || len(envelope.Results) != 1 {
						t.Fatalf("bad envelope: %+v", envelope)
					}
					r := envelope.Results[0]
					if r.Target != target || r.TLSStatus != output.TLSStatusSecure || r.Result == nil || len(r.Result.Certificates) != 2 {
						t.Fatalf("bad result: %+v", r)
					}
					if r.Result.Certificates[0].PEM != "" {
						t.Fatal("PEM must not leak into structured output")
					}
				} else {
					rows, err := csv.NewReader(strings.NewReader(stdout)).ReadAll()
					if err != nil {
						t.Fatal(err)
					}
					wantRows := 2
					if format == "csv-full" {
						wantRows = 3
					}
					if len(rows) != wantRows || strings.Join(rows[0][:4], ",") != "target,status,tls_status,error" {
						t.Fatalf("bad rows: %v", rows)
					}
					for _, row := range rows[1:] {
						if row[0] != target || row[1] != "success" || row[2] != "secure" {
							t.Fatalf("bad row: %v", row)
						}
					}
				}
			})
		}
	}
}

func TestPEMFailuresAndValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	missing := filepath.Join(t.TempDir(), "missing.pem")
	for _, format := range []string{"json", "yaml", "csv", "csv-full"} {
		for _, input := range []string{missing, "-"} {
			stdout, stderr, code := invoke(t, "not a certificate", "pem", "-o", format, input)
			if code != ExitRuntimeError || stderr != "" || !strings.Contains(stdout, "failure") {
				t.Fatalf("%s: code=%d stdout=%s stderr=%s", format, code, stdout, stderr)
			}
		}
	}
	for _, args := range [][]string{
		{"pem", "--quiet", "-o", "nonsense", missing},
		{"client", "--quiet", "-o", "nonsense", "127.0.0.1:1"},
		{"pem", "--revocation-timeout", "0s", missing},
		{"client", "--timeout", "0s", "127.0.0.1:1"},
		{"client", "--concurrency", "0", "127.0.0.1:1"},
		{"client", "--proxy", "socks5://localhost:1080", "127.0.0.1:1"},
		{"client", "--format-version", "2", "127.0.0.1:1"},
		{"pem", "--format-version", "2", missing},
	} {
		stdout, stderr, code := invoke(t, "", args...)
		if code != ExitRuntimeError || stdout != "" || !strings.Contains(stderr, "Error:") {
			t.Fatalf("%v: code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
	chain, _ := pemFixture(t)
	stdout, stderr, code := invoke(t, chain, "pem", "--quiet", "--cacert", missing, "-")
	if code != ExitRuntimeError || stdout != "" || !strings.Contains(stderr, "CA certificate") || strings.Contains(stderr, "Usage:") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
}

func TestConfigurationBeforeInputValidation(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	config := writeFixture(t, "settings.json", `{"client":{"file":"-","output":"yaml","quiet":true}}`)
	stdout, stderr, code := invoke(t, "127.0.0.1:1", "--config", config, "client", "-o", "json", "--quiet=false")
	if code != ExitRuntimeError || stderr != "" || !strings.HasPrefix(stdout, "{") || !strings.Contains(stdout, "127.0.0.1:1") {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, data := range []string{`{} trailing`, `{} {}`, `{"client":{"format-version":2}}`, `{"pem":{"revocation-timeout":"-1s"}}`} {
		config := writeFixture(t, "settings.json", data)
		stdout, stderr, code := invoke(t, "", "--config", config, "pem", "-")
		if code != ExitRuntimeError || stdout != "" || !strings.Contains(stderr, "config") {
			t.Fatalf("%s: code=%d stdout=%s stderr=%s", data, code, stdout, stderr)
		}
	}
}

func TestPEMRevocationOutputAndExitCodes(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	for _, tt := range []struct {
		status, softFail, health string
		code                     int
	}{
		{"good", "true", "secure", 0},
		{"revoked", "true", "insecure", ExitInsecure},
		{"revoked", "false", "insecure", ExitInsecure},
		{"unavailable", "true", "secure", 0},
		{"unavailable", "false", "revocation_error", ExitRevocationError},
	} {
		chain, root := pemFixtureWithRevocation(t, tt.status)
		ca := writeFixture(t, "ca.pem", root)
		for _, format := range []string{"human", "text", "json", "yaml", "csv", "csv-full", "raw"} {
			args := []string{"pem", "--no-color", "--cacert", ca, "--revocation", "crl", "--revocation-soft-fail=" + tt.softFail, "-o", format, "-"}
			stdout, stderr, code := invoke(t, chain, args...)
			if code != tt.code || stderr != "" || (format != "raw" && !strings.Contains(stdout, tt.health)) {
				t.Fatalf("%s/%s/%s: code=%d, stdout=%s, stderr=%s", tt.status, tt.softFail, format, code, stdout, stderr)
			}
			if format == "raw" && stdout != chain {
				t.Fatal("raw certificate payload changed")
			}
			args = append(args, "--quiet")
			stdout, stderr, code = invoke(t, chain, args...)
			if code != tt.code || stdout != "" || stderr != "" {
				t.Fatalf("quiet %s/%s/%s: code=%d, stdout=%s, stderr=%s", tt.status, tt.softFail, format, code, stdout, stderr)
			}
		}
	}
}

func TestHelpAndCompletionIgnoreBrokenConfig(t *testing.T) {
	config := writeFixture(t, "settings.json", "invalid JSON")
	for _, args := range [][]string{{"--help"}, {"client", "--help"}, {"pem", "--help"}, {"version"}, {"completion", "bash"}, {"completion", "zsh"}, {"completion", "fish"}, {"__complete", "client", "--output", ""}, {"__complete", ""}} {
		stdout, stderr, code := invoke(t, "", append([]string{"--config", config}, args...)...)
		if code != 0 || stdout == "" || strings.Contains(stderr, "Error:") {
			t.Fatalf("%v: code=%d stdout=%s stderr=%s", args, code, stdout, stderr)
		}
	}
}

func TestCommandInstancesDoNotShareFlags(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	chain, root := pemFixture(t)
	ca := writeFixture(t, "ca.pem", root)
	stdout, _, code := invoke(t, chain, "pem", "--cacert", ca, "--quiet", "-")
	if code != 0 || stdout != "" {
		t.Fatalf("quiet command: code=%d stdout=%s", code, stdout)
	}
	stdout, _, code = invoke(t, chain, "pem", "--cacert", ca, "-")
	if code != 0 || !strings.Contains(stdout, "Source: stdin") {
		t.Fatalf("second command: code=%d stdout=%s", code, stdout)
	}
}

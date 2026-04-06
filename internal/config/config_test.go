package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultPath(t *testing.T) {
	p, err := DefaultPath()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p == "" {
		t.Fatal("expected non-empty path")
	}
	if filepath.Base(p) != "settings.json" {
		t.Errorf("expected settings.json, got %s", filepath.Base(p))
	}
}

func TestLoad_MissingDefault(t *testing.T) {
	s, err := Load("/nonexistent/settings.json", false)
	if err != nil {
		t.Fatalf("unexpected error for missing default config: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil settings")
	}
}

func TestLoad_MissingExplicit(t *testing.T) {
	_, err := Load("/nonexistent/settings.json", true)
	if err == nil {
		t.Fatal("expected error for missing explicit config")
	}
}

func TestLoad_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{invalid`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoad_UnknownKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"unknown_key": true}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestLoad_InvalidExpiryWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	tests := []struct {
		name string
		json string
	}{
		{"too low", `{"client": {"expiry-warning": 0}}`},
		{"too high", `{"pem": {"expiry-warning": 10001}}`},
		{"negative", `{"client": {"expiry-warning": -5}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tt.json), 0644); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}
			_, err := Load(path, false)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestLoad_InvalidRevocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"client": {"revocation": "invalid"}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid revocation mode")
	}
}

func TestLoad_InvalidStartTLS(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"client": {"starttls": "ftp"}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid starttls")
	}
}

func TestLoad_InvalidFormatVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"client": {"format-version": 3}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid format-version")
	}
}

func TestLoad_InvalidConnectionTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"client": {"connect-timeout": "0s"}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid connect-timeout")
	}
}

func TestLoad_InvalidHandshakeTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"global": {"handshake-timeout": "-1s"}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected error for invalid handshake-timeout")
	}
}

func TestLoad_ValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{
		"global": {"no-color": true, "quiet": false},
		"client": {
			"expiry-warning": 21,
			"output": "json",
			"format-version": 2,
			"proxy": "http://proxy:8080",
			"tls-versions": true,
			"connect-timeout": "4s",
			"handshake-timeout": "9s",
			"revocation": "ocsp",
			"revocation-timeout": "10s",
			"revocation-soft-fail": false,
			"servername": "example.com",
			"starttls": "smtp",
			"cacert": "/etc/ssl/ca.pem",
			"file": "hosts.txt"
		},
		"pem": {
			"expiry-warning": 7,
			"output": "yaml",
			"cacert": "/etc/ssl/ca.pem",
			"revocation": "crl",
			"revocation-timeout": "3s",
			"revocation-soft-fail": true
		}
	}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	s, err := Load(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Global
	if s.Global.NoColor == nil || !*s.Global.NoColor {
		t.Error("expected global.no-color = true")
	}
	if s.Global.Quiet == nil || *s.Global.Quiet {
		t.Error("expected global.quiet = false")
	}

	// Client
	if s.Client.ExpiryWarning == nil || *s.Client.ExpiryWarning != 21 {
		t.Error("expected client.expiry-warning = 21")
	}
	if s.Client.Output == nil || *s.Client.Output != "json" {
		t.Error("expected client.output = json")
	}
	if s.Client.FormatVersion == nil || *s.Client.FormatVersion != 2 {
		t.Error("expected client.format-version = 2")
	}
	if s.Client.Proxy == nil || *s.Client.Proxy != "http://proxy:8080" {
		t.Error("expected client.proxy")
	}
	if s.Client.TLSVersions == nil || !*s.Client.TLSVersions {
		t.Error("expected client.tls-versions = true")
	}
	if s.Client.ConnectTimeout == nil || s.Client.ConnectTimeout.Duration != 4*time.Second {
		t.Error("expected client.connect-timeout = 4s")
	}
	if s.Client.HandshakeTimeout == nil || s.Client.HandshakeTimeout.Duration != 9*time.Second {
		t.Error("expected client.handshake-timeout = 9s")
	}
	if s.Client.RevocationTimeout == nil || s.Client.RevocationTimeout.Duration != 10*time.Second {
		t.Error("expected client.revocation-timeout = 10s")
	}
	if s.Client.RevocationSoftFail == nil || *s.Client.RevocationSoftFail {
		t.Error("expected client.revocation-soft-fail = false")
	}

	// Pem
	if s.Pem.ExpiryWarning == nil || *s.Pem.ExpiryWarning != 7 {
		t.Error("expected pem.expiry-warning = 7")
	}
	if s.Pem.Output == nil || *s.Pem.Output != "yaml" {
		t.Error("expected pem.output = yaml")
	}
}

func TestFlagValues_Client(t *testing.T) {
	expiry := 21
	output := "json"
	formatVersion := 2
	connectTimeout := Duration{Duration: 4 * time.Second}
	handshakeTimeout := Duration{Duration: 9 * time.Second}
	s := &Settings{
		Client: ClientSettings{
			ExpiryWarning:    &expiry,
			Output:           &output,
			FormatVersion:    &formatVersion,
			ConnectTimeout:   &connectTimeout,
			HandshakeTimeout: &handshakeTimeout,
		},
	}

	vals := s.FlagValues("client")
	if vals["expiry-warning"] != "21" {
		t.Errorf("expected expiry-warning=21, got %s", vals["expiry-warning"])
	}
	if vals["output"] != "json" {
		t.Errorf("expected output=json, got %s", vals["output"])
	}
	if vals["format-version"] != "2" {
		t.Errorf("expected format-version=2, got %s", vals["format-version"])
	}
	if vals["connect-timeout"] != "4s" {
		t.Errorf("expected connect-timeout=4s, got %s", vals["connect-timeout"])
	}
	if vals["handshake-timeout"] != "9s" {
		t.Errorf("expected handshake-timeout=9s, got %s", vals["handshake-timeout"])
	}
}

func TestFlagValues_Pem(t *testing.T) {
	noColor := true
	expiry := 7
	s := &Settings{
		Global: GlobalSettings{NoColor: &noColor},
		Pem: PemSettings{
			ExpiryWarning: &expiry,
		},
	}

	vals := s.FlagValues("pem")
	if vals["no-color"] != "true" {
		t.Errorf("expected no-color=true, got %s", vals["no-color"])
	}
	if vals["expiry-warning"] != "7" {
		t.Errorf("expected expiry-warning=7, got %s", vals["expiry-warning"])
	}
}

func TestFlagValues_UnknownSubcommand(t *testing.T) {
	noColor := true
	s := &Settings{
		Global: GlobalSettings{NoColor: &noColor},
	}

	vals := s.FlagValues("unknown")
	if vals["no-color"] != "true" {
		t.Errorf("global settings should still apply for unknown subcommand")
	}
	if len(vals) != 1 {
		t.Errorf("expected only global flags, got %d entries", len(vals))
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	s, err := Load(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vals := s.FlagValues("client")
	if len(vals) != 0 {
		t.Errorf("expected no flag values from empty config, got %d", len(vals))
	}
}

func TestFlagValues_GlobalOverriddenBySubcommand(t *testing.T) {
	globalExpiry := 30
	clientExpiry := 21
	globalOutput := "yaml"
	clientOutput := "json"
	globalCACert := "/global/ca.pem"

	s := &Settings{
		Global: GlobalSettings{
			ExpiryWarning: &globalExpiry,
			Output:        &globalOutput,
			CACert:        &globalCACert,
		},
		Client: ClientSettings{
			ExpiryWarning: &clientExpiry,
			Output:        &clientOutput,
		},
	}

	vals := s.FlagValues("client")
	if vals["expiry-warning"] != "21" {
		t.Errorf("expected client override expiry-warning=21, got %s", vals["expiry-warning"])
	}
	if vals["output"] != "json" {
		t.Errorf("expected client override output=json, got %s", vals["output"])
	}
	if vals["cacert"] != "/global/ca.pem" {
		t.Errorf("expected global cacert, got %s", vals["cacert"])
	}
}

func TestFlagValues_GlobalAppliedWhenSubcommandUnset(t *testing.T) {
	globalExpiry := 30
	globalOutput := "yaml"
	globalRevocation := "ocsp"
	globalConnectTimeout := Duration{Duration: 5 * time.Second}

	s := &Settings{
		Global: GlobalSettings{
			ExpiryWarning:  &globalExpiry,
			Output:         &globalOutput,
			ConnectTimeout: &globalConnectTimeout,
			Revocation:     &globalRevocation,
		},
	}

	vals := s.FlagValues("pem")
	if vals["expiry-warning"] != "30" {
		t.Errorf("expected global expiry-warning=30, got %s", vals["expiry-warning"])
	}
	if vals["output"] != "yaml" {
		t.Errorf("expected global output=yaml, got %s", vals["output"])
	}
	if vals["connect-timeout"] != "5s" {
		t.Errorf("expected global connect-timeout=5s, got %s", vals["connect-timeout"])
	}
	if vals["revocation"] != "ocsp" {
		t.Errorf("expected global revocation=ocsp, got %s", vals["revocation"])
	}
}

func TestFlagValues_SubcommandOverridesGlobalNoColorQuiet(t *testing.T) {
	globalNoColor := true
	globalQuiet := true
	clientNoColor := false
	pemQuiet := false

	s := &Settings{
		Global: GlobalSettings{
			NoColor: &globalNoColor,
			Quiet:   &globalQuiet,
		},
		Client: ClientSettings{
			NoColor: &clientNoColor,
		},
		Pem: PemSettings{
			Quiet: &pemQuiet,
		},
	}

	clientVals := s.FlagValues("client")
	if clientVals["no-color"] != "false" {
		t.Errorf("expected client override no-color=false, got %s", clientVals["no-color"])
	}
	if clientVals["quiet"] != "true" {
		t.Errorf("expected global quiet=true for client, got %s", clientVals["quiet"])
	}

	pemVals := s.FlagValues("pem")
	if pemVals["no-color"] != "true" {
		t.Errorf("expected global no-color=true for pem, got %s", pemVals["no-color"])
	}
	if pemVals["quiet"] != "false" {
		t.Errorf("expected pem override quiet=false, got %s", pemVals["quiet"])
	}
}

func TestLoad_InvalidGlobalExpiryWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"global": {"expiry-warning": 0}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected validation error for global.expiry-warning")
	}
}

func TestLoad_InvalidGlobalRevocation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"global": {"revocation": "invalid"}}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	_, err := Load(path, false)
	if err == nil {
		t.Fatal("expected validation error for global.revocation")
	}
}

func TestLoad_ValidGlobalConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{
		"global": {
			"no-color": true,
			"quiet": false,
			"expiry-warning": 45,
			"output": "json",
			"cacert": "/etc/ssl/ca.pem",
			"connect-timeout": "6s",
			"handshake-timeout": "12s",
			"revocation": "crl",
			"revocation-timeout": "8s",
			"revocation-soft-fail": false
		}
	}`), 0644); err != nil {
		t.Fatalf("failed to write file: %v", err)
	}

	s, err := Load(path, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if s.Global.ExpiryWarning == nil || *s.Global.ExpiryWarning != 45 {
		t.Error("expected global.expiry-warning = 45")
	}
	if s.Global.Output == nil || *s.Global.Output != "json" {
		t.Error("expected global.output = json")
	}
	if s.Global.CACert == nil || *s.Global.CACert != "/etc/ssl/ca.pem" {
		t.Error("expected global.cacert = /etc/ssl/ca.pem")
	}
	if s.Global.ConnectTimeout == nil || s.Global.ConnectTimeout.Duration != 6*time.Second {
		t.Error("expected global.connect-timeout = 6s")
	}
	if s.Global.HandshakeTimeout == nil || s.Global.HandshakeTimeout.Duration != 12*time.Second {
		t.Error("expected global.handshake-timeout = 12s")
	}
	if s.Global.Revocation == nil || *s.Global.Revocation != "crl" {
		t.Error("expected global.revocation = crl")
	}
	if s.Global.RevocationTimeout == nil || s.Global.RevocationTimeout.Duration != 8*time.Second {
		t.Error("expected global.revocation-timeout = 8s")
	}
	if s.Global.RevocationSoftFail == nil || *s.Global.RevocationSoftFail {
		t.Error("expected global.revocation-soft-fail = false")
	}
}

func TestDuration_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"valid seconds", `"5s"`, 5 * time.Second, false},
		{"valid minutes", `"2m"`, 2 * time.Minute, false},
		{"invalid", `"bad"`, 0, true},
		{"not string", `123`, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalJSON([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if d.Duration != tt.want {
				t.Errorf("got %v, want %v", d.Duration, tt.want)
			}
		})
	}
}

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const appName = "tlsctl"

// Duration is a time.Duration that unmarshals from a JSON string like "5s".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// GlobalSettings holds settings that apply to all subcommands.
type GlobalSettings struct {
	NoColor *bool `json:"no-color,omitempty"`
	Quiet   *bool `json:"quiet,omitempty"`
}

// ClientSettings holds settings for the client subcommand.
type ClientSettings struct {
	ExpiryWarning      *int      `json:"expiry-warning,omitempty"`
	Output             *string   `json:"output,omitempty"`
	CACert             *string   `json:"cacert,omitempty"`
	Proxy              *string   `json:"proxy,omitempty"`
	File               *string   `json:"file,omitempty"`
	TLSVersions        *bool     `json:"tls-versions,omitempty"`
	ServerName         *string   `json:"servername,omitempty"`
	StartTLS           *string   `json:"starttls,omitempty"`
	Insecure           *bool     `json:"insecure,omitempty"`
	Revocation         *string   `json:"revocation,omitempty"`
	RevocationTimeout  *Duration `json:"revocation-timeout,omitempty"`
	RevocationSoftFail *bool     `json:"revocation-soft-fail,omitempty"`
}

// PemSettings holds settings for the pem subcommand.
type PemSettings struct {
	ExpiryWarning      *int      `json:"expiry-warning,omitempty"`
	Output             *string   `json:"output,omitempty"`
	CACert             *string   `json:"cacert,omitempty"`
	Revocation         *string   `json:"revocation,omitempty"`
	RevocationTimeout  *Duration `json:"revocation-timeout,omitempty"`
	RevocationSoftFail *bool     `json:"revocation-soft-fail,omitempty"`
}

// Settings represents the full configuration file.
type Settings struct {
	Global GlobalSettings `json:"global"`
	Client ClientSettings `json:"client"`
	Pem    PemSettings    `json:"pem"`
}

// DefaultPath returns the OS-specific default path for settings.json.
func DefaultPath() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine config directory: %w", err)
	}
	return filepath.Join(base, appName, "settings.json"), nil
}

// Load reads and parses a settings.json file from the given path.
// If explicit is true, a missing file is treated as an error.
// If explicit is false (default path), a missing file returns empty settings.
func Load(path string, explicit bool) (*Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			return &Settings{}, nil
		}
		return nil, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var s Settings
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}

	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}

	return &s, nil
}

func (s *Settings) validate() error {
	if err := validateExpiryWarning(s.Client.ExpiryWarning); err != nil {
		return fmt.Errorf("client.expiry-warning: %w", err)
	}
	if err := validateExpiryWarning(s.Pem.ExpiryWarning); err != nil {
		return fmt.Errorf("pem.expiry-warning: %w", err)
	}
	if err := validateRevocationMode(s.Client.Revocation); err != nil {
		return fmt.Errorf("client.revocation: %w", err)
	}
	if err := validateRevocationMode(s.Pem.Revocation); err != nil {
		return fmt.Errorf("pem.revocation: %w", err)
	}
	if err := validateStartTLS(s.Client.StartTLS); err != nil {
		return fmt.Errorf("client.starttls: %w", err)
	}
	return nil
}

func validateExpiryWarning(v *int) error {
	if v == nil {
		return nil
	}
	if *v < 1 || *v > 10000 {
		return fmt.Errorf("must be between 1 and 10000")
	}
	return nil
}

func validateRevocationMode(v *string) error {
	if v == nil {
		return nil
	}
	switch *v {
	case "", "crl", "ocsp":
		return nil
	default:
		return fmt.Errorf("must be one of crl, ocsp")
	}
}

func validateStartTLS(v *string) error {
	if v == nil {
		return nil
	}
	switch *v {
	case "", "smtp", "imap", "pop3", "ldap":
		return nil
	default:
		return fmt.Errorf("must be one of smtp, imap, pop3, ldap")
	}
}

// FlagValues returns a map of flag-name to string-value for the given
// subcommand section. Only non-nil fields are included.
func (s *Settings) FlagValues(subcommand string) map[string]string {
	vals := make(map[string]string)

	// Apply global settings first.
	if s.Global.NoColor != nil {
		vals["no-color"] = boolStr(*s.Global.NoColor)
	}
	if s.Global.Quiet != nil {
		vals["quiet"] = boolStr(*s.Global.Quiet)
	}

	// Apply subcommand-specific settings (overrides global if same key).
	switch subcommand {
	case "client":
		addClientFlags(vals, &s.Client)
	case "pem":
		addPemFlags(vals, &s.Pem)
	}

	return vals
}

func addClientFlags(vals map[string]string, c *ClientSettings) {
	if c.ExpiryWarning != nil {
		vals["expiry-warning"] = fmt.Sprintf("%d", *c.ExpiryWarning)
	}
	if c.Output != nil {
		vals["output"] = *c.Output
	}
	if c.CACert != nil {
		vals["cacert"] = *c.CACert
	}
	if c.Proxy != nil {
		vals["proxy"] = *c.Proxy
	}
	if c.File != nil {
		vals["file"] = *c.File
	}
	if c.TLSVersions != nil {
		vals["tls-versions"] = boolStr(*c.TLSVersions)
	}
	if c.ServerName != nil {
		vals["servername"] = *c.ServerName
	}
	if c.StartTLS != nil {
		vals["starttls"] = *c.StartTLS
	}
	if c.Insecure != nil {
		vals["insecure"] = boolStr(*c.Insecure)
	}
	if c.Revocation != nil {
		vals["revocation"] = *c.Revocation
	}
	if c.RevocationTimeout != nil {
		vals["revocation-timeout"] = c.RevocationTimeout.String()
	}
	if c.RevocationSoftFail != nil {
		vals["revocation-soft-fail"] = boolStr(*c.RevocationSoftFail)
	}
}

func addPemFlags(vals map[string]string, p *PemSettings) {
	if p.ExpiryWarning != nil {
		vals["expiry-warning"] = fmt.Sprintf("%d", *p.ExpiryWarning)
	}
	if p.Output != nil {
		vals["output"] = *p.Output
	}
	if p.CACert != nil {
		vals["cacert"] = *p.CACert
	}
	if p.Revocation != nil {
		vals["revocation"] = *p.Revocation
	}
	if p.RevocationTimeout != nil {
		vals["revocation-timeout"] = p.RevocationTimeout.String()
	}
	if p.RevocationSoftFail != nil {
		vals["revocation-soft-fail"] = boolStr(*p.RevocationSoftFail)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

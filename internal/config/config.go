package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/catay/tlsctl/v2/internal/output"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
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
	NoColor            *bool     `json:"no-color,omitempty"`
	Quiet              *bool     `json:"quiet,omitempty"`
	ExpiryWarning      *int      `json:"expiry-warning,omitempty"`
	Output             *string   `json:"output,omitempty"`
	CACert             *string   `json:"cacert,omitempty"`
	ConnectTimeout     *Duration `json:"connect-timeout,omitempty"`
	HandshakeTimeout   *Duration `json:"handshake-timeout,omitempty"`
	Revocation         *string   `json:"revocation,omitempty"`
	RevocationTimeout  *Duration `json:"revocation-timeout,omitempty"`
	RevocationSoftFail *bool     `json:"revocation-soft-fail,omitempty"`
}

// ClientSettings holds settings for the client subcommand.
type ClientSettings struct {
	Concurrency        *int      `json:"concurrency,omitempty"`
	Timeout            *Duration `json:"timeout,omitempty"`
	NoColor            *bool     `json:"no-color,omitempty"`
	Quiet              *bool     `json:"quiet,omitempty"`
	ExpiryWarning      *int      `json:"expiry-warning,omitempty"`
	Output             *string   `json:"output,omitempty"`
	CACert             *string   `json:"cacert,omitempty"`
	Proxy              *string   `json:"proxy,omitempty"`
	File               *string   `json:"file,omitempty"`
	TLSVersions        *bool     `json:"tls-versions,omitempty"`
	ALPN               *string   `json:"alpn,omitempty"`
	ServerName         *string   `json:"servername,omitempty"`
	StartTLS           *string   `json:"starttls,omitempty"`
	ConnectTimeout     *Duration `json:"connect-timeout,omitempty"`
	HandshakeTimeout   *Duration `json:"handshake-timeout,omitempty"`
	Revocation         *string   `json:"revocation,omitempty"`
	RevocationTimeout  *Duration `json:"revocation-timeout,omitempty"`
	RevocationSoftFail *bool     `json:"revocation-soft-fail,omitempty"`
}

// PemSettings holds settings for the pem subcommand.
type PemSettings struct {
	NoColor            *bool     `json:"no-color,omitempty"`
	Quiet              *bool     `json:"quiet,omitempty"`
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

	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("invalid config file %s: expected a single JSON document", path)
	}

	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("invalid config file %s: %w", path, err)
	}

	return &s, nil
}

func (s *Settings) validate() error {
	for _, section := range []struct {
		name    string
		format  *string
		timeout *Duration
	}{
		{"global", s.Global.Output, s.Global.RevocationTimeout},
		{"client", s.Client.Output, s.Client.RevocationTimeout},
		{"pem", s.Pem.Output, s.Pem.RevocationTimeout},
	} {
		if section.format != nil {
			if _, err := output.New(output.Format(*section.format)); err != nil {
				return fmt.Errorf("%s.output: %w", section.name, err)
			}
		}
		if err := validatePositiveDuration(section.timeout); err != nil {
			return fmt.Errorf("%s.revocation-timeout: %w", section.name, err)
		}
	}
	if s.Client.Concurrency != nil && (*s.Client.Concurrency < 1 || *s.Client.Concurrency > 256) {
		return fmt.Errorf("client.concurrency: must be between 1 and 256")
	}
	if err := validatePositiveDuration(s.Client.Timeout); err != nil {
		return fmt.Errorf("client.timeout: %w", err)
	}

	if err := validateExpiryWarning(s.Global.ExpiryWarning); err != nil {
		return fmt.Errorf("global.expiry-warning: %w", err)
	}
	if err := validateRevocationMode(s.Global.Revocation); err != nil {
		return fmt.Errorf("global.revocation: %w", err)
	}
	if err := validatePositiveDuration(s.Global.ConnectTimeout); err != nil {
		return fmt.Errorf("global.connect-timeout: %w", err)
	}
	if err := validatePositiveDuration(s.Global.HandshakeTimeout); err != nil {
		return fmt.Errorf("global.handshake-timeout: %w", err)
	}
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
	if err := validateALPN(s.Client.ALPN); err != nil {
		return fmt.Errorf("client.alpn: %w", err)
	}
	if s.Client.Proxy != nil {
		if err := tlsquery.ValidateProxy(*s.Client.Proxy); err != nil {
			return fmt.Errorf("client.proxy: %w", err)
		}
	}
	if err := validatePositiveDuration(s.Client.ConnectTimeout); err != nil {
		return fmt.Errorf("client.connect-timeout: %w", err)
	}
	if err := validatePositiveDuration(s.Client.HandshakeTimeout); err != nil {
		return fmt.Errorf("client.handshake-timeout: %w", err)
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
	if *v == "" {
		return nil
	}
	if tlsquery.ValidStartTLSProtocol(*v) {
		return nil
	}
	return fmt.Errorf("must be one of %s", tlsquery.StartTLSProtocolList())
}

func validateALPN(v *string) error {
	if v == nil {
		return nil
	}
	_, err := tlsquery.ParseALPNProtocols(*v)
	return err
}

func validatePositiveDuration(v *Duration) error {
	if v == nil {
		return nil
	}
	if v.Duration <= 0 {
		return fmt.Errorf("must be greater than 0")
	}
	return nil
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
	if s.Global.ExpiryWarning != nil {
		vals["expiry-warning"] = fmt.Sprintf("%d", *s.Global.ExpiryWarning)
	}
	if s.Global.Output != nil {
		vals["output"] = *s.Global.Output
	}
	if s.Global.CACert != nil {
		vals["cacert"] = *s.Global.CACert
	}
	if s.Global.ConnectTimeout != nil {
		vals["connect-timeout"] = s.Global.ConnectTimeout.String()
	}
	if s.Global.HandshakeTimeout != nil {
		vals["handshake-timeout"] = s.Global.HandshakeTimeout.String()
	}
	if s.Global.Revocation != nil {
		vals["revocation"] = *s.Global.Revocation
	}
	if s.Global.RevocationTimeout != nil {
		vals["revocation-timeout"] = s.Global.RevocationTimeout.String()
	}
	if s.Global.RevocationSoftFail != nil {
		vals["revocation-soft-fail"] = boolStr(*s.Global.RevocationSoftFail)
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
	if c.Concurrency != nil {
		vals["concurrency"] = fmt.Sprint(*c.Concurrency)
	}
	if c.Timeout != nil {
		vals["timeout"] = c.Timeout.String()
	}
	if c.NoColor != nil {
		vals["no-color"] = boolStr(*c.NoColor)
	}
	if c.Quiet != nil {
		vals["quiet"] = boolStr(*c.Quiet)
	}
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
	if c.ALPN != nil {
		vals["alpn"] = *c.ALPN
	}
	if c.ServerName != nil {
		vals["servername"] = *c.ServerName
	}
	if c.StartTLS != nil {
		vals["starttls"] = *c.StartTLS
	}
	if c.ConnectTimeout != nil {
		vals["connect-timeout"] = c.ConnectTimeout.String()
	}
	if c.HandshakeTimeout != nil {
		vals["handshake-timeout"] = c.HandshakeTimeout.String()
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
	if p.NoColor != nil {
		vals["no-color"] = boolStr(*p.NoColor)
	}
	if p.Quiet != nil {
		vals["quiet"] = boolStr(*p.Quiet)
	}
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

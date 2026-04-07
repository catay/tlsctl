package cli

import (
	"strings"
	"testing"
)

func TestNormalizeEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		want      string
		wantError bool
		errorMsg  string
	}{
		{
			name:     "valid endpoint with port",
			endpoint: "example.com:443",
			want:     "example.com:443",
		},
		{
			name:     "valid IP endpoint",
			endpoint: "192.168.1.1:8443",
			want:     "192.168.1.1:8443",
		},
		{
			name:     "missing port defaults to 443",
			endpoint: "example.com",
			want:     "example.com:443",
		},
		{
			name:      "empty hostname",
			endpoint:  ":443",
			wantError: true,
			errorMsg:  "invalid hostname",
		},
		{
			name:     "empty port defaults to 443",
			endpoint: "example.com:",
			want:     "example.com:443",
		},
		{
			name:      "non-numeric port",
			endpoint:  "example.com:abc",
			wantError: true,
			errorMsg:  "port must be a number in the range 0-65535",
		},
		{
			name:     "port at lower bound",
			endpoint: "example.com:0",
			want:     "example.com:0",
		},
		{
			name:     "port at upper bound",
			endpoint: "example.com:65535",
			want:     "example.com:65535",
		},
		{
			name:      "port exceeds upper bound",
			endpoint:  "example.com:65536",
			wantError: true,
			errorMsg:  "port must be a number in the range 0-65535",
		},
		{
			name:      "port way out of range",
			endpoint:  "example.com:99999",
			wantError: true,
			errorMsg:  "port must be a number in the range 0-65535",
		},
		{
			name:     "IPv6 address with port",
			endpoint: "[::1]:443",
			want:     "[::1]:443",
		},
		{
			name:     "IPv6 address without port",
			endpoint: "::1",
			want:     "[::1]:443",
		},
		{
			name:     "full IPv6 address with port",
			endpoint: "[2001:db8::1]:8443",
			want:     "[2001:db8::1]:8443",
		},
		{
			name:      "reject URL scheme",
			endpoint:  "https://example.com",
			wantError: true,
			errorMsg:  "expected host[:port], not a URL",
		},
		{
			name:      "reject path",
			endpoint:  "example.com/path",
			wantError: true,
			errorMsg:  "expected host[:port], not a URL",
		},
		{
			name:      "reject query",
			endpoint:  "example.com?foo=bar",
			wantError: true,
			errorMsg:  "expected host[:port], not a URL",
		},
		{
			name:      "reject fragment",
			endpoint:  "example.com#anchor",
			wantError: true,
			errorMsg:  "expected host[:port], not a URL",
		},
		{
			name:      "reject userinfo",
			endpoint:  "user@example.com",
			wantError: true,
			errorMsg:  "expected host[:port], not a URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tt.endpoint)
			if tt.wantError {
				if err == nil {
					t.Errorf("NormalizeEndpoint(%q) expected error, got nil", tt.endpoint)
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("NormalizeEndpoint(%q) error = %q, want to contain %q", tt.endpoint, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("NormalizeEndpoint(%q) unexpected error: %v", tt.endpoint, err)
				}
				if got != tt.want {
					t.Errorf("NormalizeEndpoint(%q) = %q, want %q", tt.endpoint, got, tt.want)
				}
			}
		})
	}
}

func TestNormalizeEndpoint_StartTLS(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		proto    string
		want     string
	}{
		{"smtp default port", "mail.example.com", "smtp", "mail.example.com:587"},
		{"imap default port", "mail.example.com", "imap", "mail.example.com:143"},
		{"pop3 default port", "mail.example.com", "pop3", "mail.example.com:110"},
		{"ldap default port", "ldap.example.com", "ldap", "ldap.example.com:389"},
		{"explicit port overrides", "mail.example.com:25", "smtp", "mail.example.com:25"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeEndpoint(tt.endpoint, tt.proto)
			if err != nil {
				t.Fatalf("NormalizeEndpoint(%q, %q) unexpected error: %v", tt.endpoint, tt.proto, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeEndpoint(%q, %q) = %q, want %q", tt.endpoint, tt.proto, got, tt.want)
			}
		})
	}
}

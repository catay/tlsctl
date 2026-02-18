package tlsquery

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
)

func TestAbbreviateVerifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "hostname mismatch",
			err:      x509.HostnameError{Host: "example.com", Certificate: &x509.Certificate{Subject: pkix.Name{CommonName: "other.com"}}},
			expected: "hostname mismatch",
		},
		{
			name:     "unknown authority",
			err:      x509.UnknownAuthorityError{},
			expected: "unknown authority",
		},
		{
			name:     "certificate expired",
			err:      x509.CertificateInvalidError{Reason: x509.Expired},
			expected: "certificate expired",
		},
		{
			name:     "not authorized to sign",
			err:      x509.CertificateInvalidError{Reason: x509.NotAuthorizedToSign},
			expected: "not authorized to sign",
		},
		{
			name:     "name mismatch",
			err:      x509.CertificateInvalidError{Reason: x509.NameMismatch},
			expected: "name mismatch",
		},
		{
			name:     "invalid certificate generic",
			err:      x509.CertificateInvalidError{Reason: x509.IncompatibleUsage},
			expected: "invalid certificate",
		},
		{
			name:     "system roots error",
			err:      x509.SystemRootsError{},
			expected: "system roots unavailable",
		},
		{
			name:     "generic error strips x509 prefix",
			err:      errors.New("x509: something went wrong"),
			expected: "something went wrong",
		},
		{
			name:     "generic error without prefix",
			err:      errors.New("some other error"),
			expected: "some other error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := abbreviateVerifyError(tt.err)
			if got != tt.expected {
				t.Errorf("abbreviateVerifyError(%v) = %q, want %q", tt.err, got, tt.expected)
			}
		})
	}
}

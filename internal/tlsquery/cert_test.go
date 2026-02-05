package tlsquery

import (
	"testing"
	"time"
)

func TestCertInfo_NotAfterTime(t *testing.T) {
	cert := &CertInfo{NotAfter: "2027-01-01T00:00:00Z"}

	got, err := cert.NotAfterTime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

func TestCertInfo_NotBeforeTime(t *testing.T) {
	cert := &CertInfo{NotBefore: "2025-01-01T00:00:00Z"}

	got, err := cert.NotBeforeTime()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, got)
	}
}

func TestCertInfo_DisplayName(t *testing.T) {
	tests := []struct {
		name     string
		cert     CertInfo
		expected string
	}{
		{
			name:     "uses CommonName when available",
			cert:     CertInfo{CommonName: "example.com", Subject: "CN=example.com", SubjectAltNames: []string{"www.example.com"}},
			expected: "example.com",
		},
		{
			name:     "falls back to first SAN",
			cert:     CertInfo{Subject: "O=Example", SubjectAltNames: []string{"www.example.com", "api.example.com"}},
			expected: "www.example.com",
		},
		{
			name:     "falls back to Subject",
			cert:     CertInfo{Subject: "O=Example Org"},
			expected: "O=Example Org",
		},
		{
			name:     "returns unknown when all empty",
			cert:     CertInfo{},
			expected: "(unknown)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cert.DisplayName()
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

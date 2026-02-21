package cmd

import (
	"testing"
	"time"

	"github.com/catay/tlsctl/internal/revocation"
	"github.com/catay/tlsctl/internal/tlsquery"
)

func TestSetExitCode(t *testing.T) {
	tests := []struct {
		name     string
		initial  int
		set      int
		expected int
	}{
		{"zero to runtime error", ExitOK, ExitRuntimeError, ExitRuntimeError},
		{"zero to insecure", ExitOK, ExitInsecure, ExitInsecure},
		{"zero to revocation error", ExitOK, ExitRevocationError, ExitRevocationError},
		{"zero to expiring", ExitOK, ExitExpiring, ExitExpiring},
		{"expiring to insecure", ExitExpiring, ExitInsecure, ExitInsecure},
		{"expiring to revocation error", ExitExpiring, ExitRevocationError, ExitRevocationError},
		{"insecure to expiring is no-op", ExitInsecure, ExitExpiring, ExitInsecure},
		{"insecure to revocation error", ExitInsecure, ExitRevocationError, ExitRevocationError},
		{"revocation error to insecure is no-op", ExitRevocationError, ExitInsecure, ExitRevocationError},
		{"revocation error to expiring is no-op", ExitRevocationError, ExitExpiring, ExitRevocationError},
		{"runtime error is sticky", ExitRuntimeError, ExitInsecure, ExitRuntimeError},
		{"runtime error stays over revocation", ExitRuntimeError, ExitRevocationError, ExitRuntimeError},
		{"runtime error stays over expiring", ExitRuntimeError, ExitExpiring, ExitRuntimeError},
		{"insecure to runtime error", ExitInsecure, ExitRuntimeError, ExitRuntimeError},
		{"expiring to runtime error", ExitExpiring, ExitRuntimeError, ExitRuntimeError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = tt.initial
			setExitCode(tt.set)
			if exitCode != tt.expected {
				t.Errorf("setExitCode(%d) with initial %d: got %d, want %d", tt.set, tt.initial, exitCode, tt.expected)
			}
			exitCode = ExitOK // reset
		})
	}
}

func TestUpdateExitCodeForChain(t *testing.T) {
	now := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		chain    *tlsquery.ChainInfo
		expected int
	}{
		{
			name:     "nil chain",
			chain:    nil,
			expected: ExitOK,
		},
		{
			name: "verified valid cert",
			chain: &tlsquery.ChainInfo{
				Verified: true,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2027-01-01T00:00:00Z",
				}},
			},
			expected: ExitOK,
		},
		{
			name: "unverified cert",
			chain: &tlsquery.ChainInfo{
				Verified: false,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2027-01-01T00:00:00Z",
				}},
			},
			expected: ExitInsecure,
		},
		{
			name: "expiring soon cert",
			chain: &tlsquery.ChainInfo{
				Verified: true,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2026-07-01T00:00:00Z",
				}},
			},
			expected: ExitExpiring,
		},
		{
			name: "expired cert",
			chain: &tlsquery.ChainInfo{
				Verified: true,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2025-01-01T00:00:00Z",
				}},
			},
			expected: ExitInsecure,
		},
		{
			name: "revoked cert",
			chain: &tlsquery.ChainInfo{
				Verified: true,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2027-01-01T00:00:00Z",
					Revocation: &revocation.Info{
						OverallStatus: revocation.StatusRevoked,
					},
				}},
			},
			expected: ExitInsecure,
		},
		{
			name: "revocation error",
			chain: &tlsquery.ChainInfo{
				Verified: true,
				Certificates: []tlsquery.CertInfo{{
					Type:     "leaf",
					NotAfter: "2027-01-01T00:00:00Z",
					Revocation: &revocation.Info{
						OverallStatus: revocation.StatusError,
					},
				}},
			},
			expected: ExitRevocationError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode = ExitOK
			updateExitCodeForChain(tt.chain, now)
			if exitCode != tt.expected {
				t.Errorf("got exit code %d, want %d", exitCode, tt.expected)
			}
			exitCode = ExitOK // reset
		})
	}
}

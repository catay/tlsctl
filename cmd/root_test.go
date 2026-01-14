package cmd

import "testing"

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name      string
		endpoint  string
		wantError bool
		errorMsg  string
	}{
		{
			name:      "valid endpoint",
			endpoint:  "example.com:443",
			wantError: false,
		},
		{
			name:      "valid IP endpoint",
			endpoint:  "192.168.1.1:8443",
			wantError: false,
		},
		{
			name:      "missing port",
			endpoint:  "example.com",
			wantError: true,
			errorMsg:  "invalid endpoint format",
		},
		{
			name:      "empty hostname",
			endpoint:  ":443",
			wantError: true,
			errorMsg:  "invalid hostname",
		},
		{
			name:      "empty port",
			endpoint:  "example.com:",
			wantError: true,
			errorMsg:  "invalid port: port cannot be empty",
		},
		{
			name:      "non-numeric port",
			endpoint:  "example.com:abc",
			wantError: true,
			errorMsg:  "invalid port",
		},
		{
			name:      "multiple colons without brackets",
			endpoint:  "a:b:c",
			wantError: true,
			errorMsg:  "invalid endpoint format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEndpoint(tt.endpoint)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateEndpoint(%q) expected error, got nil", tt.endpoint)
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("validateEndpoint(%q) error = %q, want to contain %q", tt.endpoint, err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateEndpoint(%q) unexpected error: %v", tt.endpoint, err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

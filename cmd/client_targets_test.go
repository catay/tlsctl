package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/tlsquery"
)

func TestCollectTargets(t *testing.T) {
	dir := t.TempDir()
	validFile := filepath.Join(dir, "targets.txt")
	if err := os.WriteFile(validFile, []byte(`# comment
example.com
example.org:8443 # inline comment

`), 0644); err != nil {
		t.Fatalf("failed to write targets file: %v", err)
	}

	emptyFile := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(emptyFile, []byte("# only comments\n\n"), 0644); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		file    string
		want    []string
		wantErr bool
	}{
		{
			name: "args only",
			args: []string{"example.net"},
			want: []string{"example.net:443"},
		},
		{
			name: "file only",
			file: validFile,
			want: []string{"example.com:443", "example.org:8443"},
		},
		{
			name: "file and args",
			args: []string{"api.local:9443"},
			file: validFile,
			want: []string{"example.com:443", "example.org:8443", "api.local:9443"},
		},
		{
			name:    "empty inputs",
			wantErr: true,
		},
		{
			name:    "file with no endpoints",
			file:    emptyFile,
			wantErr: true,
		},
		{
			name:    "invalid endpoint",
			args:    []string{"example.com:abc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := collectTargets(tt.args, tt.file, "")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateOutputFormatVersion(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		version int
		wantErr bool
	}{
		{name: "default version", format: "", version: 1},
		{name: "json v2", format: "json", version: 2},
		{name: "yaml v2", format: "yaml", version: 2},
		{name: "invalid version", format: "json", version: 3, wantErr: true},
		{name: "csv v2", format: "csv", version: 2},
		{name: "csv full v2", format: "csv-full", version: 2},
		{name: "human v2 unsupported", format: "", version: 2, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputFormatVersion(output.Format(tt.format), tt.version)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestValidateConnectionTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		flags   connectionFlags
		wantErr bool
	}{
		{
			name: "valid",
			flags: connectionFlags{
				connectTimeout:   time.Second,
				handshakeTimeout: 2 * time.Second,
			},
		},
		{
			name: "invalid connect timeout",
			flags: connectionFlags{
				connectTimeout:   0,
				handshakeTimeout: time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid handshake timeout",
			flags: connectionFlags{
				connectTimeout:   time.Second,
				handshakeTimeout: 0,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConnectionTimeouts(tt.flags)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestParseALPNProtocols(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "empty", input: "", want: nil},
		{name: "single", input: "h2", want: []string{"h2"}},
		{name: "multiple", input: "h2,http/1.1", want: []string{"h2", "http/1.1"}},
		{name: "trim spaces", input: " h2, http/1.1 ", want: []string{"h2", "http/1.1"}},
		{name: "empty entry", input: "h2,,http/1.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlsquery.ParseALPNProtocols(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewClientCmdALPNFlag(t *testing.T) {
	cmd := newClientCmd(defaultRuntime)
	flag := cmd.Flags().Lookup("alpn")
	if flag == nil {
		t.Fatal("expected --alpn flag to be registered")
	}
	if flag.DefValue != "" {
		t.Fatalf("expected --alpn default to be empty, got %q", flag.DefValue)
	}
}

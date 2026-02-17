package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
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
			got, err := collectTargets(tt.args, tt.file)
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

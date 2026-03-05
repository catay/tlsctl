package tlsquery

import (
	"net"
	"testing"
)

func TestValidStartTLSProtocol(t *testing.T) {
	tests := []struct {
		protocol string
		want     bool
	}{
		{"smtp", true},
		{"imap", true},
		{"pop3", true},
		{"ldap", true},
		{"SMTP", false},
		{"ftp", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			if got := ValidStartTLSProtocol(tt.protocol); got != tt.want {
				t.Errorf("ValidStartTLSProtocol(%q) = %v, want %v", tt.protocol, got, tt.want)
			}
		})
	}
}

func TestStartTLSPort(t *testing.T) {
	tests := []struct {
		protocol string
		want     string
		wantOK   bool
	}{
		{"smtp", "587", true},
		{"imap", "143", true},
		{"pop3", "110", true},
		{"ldap", "389", true},
		{"unknown", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.protocol, func(t *testing.T) {
			got, ok := StartTLSPort(tt.protocol)
			if got != tt.want {
				t.Errorf("StartTLSPort(%q) = %q, want %q", tt.protocol, got, tt.want)
			}
			if ok != tt.wantOK {
				t.Errorf("StartTLSPort(%q) ok = %v, want %v", tt.protocol, ok, tt.wantOK)
			}
		})
	}
}

func TestStartTLSProtocolsReturnsCopy(t *testing.T) {
	protos := StartTLSProtocols()
	if len(protos) == 0 {
		t.Fatal("expected non-empty protocol list")
	}

	protos[0] = "modified"
	if got := StartTLSProtocols()[0]; got == "modified" {
		t.Fatal("expected StartTLSProtocols to return a copy")
	}
}

func TestNegotiateStartTLS_UnsupportedProtocol(t *testing.T) {
	// Use a dummy connection; the function should return an error before reading.
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	err := negotiateStartTLS(client, "ftp")
	if err == nil {
		t.Fatal("expected error for unsupported protocol, got nil")
	}
}

func TestNegotiateSMTP(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		buf := make([]byte, 256)
		_, _ = server.Write([]byte("220 mail.example.com ESMTP ready\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"))
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("220 Ready to start TLS\r\n"))
	}()

	if err := negotiateStartTLS(client, "smtp"); err != nil {
		t.Fatalf("negotiateStartTLS(smtp) failed: %v", err)
	}
}

func TestNegotiateIMAP(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("* OK IMAP4rev1 Server ready\r\n"))
		buf := make([]byte, 256)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("a001 OK Begin TLS negotiation now\r\n"))
	}()

	if err := negotiateStartTLS(client, "imap"); err != nil {
		t.Fatalf("negotiateStartTLS(imap) failed: %v", err)
	}
}

func TestNegotiateIMAP_UntaggedLines(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("* OK IMAP4rev1 Server ready\r\n"))
		buf := make([]byte, 256)
		_, _ = server.Read(buf)
		// Server sends untagged capability line before the tagged response.
		_, _ = server.Write([]byte("* CAPABILITY IMAP4rev1 STARTTLS\r\n"))
		_, _ = server.Write([]byte("a001 OK Begin TLS negotiation now\r\n"))
	}()

	if err := negotiateStartTLS(client, "imap"); err != nil {
		t.Fatalf("negotiateStartTLS(imap) with untagged lines failed: %v", err)
	}
}

func TestNegotiatePOP3(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		_, _ = server.Write([]byte("+OK POP3 server ready\r\n"))
		buf := make([]byte, 256)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("+OK Begin TLS negotiation\r\n"))
	}()

	if err := negotiateStartTLS(client, "pop3"); err != nil {
		t.Fatalf("negotiateStartTLS(pop3) failed: %v", err)
	}
}

func TestNegotiateLDAP(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		buf := make([]byte, 256)
		_, _ = server.Read(buf)
		// Send a successful ExtendedResponse:
		//   SEQUENCE { INTEGER(1), APPLICATION(24) { ENUMERATED(0), OCTET_STRING(""), OCTET_STRING("") } }
		resp := []byte{
			0x30, 0x0c, // SEQUENCE, length 12
			0x02, 0x01, 0x01, // INTEGER 1 (MessageID)
			0x78, 0x07, // APPLICATION 24, length 7
			0x0a, 0x01, 0x00, // ENUMERATED 0 (success)
			0x04, 0x00, // OCTET STRING "" (matchedDN)
			0x04, 0x00, // OCTET STRING "" (diagnosticMessage)
		}
		_, _ = server.Write(resp)
	}()

	if err := negotiateStartTLS(client, "ldap"); err != nil {
		t.Fatalf("negotiateStartTLS(ldap) failed: %v", err)
	}
}

package tlsquery

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQueryVerifiesSameHandshake(t *testing.T) {
	var handshakes atomic.Int32
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	s.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		handshakes.Add(1)
		return nil, nil
	}}
	s.StartTLS()
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	for _, trusted := range []bool{true, false} {
		opts := QueryOptions{}
		if trusted {
			opts.RootCAs = roots
		}
		before := handshakes.Load()
		chain, err := Query(s.Listener.Addr().String(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if chain.Verified != trusted || handshakes.Load()-before != 1 {
			t.Fatalf("trusted=%v verified=%v handshakes=%d", trusted, chain.Verified, handshakes.Load()-before)
		}
	}
}

func TestQueryLegacyOnlyServer(t *testing.T) {
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}}
	s.StartTLS()
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	chain, err := QueryContext(ctx, s.Listener.Addr().String(), QueryOptions{TLSVersions: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(chain.TLSVersions) != 1 || chain.TLSVersions[0].Version != "TLS 1.0" || chain.Verified {
		t.Fatalf("unexpected legacy probe: %+v", chain)
	}
}

func TestQueryCancellationDuringHandshake(t *testing.T) {
	for _, mode := range []string{"tls", "smtp", "proxy"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan struct{})
			done := make(chan struct{})
			go func() {
				defer close(done)
				conn, err := listener.Accept()
				close(accepted)
				if err == nil {
					defer conn.Close()
					_, _ = io.Copy(io.Discard, conn)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			opts := QueryOptions{HandshakeTimeout: 10 * time.Second}
			switch mode {
			case "smtp":
				opts.StartTLS = mode
			case "proxy":
				opts.Proxy = "http://" + listener.Addr().String()
			}
			result := make(chan error, 1)
			go func() {
				_, err := QueryContext(ctx, listener.Addr().String(), opts)
				result <- err
			}()
			select {
			case <-accepted:
			case <-time.After(3 * time.Second):
				t.Fatal("connection was not established")
			}
			cancel()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("canceled query succeeded")
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not interrupt handshake")
			}
			<-done
		})
	}
}

func TestMalformedStartTLSReplies(t *testing.T) {
	for _, tt := range []struct{ protocol, greeting, response string }{
		{"smtp", "220evil\r\n", ""},
		{"smtp", strings.Repeat("x", 64*1024), ""},
		{"imap", "* BYE disconnected\r\n", ""},
		{"imap", "* OK ready\r\n", "a001 OKAY not success\r\n"},
		{"pop3", "+OKAY ready\r\n", ""},
		{"pop3", "+OK ready\r\n", "+OKAY not success\r\n"},
		{"ldap", "", "\x30\x0c\x02\x01\x02\x78\x07\x0a\x01\x00\x04\x00\x04\x00"},
		{"ldap", "", "\x30\x0c\x02\x01\x01\x78\x07\x0a\x01\x01\x04\x00\x04\x00"},
	} {
		t.Run(tt.protocol+tt.greeting[:min(8, len(tt.greeting))], func(t *testing.T) {
			server, client := net.Pipe()
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(time.Second))
			go func() {
				defer server.Close()
				if tt.greeting != "" {
					_, _ = io.WriteString(server, tt.greeting)
				}
				if tt.response != "" {
					buf := make([]byte, 512)
					_, _ = server.Read(buf)
					_, _ = io.WriteString(server, tt.response)
				}
			}()
			if err := negotiateStartTLS(client, tt.protocol); err == nil {
				t.Fatal("accepted malformed reply")
			}
		})
	}
}

func TestProtocolLineLimit(t *testing.T) {
	r := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 64*1024)+"\n"), 64*1024)
	if _, err := readProtocolLine(r); err == nil {
		t.Fatal("accepted oversized response")
	}
	if _, err := ParseALPNProtocols(strings.Repeat("x", 256)); err == nil {
		t.Fatal("accepted oversized ALPN protocol")
	}
}

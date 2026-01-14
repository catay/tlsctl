package tlsquery

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestQuery_ValidEndpoint(t *testing.T) {
	server, addr := startTestTLSServer(t, false)
	defer server.Close()

	oldConfig := TLSConfig
	TLSConfig = &tls.Config{InsecureSkipVerify: true}
	defer func() { TLSConfig = oldConfig }()

	chain, err := Query(addr)
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if len(chain.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}

	leaf := chain.Certificates[0]
	if leaf.CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", leaf.CommonName)
	}
	if leaf.Type != "leaf" {
		t.Errorf("expected type 'leaf', got %q", leaf.Type)
	}
	if len(leaf.SubjectAltNames) != 2 {
		t.Errorf("expected 2 SANs, got %d", len(leaf.SubjectAltNames))
	}
}

func TestQuery_InvalidEndpoint(t *testing.T) {
	_, err := Query("invalid:99999")
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestQuery_ConnectionRefused(t *testing.T) {
	_, err := Query("127.0.0.1:1")
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestCertType(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		isCA     bool
		selfSign bool
		want     string
	}{
		{"leaf certificate", 0, false, false, "leaf"},
		{"intermediate CA", 1, true, false, "intermediate"},
		{"root CA", 1, true, true, "root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := &x509.Certificate{
				IsCA: tt.isCA,
				Subject: pkix.Name{
					CommonName: "Test",
				},
			}
			if tt.selfSign {
				cert.Issuer = cert.Subject
			} else {
				cert.Issuer = pkix.Name{CommonName: "Other"}
			}

			got := certType(tt.index, cert)
			if got != tt.want {
				t.Errorf("certType() = %q, want %q", got, tt.want)
			}
		})
	}
}

func startTestTLSServer(t *testing.T, clientAuth bool) (net.Listener, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		Issuer: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"test.example.com", "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.Handshake()
			conn.Close()
		}
	}()

	return listener, listener.Addr().String()
}

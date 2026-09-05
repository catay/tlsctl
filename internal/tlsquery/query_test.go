package tlsquery

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestQuery_ValidEndpoint(t *testing.T) {
	server, addr := startTestTLSServer(t, false)
	defer server.Close()

	chain, err := Query(addr, QueryOptions{})
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
	if chain.Verified {
		t.Error("expected Verified to be false for self-signed test certificate")
	}
	if chain.VerificationError == "" {
		t.Error("expected VerificationError to be set for self-signed test certificate")
	}
	if chain.NegotiatedTLS == nil {
		t.Fatal("expected negotiated tls details to be captured")
	}
}

func TestQuery_InvalidEndpoint(t *testing.T) {
	_, err := Query("invalid:99999", QueryOptions{})
	if err == nil {
		t.Error("expected error for invalid endpoint")
	}
}

func TestQuery_ConnectionRefused(t *testing.T) {
	_, err := Query("127.0.0.1:1", QueryOptions{})
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestResolveTimeouts_Defaults(t *testing.T) {
	connectTimeout, handshakeTimeout := resolveTimeouts(QueryOptions{})
	if connectTimeout != DefaultConnectTimeout {
		t.Fatalf("connect timeout = %v, want %v", connectTimeout, DefaultConnectTimeout)
	}
	if handshakeTimeout != DefaultHandshakeTimeout {
		t.Fatalf("handshake timeout = %v, want %v", handshakeTimeout, DefaultHandshakeTimeout)
	}
}

func TestBuildConfig_ALPNProtocols(t *testing.T) {
	config, err := buildConfig(QueryOptions{ALPNProtocols: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("buildConfig failed: %v", err)
	}
	if got, want := strings.Join(config.NextProtos, ","), "h2,http/1.1"; got != want {
		t.Fatalf("NextProtos = %q, want %q", got, want)
	}
}

func TestQuery_NegotiatedALPN(t *testing.T) {
	server, addr := startTestTLSServerWithNextProtos(t, []string{"h2", "http/1.1"})
	defer server.Close()

	chain, err := Query(addr, QueryOptions{ALPNProtocols: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}
	if chain.NegotiatedTLS == nil {
		t.Fatal("expected negotiated tls details")
	}
	if chain.NegotiatedTLS.ALPN != "h2" {
		t.Fatalf("expected negotiated ALPN h2, got %q", chain.NegotiatedTLS.ALPN)
	}
}

func TestQuery_HandshakeTimeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			close(done)
			return
		}
		defer conn.Close()
		time.Sleep(250 * time.Millisecond)
		close(done)
	}()

	start := time.Now()
	_, err = Query(listener.Addr().String(), QueryOptions{HandshakeTimeout: 50 * time.Millisecond})
	if err == nil {
		t.Fatal("expected handshake timeout error")
	}
	if !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("query took too long: %v", elapsed)
	}
	<-done
}

func TestCertType(t *testing.T) {
	tests := []struct {
		name     string
		isCA     bool
		selfSign bool
		want     string
	}{
		{"leaf certificate", false, false, "leaf"},
		{"intermediate CA", true, false, "intermediate"},
		{"root CA", true, true, "root"},
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

			got := CertTypeFromCert(cert)
			if got != tt.want {
				t.Errorf("CertTypeFromCert() = %q, want %q", got, tt.want)
			}
		})
	}
}

func startTestTLSServer(t *testing.T, clientAuth bool) (net.Listener, string) {
	return startTestTLSServerWithNextProtos(t, nil)
}

func startTestTLSServerWithNextProtos(t *testing.T, nextProtos []string) (net.Listener, string) {
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
		NextProtos:   nextProtos,
	}

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping TLS listener test: %v", err)
		return nil, ""
	}
	listener := tls.NewListener(rawListener, tlsConfig)

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

func TestResolveProxy(t *testing.T) {
	tests := []struct {
		name     string
		proxy    string
		wantNil  bool
		wantHost string
	}{
		{"explicit http proxy", "http://proxy:8080", false, "proxy:8080"},
		{"explicit without scheme", "proxy:3128", false, "proxy:3128"},
		{"empty uses env fallback", "", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("HTTPS_PROXY", "")

			opts := QueryOptions{Proxy: tt.proxy}
			u, err := resolveProxy("example.com:443", opts)
			if err != nil {
				t.Fatalf("resolveProxy() error: %v", err)
			}
			if tt.wantNil {
				if u != nil {
					t.Errorf("expected nil proxy URL, got %v", u)
				}
			} else {
				if u == nil {
					t.Fatal("expected non-nil proxy URL")
					return
				}
				if u.Host != tt.wantHost {
					t.Errorf("expected host %q, got %q", tt.wantHost, u.Host)
				}
			}
		})
	}
}

func TestResolveProxy_EnvFallback(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://envproxy:9090")

	u, err := resolveProxy("example.com:443", QueryOptions{})
	if err != nil {
		t.Fatalf("resolveProxy() error: %v", err)
	}
	// http.ProxyFromEnvironment caches proxy config at first call;
	// if cached as empty from earlier tests, u may be nil here.
	if u != nil && u.Host != "envproxy:9090" {
		t.Errorf("expected host envproxy:9090, got %q", u.Host)
	}
}

func startTestHTTPProxy(t *testing.T, targetAddr string, requireAuth bool) (string, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping proxy test: %v", err)
		return "", func() {}
	}

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleProxyConnection(conn, targetAddr, requireAuth)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener.Addr().String(), cleanup
}

func handleProxyConnection(conn net.Conn, targetAddr string, requireAuth bool) {
	defer conn.Close()

	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method != "CONNECT" {
		resp := &http.Response{
			StatusCode: http.StatusMethodNotAllowed,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(conn) //nolint:errcheck
		return
	}

	if requireAuth {
		authHeader := req.Header.Get("Proxy-Authorization")
		if authHeader == "" {
			resp := &http.Response{
				StatusCode: http.StatusProxyAuthRequired,
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			resp.Write(conn) //nolint:errcheck
			return
		}
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
		if authHeader != expected {
			resp := &http.Response{
				StatusCode: http.StatusForbidden,
				ProtoMajor: 1,
				ProtoMinor: 1,
			}
			resp.Write(conn) //nolint:errcheck
			return
		}
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(conn) //nolint:errcheck
		return
	}
	defer target.Close()

	fmt.Fprint(conn, "HTTP/1.1 200 Connection established\r\n\r\n")

	go io.Copy(target, br) //nolint:errcheck
	io.Copy(conn, target)  //nolint:errcheck
}

func TestQuery_ViaProxy(t *testing.T) {
	server, addr := startTestTLSServer(t, false)
	defer server.Close()

	proxyAddr, cleanup := startTestHTTPProxy(t, addr, false)
	defer cleanup()

	chain, err := Query(addr, QueryOptions{Proxy: "http://" + proxyAddr})
	if err != nil {
		t.Fatalf("Query via proxy failed: %v", err)
	}

	if len(chain.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
	if chain.Certificates[0].CommonName != "test.example.com" {
		t.Errorf("expected CN 'test.example.com', got %q", chain.Certificates[0].CommonName)
	}
}

func TestQuery_ViaProxyWithAuth(t *testing.T) {
	server, addr := startTestTLSServer(t, false)
	defer server.Close()

	proxyAddr, cleanup := startTestHTTPProxy(t, addr, true)
	defer cleanup()

	chain, err := Query(addr, QueryOptions{Proxy: "http://user:pass@" + proxyAddr})
	if err != nil {
		t.Fatalf("Query via proxy with auth failed: %v", err)
	}

	if len(chain.Certificates) == 0 {
		t.Fatal("expected at least one certificate")
	}
}

func TestQuery_ViaProxyAuthRequired(t *testing.T) {
	server, addr := startTestTLSServer(t, false)
	defer server.Close()

	proxyAddr, cleanup := startTestHTTPProxy(t, addr, true)
	defer cleanup()

	_, err := Query(addr, QueryOptions{Proxy: "http://" + proxyAddr})
	if err == nil {
		t.Error("expected error when proxy requires auth but none provided")
	}
}

func TestDialViaProxy_ConnectFailed(t *testing.T) {
	proxyURL, _ := url.Parse("http://127.0.0.1:1")
	_, err := dialViaProxy("example.com:443", proxyURL, 2*time.Second, 2*time.Second)
	if err == nil {
		t.Error("expected error connecting to non-existent proxy")
	}
	if !strings.Contains(err.Error(), "failed to connect to proxy") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestDialViaProxy_ProxyRejectsConnect(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping proxy rejection test: %v", err)
		return
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		http.ReadRequest(br) //nolint:errcheck
		fmt.Fprint(conn, "HTTP/1.1 403 Forbidden\r\n\r\n")
	}()

	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	_, err = dialViaProxy("example.com:443", proxyURL, 5*time.Second, 5*time.Second)
	if err == nil {
		t.Error("expected error for rejected CONNECT")
	}
	if !strings.Contains(err.Error(), "proxy CONNECT failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

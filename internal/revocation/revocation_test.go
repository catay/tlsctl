package revocation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	return cert, key
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, crlDPs []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		CRLDistributionPoints: crlDPs,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	return cert, key
}

func serveCRL(t *testing.T, crlBytes []byte) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping CRL test: failed to listen on localhost: %v", err)
		return nil
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write(crlBytes)
	}))
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func createCRL(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, revoked []x509.RevocationListEntry, nextUpdate time.Time) []byte {
	t.Helper()

	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: revoked,
	}

	crlBytes, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("create CRL: %v", err)
	}

	return crlBytes
}

func newLeafWithOCSP(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ocspServers []string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		OCSPServer:   ocspServers,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}

	return cert, key
}

func createOCSPResponse(t *testing.T, leaf, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, tmpl ocsp.Response) []byte {
	t.Helper()

	der, err := ocsp.CreateResponse(issuer, issuer, tmpl, issuerKey)
	if err != nil {
		t.Fatalf("create OCSP response: %v", err)
	}

	return der
}

func serveOCSP(t *testing.T, respBytes []byte) *httptest.Server {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping OCSP test: failed to listen on localhost: %v", err)
		return nil
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(respBytes)
	}))
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckCRL_NotRevoked(t *testing.T) {
	ca, caKey := newCA(t)
	crlBytes := createCRL(t, ca, caKey, nil, time.Now().Add(24*time.Hour))
	srv := serveCRL(t, crlBytes)

	leaf, _ := newLeaf(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodCRL}, SoftFail: true})

	if info.OverallStatus != StatusGood {
		t.Errorf("expected overall status %q, got %q", StatusGood, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusGood {
		t.Errorf("expected result status %q, got %q", StatusGood, info.Results[0].Status)
	}
}

func TestCheckCRL_Revoked(t *testing.T) {
	ca, caKey := newCA(t)

	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	revoked := []x509.RevocationListEntry{
		{
			SerialNumber:   big.NewInt(42),
			RevocationTime: revokedAt,
			ReasonCode:     1,
		},
	}
	crlBytes := createCRL(t, ca, caKey, revoked, time.Now().Add(24*time.Hour))
	srv := serveCRL(t, crlBytes)

	leaf, _ := newLeaf(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodCRL}, SoftFail: true})

	if info.OverallStatus != StatusRevoked {
		t.Errorf("expected overall status %q, got %q", StatusRevoked, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	r := info.Results[0]
	if r.Status != StatusRevoked {
		t.Errorf("expected result status %q, got %q", StatusRevoked, r.Status)
	}
	if r.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if r.Reason != "key compromise" {
		t.Errorf("expected reason %q, got %q", "key compromise", r.Reason)
	}
}

func TestCheckCRL_NoCRLDistributionPoints(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeaf(t, ca, caKey, nil)

	checker := NewChecker(http.DefaultClient, time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodCRL}, SoftFail: true})

	if info.OverallStatus != StatusNotSupported {
		t.Errorf("expected overall status %q, got %q", StatusNotSupported, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusNotSupported {
		t.Errorf("expected result status %q, got %q", StatusNotSupported, info.Results[0].Status)
	}
}

func TestCheckCRL_FetchError(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeaf(t, ca, caKey, []string{"http://127.0.0.1:1/crl"})

	checker := NewChecker(http.DefaultClient, time.Now)
	info := checker.CheckCert(leaf, ca, Options{
		Methods:  []Method{MethodCRL},
		SoftFail: true,
		Timeout:  500 * time.Millisecond,
	})

	if info.OverallStatus != StatusUnknown {
		t.Errorf("expected overall status %q, got %q", StatusUnknown, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusError {
		t.Errorf("expected result status %q, got %q", StatusError, info.Results[0].Status)
	}
	if info.Results[0].Error == "" {
		t.Error("expected error message to be set")
	}
}

func TestCheckCRL_StaleCRL(t *testing.T) {
	ca, caKey := newCA(t)
	staleNextUpdate := time.Now().Add(-time.Hour)
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: staleNextUpdate.Add(-time.Hour),
		NextUpdate: staleNextUpdate,
	}
	crlBytes, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		t.Fatalf("create stale CRL: %v", err)
	}
	srv := serveCRL(t, crlBytes)

	leaf, _ := newLeaf(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{
		Methods:  []Method{MethodCRL},
		SoftFail: true,
	})

	if info.OverallStatus != StatusUnknown {
		t.Errorf("expected overall status %q, got %q", StatusUnknown, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	r := info.Results[0]
	if r.Status != StatusUnknown {
		t.Errorf("expected result status %q, got %q", StatusUnknown, r.Status)
	}
	if r.Error != "stale CRL: past NextUpdate time" {
		t.Errorf("expected stale error, got %q", r.Error)
	}
}

func TestComputeOverallStatus(t *testing.T) {
	tests := []struct {
		name     string
		results  []Result
		expected Status
	}{
		{
			name:     "no results",
			results:  nil,
			expected: StatusNotChecked,
		},
		{
			name:     "single good",
			results:  []Result{{Status: StatusGood}},
			expected: StatusGood,
		},
		{
			name:     "single revoked",
			results:  []Result{{Status: StatusRevoked}},
			expected: StatusRevoked,
		},
		{
			name:     "single error",
			results:  []Result{{Status: StatusError}},
			expected: StatusError,
		},
		{
			name:     "single unknown",
			results:  []Result{{Status: StatusUnknown}},
			expected: StatusUnknown,
		},
		{
			name:     "single not_checked",
			results:  []Result{{Status: StatusNotChecked}},
			expected: StatusUnknown,
		},
		{
			name:     "single not_supported",
			results:  []Result{{Status: StatusNotSupported}},
			expected: StatusNotSupported,
		},
		{
			name: "revoked takes precedence over good",
			results: []Result{
				{Status: StatusGood},
				{Status: StatusRevoked},
			},
			expected: StatusRevoked,
		},
		{
			name: "good takes precedence over error",
			results: []Result{
				{Status: StatusError},
				{Status: StatusGood},
			},
			expected: StatusGood,
		},
		{
			name: "error takes precedence over unknown",
			results: []Result{
				{Status: StatusUnknown},
				{Status: StatusError},
			},
			expected: StatusError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeOverallStatus(tt.results)
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestCheckOCSP_NotRevoked(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, []string{"http://placeholder"})

	respBytes := createOCSPResponse(t, leaf, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(24 * time.Hour),
	})
	srv := serveOCSP(t, respBytes)

	leaf, _ = newLeafWithOCSP(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodOCSP}, SoftFail: true})

	if info.OverallStatus != StatusGood {
		t.Errorf("expected overall status %q, got %q", StatusGood, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusGood {
		t.Errorf("expected result status %q, got %q", StatusGood, info.Results[0].Status)
	}
}

func TestCheckOCSP_Revoked(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, []string{"http://placeholder"})

	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	respBytes := createOCSPResponse(t, leaf, ca, caKey, ocsp.Response{
		SerialNumber:     leaf.SerialNumber,
		Status:           ocsp.Revoked,
		ThisUpdate:       time.Now().Add(-time.Hour),
		NextUpdate:       time.Now().Add(24 * time.Hour),
		RevokedAt:        revokedAt,
		RevocationReason: 1,
	})
	srv := serveOCSP(t, respBytes)

	leaf, _ = newLeafWithOCSP(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodOCSP}, SoftFail: true})

	if info.OverallStatus != StatusRevoked {
		t.Errorf("expected overall status %q, got %q", StatusRevoked, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	r := info.Results[0]
	if r.Status != StatusRevoked {
		t.Errorf("expected result status %q, got %q", StatusRevoked, r.Status)
	}
	if r.RevokedAt == nil {
		t.Error("expected RevokedAt to be set")
	}
	if r.Reason != "key compromise" {
		t.Errorf("expected reason %q, got %q", "key compromise", r.Reason)
	}
}

func TestCheckOCSP_NoOCSPServer(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, nil)

	checker := NewChecker(http.DefaultClient, time.Now)
	info := checker.CheckCert(leaf, ca, Options{Methods: []Method{MethodOCSP}, SoftFail: true})

	if info.OverallStatus != StatusNotSupported {
		t.Errorf("expected overall status %q, got %q", StatusNotSupported, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusNotSupported {
		t.Errorf("expected result status %q, got %q", StatusNotSupported, info.Results[0].Status)
	}
}

func TestCheckOCSP_NoIssuer(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, []string{"http://ocsp.example.com"})

	checker := NewChecker(http.DefaultClient, time.Now)
	info := checker.CheckCert(leaf, nil, Options{Methods: []Method{MethodOCSP}, SoftFail: true})

	if info.OverallStatus != StatusUnknown {
		t.Errorf("expected overall status %q, got %q", StatusUnknown, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusNotChecked {
		t.Errorf("expected result status %q, got %q", StatusNotChecked, info.Results[0].Status)
	}
}

func TestCheckOCSP_FetchError(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, []string{"http://127.0.0.1:1/ocsp"})

	checker := NewChecker(http.DefaultClient, time.Now)
	info := checker.CheckCert(leaf, ca, Options{
		Methods:  []Method{MethodOCSP},
		SoftFail: true,
		Timeout:  500 * time.Millisecond,
	})

	if info.OverallStatus != StatusUnknown {
		t.Errorf("expected overall status %q, got %q", StatusUnknown, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	if info.Results[0].Status != StatusError {
		t.Errorf("expected result status %q, got %q", StatusError, info.Results[0].Status)
	}
	if info.Results[0].Error == "" {
		t.Error("expected error message to be set")
	}
}

func TestCheckOCSP_StaleResponse(t *testing.T) {
	ca, caKey := newCA(t)
	leaf, _ := newLeafWithOCSP(t, ca, caKey, []string{"http://placeholder"})

	staleNextUpdate := time.Now().Add(-time.Hour)
	respBytes := createOCSPResponse(t, leaf, ca, caKey, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       ocsp.Good,
		ThisUpdate:   staleNextUpdate.Add(-time.Hour),
		NextUpdate:   staleNextUpdate,
	})
	srv := serveOCSP(t, respBytes)

	leaf, _ = newLeafWithOCSP(t, ca, caKey, []string{srv.URL})

	checker := NewChecker(srv.Client(), time.Now)
	info := checker.CheckCert(leaf, ca, Options{
		Methods:  []Method{MethodOCSP},
		SoftFail: true,
	})

	if info.OverallStatus != StatusUnknown {
		t.Errorf("expected overall status %q, got %q", StatusUnknown, info.OverallStatus)
	}
	if len(info.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(info.Results))
	}
	r := info.Results[0]
	if r.Status != StatusUnknown {
		t.Errorf("expected result status %q, got %q", StatusUnknown, r.Status)
	}
	if r.Error != "stale OCSP response: past NextUpdate time" {
		t.Errorf("expected stale error, got %q", r.Error)
	}
}

func TestFormatRevocationReason(t *testing.T) {
	tests := []struct {
		code     int
		expected string
	}{
		{0, "unspecified"},
		{1, "key compromise"},
		{2, "CA compromise"},
		{3, "affiliation changed"},
		{4, "superseded"},
		{5, "cessation of operation"},
		{6, "certificate hold"},
		{8, "remove from CRL"},
		{9, "privilege withdrawn"},
		{10, "AA compromise"},
		{7, "unknown (7)"},
		{99, "unknown (99)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := formatRevocationReason(tt.code)
			if got != tt.expected {
				t.Errorf("code %d: expected %q, got %q", tt.code, tt.expected, got)
			}
		})
	}
}

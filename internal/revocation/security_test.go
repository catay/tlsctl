package revocation

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestFailurePolicyAndResponderFallback(t *testing.T) {
	ca, key := newCA(t)
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) }))
	defer failed.Close()
	for _, method := range []Method{MethodCRL, MethodOCSP} {
		for _, soft := range []bool{false, true} {
			for _, fallback := range []bool{false, true} {
				leaf, _ := newLeaf(t, ca, key, []string{failed.URL})
				leaf.OCSPServer = []string{failed.URL}
				if fallback {
					if method == MethodCRL {
						good := serveCRL(t, createCRL(t, ca, key, nil, time.Now().Add(time.Hour)))
						leaf.CRLDistributionPoints = append(leaf.CRLDistributionPoints, good.URL)
					} else {
						good := serveOCSP(t, createOCSPResponse(t, leaf, ca, key, ocsp.Response{SerialNumber: leaf.SerialNumber, Status: ocsp.Good, ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour)}))
						leaf.OCSPServer = append(leaf.OCSPServer, good.URL)
					}
				}
				got := NewChecker(nil, nil).CheckCert(leaf, ca, Options{Methods: []Method{method}, SoftFail: soft})
				want := StatusError
				if soft {
					want = StatusUnknown
				}
				if fallback {
					want = StatusGood
				}
				if got.OverallStatus != want {
					t.Fatalf("%s soft=%t fallback=%t: %+v", method, soft, fallback, got)
				}
				if len(got.Results) == 0 || got.Results[0].Error == "" {
					t.Fatal("failed responder diagnostics were lost")
				}
				if fallback && len(got.Results) != 2 {
					t.Fatal("fallback responder was not recorded")
				}
			}
		}
	}
}

func TestRevocationRequiresIssuer(t *testing.T) {
	ca, key := newCA(t)
	wrong, _ := newCA(t)
	leaf, _ := newLeaf(t, ca, key, []string{"http://unused.invalid"})
	leaf.OCSPServer = []string{"http://unused.invalid"}
	for _, method := range []Method{MethodCRL, MethodOCSP} {
		for _, issuer := range []*x509.Certificate{nil, wrong} {
			got := NewChecker(nil, nil).CheckCert(leaf, issuer, Options{Methods: []Method{method}, SoftFail: true})
			if got.OverallStatus == StatusGood || got.Results[0].Status != StatusNotChecked {
				t.Fatalf("accepted missing/wrong issuer: %+v", got)
			}
		}
	}
}

func TestCRLRejectsWrongSignature(t *testing.T) {
	ca, key := newCA(t)
	wrong, wrongKey := newCA(t)
	server := serveCRL(t, createCRL(t, wrong, wrongKey, nil, time.Now().Add(time.Hour)))
	leaf, _ := newLeaf(t, ca, key, []string{server.URL})
	got := NewChecker(nil, nil).CheckCert(leaf, ca, Options{Methods: []Method{MethodCRL}})
	if got.OverallStatus != StatusError || got.Results[0].Error == "" {
		t.Fatalf("accepted wrong CRL signature: %+v", got)
	}
}

func TestResponseFreshness(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name         string
		issued, next time.Time
		bad          bool
	}{
		{"fresh", now.Add(-time.Hour), now.Add(time.Hour), false},
		{"future", now.Add(6 * time.Minute), now.Add(time.Hour), true},
		{"clock skew", now.Add(time.Minute), now.Add(time.Hour), false},
		{"stale", now.Add(-time.Hour), now.Add(-time.Minute), true},
		{"expiry boundary", now.Add(-time.Hour), now, true},
		{"missing thisUpdate", time.Time{}, now.Add(time.Hour), true},
		{"inverted", now, now.Add(-time.Hour), true},
		{"without nextUpdate", now.Add(-time.Hour), time.Time{}, false},
		{"old without nextUpdate", now.Add(-25 * time.Hour), time.Time{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkFreshness(tc.issued, tc.next, now, "response"); (err != nil) != tc.bad {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestDelegatedOCSPAuthorization(t *testing.T) {
	ca, caKey := newCA(t)
	for _, tc := range []struct {
		name    string
		eku     []x509.ExtKeyUsage
		expired bool
		want    Status
	}{
		{"authorized", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, false, StatusGood},
		{"server cert", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, false, StatusError},
		{"missing EKU", nil, false, StatusError},
		{"expired responder", []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, true, StatusError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			until := now.Add(time.Hour)
			if tc.expired {
				until = now.Add(-time.Minute)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "responder"},
				NotBefore: now.Add(-time.Hour), NotAfter: until, ExtKeyUsage: tc.eku, KeyUsage: x509.KeyUsageDigitalSignature}
			der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
			if err != nil {
				t.Fatal(err)
			}
			responder, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			leaf, _ := newLeaf(t, ca, caKey, nil)
			response, err := ocsp.CreateResponse(ca, responder, ocsp.Response{SerialNumber: leaf.SerialNumber,
				Status: ocsp.Good, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), Certificate: responder}, key)
			if err != nil {
				t.Fatal(err)
			}
			server := serveOCSP(t, response)
			leaf.OCSPServer = []string{server.URL}
			got := NewChecker(nil, nil).CheckCert(leaf, ca, Options{Methods: []Method{MethodOCSP}})
			if got.OverallStatus != tc.want {
				t.Fatalf("got %+v want %s", got, tc.want)
			}
		})
	}
}

func TestRevocationCancellation(t *testing.T) {
	ca, key := newCA(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	leaf, _ := newLeaf(t, ca, key, []string{server.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	got := NewChecker(nil, nil).CheckCert(leaf, ca, Options{Context: ctx, Timeout: time.Second})
	if got.OverallStatus != StatusError || time.Since(start) > time.Second {
		t.Fatalf("cancellation failed: %+v", got)
	}
}

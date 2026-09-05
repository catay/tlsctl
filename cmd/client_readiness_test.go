package cmd

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

func TestBatchConcurrencyOrderingAndDeadline(t *testing.T) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	opts := tlsquery.QueryOptions{RootCAs: roots}
	targets := []string{s.Listener.Addr().String(), "127.0.0.1:1", s.Listener.Addr().String(), s.Listener.Addr().String()}
	var active, peak atomic.Int32
	revoke := func(ctx context.Context, _ *tlsquery.ChainInfo) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
	results := queryTargets(context.Background(), targets, opts, 2, time.Second, revoke)
	if peak.Load() != 2 {
		t.Fatalf("peak concurrency=%d, want 2", peak.Load())
	}
	for i, result := range results {
		if result.endpoint != targets[i] || (result.err != nil) != (i == 1) {
			t.Fatalf("result %d: %+v", i, result)
		}
	}
	results = queryTargets(context.Background(), targets[:1], opts, 1, 50*time.Millisecond,
		func(ctx context.Context, _ *tlsquery.ChainInfo) { <-ctx.Done() })
	if results[0].err == nil {
		t.Fatal("revocation exceeded the overall deadline without failing")
	}
}

func BenchmarkBatchConcurrency(b *testing.B) {
	s := httptest.NewTLSServer(http.NotFoundHandler())
	defer s.Close()
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	targets := make([]string, 32)
	for i := range targets {
		targets[i] = s.Listener.Addr().String()
	}
	for _, concurrency := range []int{1, 8} {
		b.Run(fmt.Sprint(concurrency), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				results := queryTargets(context.Background(), targets, tlsquery.QueryOptions{RootCAs: roots}, concurrency, time.Second,
					func(context.Context, *tlsquery.ChainInfo) { time.Sleep(5 * time.Millisecond) })
				for _, result := range results {
					if result.err != nil {
						b.Fatal(result.err)
					}
				}
			}
		})
	}
}

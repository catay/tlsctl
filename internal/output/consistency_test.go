package output

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/catay/tlsctl/v2/internal/revocation"
)

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestRenderWriteErrors(t *testing.T) {
	errFull := errors.New("disk full")
	for _, format := range []Format{FormatHuman, FormatText, FormatRaw, FormatJSON, FormatYAML, FormatCSV, FormatCSVFull} {
		t.Run(string(format), func(t *testing.T) {
			r, err := New(format)
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Render(failingWriter{errFull}, testChain(), Options{Now: fixedNow}); err == nil || !strings.Contains(err.Error(), errFull.Error()) {
				t.Fatalf("lost write error: %v", err)
			}
		})
	}
	if err := (RawPEMRenderer{}).Render(shortWriter{}, testChain(), Options{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write: %v", err)
	}
}

func TestHumanAndStructuredHealthAgree(t *testing.T) {
	for _, tc := range []struct {
		rev  revocation.Status
		want string
	}{
		{revocation.StatusGood, "secure"}, {revocation.StatusRevoked, "insecure"},
		{revocation.StatusError, "revocation_error"}, {revocation.StatusUnknown, "secure"},
	} {
		t.Run(string(tc.rev), func(t *testing.T) {
			chain := testChain()
			chain.Verified = true
			chain.Certificates[0].Revocation = &revocation.Info{OverallStatus: tc.rev}
			result := TargetResult{Result: chain}
			if got := result.TLSStatus(Options{Now: fixedNow}); string(got) != tc.want {
				t.Fatalf("status=%s", got)
			}
			var buf bytes.Buffer
			if err := (HumanRenderer{}).Render(&buf, chain, Options{Now: fixedNow}); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(buf.String(), "("+tc.want+",") {
				t.Fatalf("contradictory status: %s", buf.String())
			}
			if tc.rev == revocation.StatusUnknown && !strings.Contains(buf.String(), "unknown") {
				t.Fatal("revocation uncertainty is missing")
			}
		})
	}
}

func TestExpiryBoundary(t *testing.T) {
	for _, tc := range []struct {
		remaining time.Duration
		want      TLSStatus
	}{
		{30*24*time.Hour + time.Second, TLSStatusSecure}, {30 * 24 * time.Hour, TLSStatusExpiring},
		{time.Second, TLSStatusExpiring}, {-time.Second, TLSStatusInsecure},
	} {
		chain := testChain()
		chain.Verified = true
		chain.Certificates[0].NotAfter = fixedNow().Add(tc.remaining).Format(time.RFC3339)
		if got := (TargetResult{Result: chain}).TLSStatus(Options{Now: fixedNow}); got != tc.want {
			t.Fatalf("%s: got %s want %s", tc.remaining, got, tc.want)
		}
	}
}

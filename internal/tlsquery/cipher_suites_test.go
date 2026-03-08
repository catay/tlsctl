package tlsquery

import (
	"crypto/tls"
	"testing"
)

func TestIsCipherSuiteSecure(t *testing.T) {
	secureSuites := tls.CipherSuites()
	if len(secureSuites) == 0 {
		t.Fatal("expected at least one secure cipher suite")
	}

	insecureSuites := tls.InsecureCipherSuites()
	if len(insecureSuites) == 0 {
		t.Fatal("expected at least one insecure cipher suite")
	}

	if !IsCipherSuiteSecure(secureSuites[0].Name) {
		t.Fatalf("expected %q to be secure", secureSuites[0].Name)
	}

	if IsCipherSuiteSecure(insecureSuites[0].Name) {
		t.Fatalf("expected %q to be insecure", insecureSuites[0].Name)
	}

	if IsCipherSuiteSecure("TLS_FAKE_UNKNOWN_CIPHER") {
		t.Fatal("expected unknown cipher suite to be treated as insecure")
	}
}

func TestSplitCipherSuitesBySecurity(t *testing.T) {
	secureSuites := tls.CipherSuites()
	if len(secureSuites) < 2 {
		t.Fatal("expected at least two secure cipher suites")
	}

	insecureSuites := tls.InsecureCipherSuites()
	if len(insecureSuites) == 0 {
		t.Fatal("expected at least one insecure cipher suite")
	}

	input := []string{
		insecureSuites[0].Name,
		secureSuites[0].Name,
		"TLS_FAKE_UNKNOWN_CIPHER",
		secureSuites[1].Name,
	}

	secure, insecure := SplitCipherSuitesBySecurity(input)

	if len(secure) != 2 {
		t.Fatalf("expected 2 secure cipher suites, got %d", len(secure))
	}
	if secure[0] != secureSuites[0].Name || secure[1] != secureSuites[1].Name {
		t.Fatalf("unexpected secure ciphers: %#v", secure)
	}

	if len(insecure) != 2 {
		t.Fatalf("expected 2 insecure cipher suites, got %d", len(insecure))
	}
	if insecure[0] != insecureSuites[0].Name || insecure[1] != "TLS_FAKE_UNKNOWN_CIPHER" {
		t.Fatalf("unexpected insecure ciphers: %#v", insecure)
	}
}

package tlsquery

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCertPEM = `-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUeOm+K0swTFTmW3SlcuomhTHmSIcwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIdGVzdGxlYWYwHhcNMjYwMTIxMjI1ODQzWhcNMjYwMTIy
MjI1ODQzWjATMREwDwYDVQQDDAh0ZXN0bGVhZjCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOPUlhdyTWl1XDUmNjt86WHMU51g0ubTqAMIH2OcP/FmUaH3
BKMh6YtpKw5i3CvNbI+fMkPCIWzbidwYzIgTUjxYUQxVxqBYMbfDWwUJSqdIFexN
B5c7fLRrBpy78nRcWbK7pJpJr5fz+SctmUJ2sZEXV8MzivRiOcm1AsJuR9b01ETy
9hGSOT8UOEwQmas27A5wL0/ly3/9+gsmeFCNTC6DBa1eK1TYucqPEt8yNDX7yQOx
yw59mnDnOxHKyguPLH1IN94uFwJWwxL6YvTo7+juF2RbojC9D2e12aGkfyONv2dc
FwwJghY5+dTMp2ROFgiCKBTu1xSVSWs2i8MAdPkCAwEAAaNrMGkwHQYDVR0OBBYE
FALjqL2SFlGX5pn4PW7FdGOJOipzMB8GA1UdIwQYMBaAFALjqL2SFlGX5pn4PW7F
dGOJOipzMA8GA1UdEwEB/wQFMAMBAf8wFgYDVR0RBA8wDYILZXhhbXBsZS5jb20w
DQYJKoZIhvcNAQELBQADggEBAGHD6PZyWAygSS7jg2nTYUCIBt8VxCT2RV13pj9k
gduZocmzbIM12b0lJVpL8e0qohD6LeeBLATANoSDME9B0RWUZnphDbVCIEJxHd77
JsaLs8v1i/mUBwtnYMwYW9cv01xq6gfCg2VWYnB6rIbACLr/NcoSzIlrHjuyIM18
5Olx9Mj3xKyoMpGVKvcj47lbddQbWetLETpRUkXYCcma6+wAtb7ss5oPPuxbtTIU
rjqULqhTIZDphvDoNCm0GbmdrOo7WGgnGiAImdwk1GNo1Hgexa2rba/7rH1MzI9C
Bw6sq9aRI8sU3PPRS0Jgom9ct6ihMv+J6LIblNCEf1Vms0Q=
-----END CERTIFICATE-----`

const testCACertPEM = `-----BEGIN CERTIFICATE-----
MIIDAzCCAeugAwIBAgIUO27sC4tdHkK+8SKrauJB3DY9zUkwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGdGVzdGNhMB4XDTI2MDEyMTIyNTgzOFoXDTI2MDEyMjIy
NTgzOFowETEPMA0GA1UEAwwGdGVzdGNhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAyixoy2On8eH7ASJoKeRiVXYZf5C9xjUdH8/qjxmHmbsaoWEuMOln
5qFyTMIyu3fXrslmPog8zaePLo8BF8JahlmenDOu7q9zGB5MW2g2pwNwAFQuf+NW
5AT91TnUlPoDFLEQjEgdBFoCmzr0S/9y3h2UK0H43Uo6jTDNCy7RsXlJgw70l+sa
wcckTjrwTzaTrZeXqNqwQ8rj6qpjhyLS+ztrOE8mwSYBsjB0xyqWc5i2cLnnNuf3
01DxPJ9nXtuAbnIrPfKNC4JhikjNhb/7mL1gq4pW094kAoqNi0rSJKzcCW7COnwR
vB1kairsO/KgQTHzwsOm9uYzboLnusg3LQIDAQABo1MwUTAdBgNVHQ4EFgQUQ2PX
OOp4MpPM2FSltb53WAQ3EUAwHwYDVR0jBBgwFoAUQ2PXOOp4MpPM2FSltb53WAQ3
EUAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAG0zgGaCytMuZ
ba5U3VyS+sC5cPu8YDslEDaa1MB29/38euD5FqBOY4fLJFpVboz+v9p5S8eLG1S+
haYRWxjmyTWpJCeB0EdfUe/Tk3nMCK22A9pbmFKikQesZRWXRu2qz44gQO1cqpp7
mML6lNa39Wo308dWFSgiUmSoEFEFENnrLRFs/JsGf04GTZ+QmvHTQwVoe3sKEHl6
vR2eTpQ0LX/DlH2ddllcUcinnQFWc2ER43YMcPXjOgK1vYv/I71Hd6uX2FNNoQju
BumTOpU6ssVGH4yAV7KASvvOG7XDh/8hHbZNvgb1JSPSW3IGGY4jRqGpsPghak+j
A9Ga5cgZIQ==
-----END CERTIFICATE-----`

func TestParsePEM(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantCount int
		wantError bool
		errorMsg  string
	}{
		{
			name:      "single leaf certificate",
			data:      testCertPEM,
			wantCount: 1,
		},
		{
			name:      "single CA certificate",
			data:      testCACertPEM,
			wantCount: 1,
		},
		{
			name:      "multiple certificates",
			data:      testCertPEM + "\n" + testCACertPEM,
			wantCount: 2,
		},
		{
			name:      "empty data",
			data:      "",
			wantError: true,
			errorMsg:  "no certificates found",
		},
		{
			name:      "no certificate blocks",
			data:      "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
			wantError: true,
			errorMsg:  "no certificates found",
		},
		{
			name:      "invalid certificate data",
			data:      "-----BEGIN CERTIFICATE-----\naW52YWxpZA==\n-----END CERTIFICATE-----",
			wantError: true,
			errorMsg:  "failed to parse certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chain, err := ParsePEM([]byte(tt.data))
			if tt.wantError {
				if err == nil {
					t.Errorf("ParsePEM() expected error, got nil")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("ParsePEM() error = %q, want to contain %q", err.Error(), tt.errorMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ParsePEM() unexpected error: %v", err)
					return
				}
				if len(chain.Certificates) != tt.wantCount {
					t.Errorf("ParsePEM() got %d certificates, want %d", len(chain.Certificates), tt.wantCount)
				}
			}
		})
	}
}

func TestParsePEMFile(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid file with single certificate", func(t *testing.T) {
		path := filepath.Join(tmpDir, "single.pem")
		if err := os.WriteFile(path, []byte(testCertPEM), 0644); err != nil {
			t.Fatal(err)
		}

		chain, err := ParsePEMFile(path)
		if err != nil {
			t.Errorf("ParsePEMFile() unexpected error: %v", err)
			return
		}
		if len(chain.Certificates) != 1 {
			t.Errorf("ParsePEMFile() got %d certificates, want 1", len(chain.Certificates))
		}
		if chain.Certificates[0].CommonName != "testleaf" {
			t.Errorf("ParsePEMFile() CommonName = %q, want %q", chain.Certificates[0].CommonName, "testleaf")
		}
	})

	t.Run("valid file with multiple certificates", func(t *testing.T) {
		path := filepath.Join(tmpDir, "chain.pem")
		data := testCertPEM + "\n" + testCACertPEM
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			t.Fatal(err)
		}

		chain, err := ParsePEMFile(path)
		if err != nil {
			t.Errorf("ParsePEMFile() unexpected error: %v", err)
			return
		}
		if len(chain.Certificates) != 2 {
			t.Errorf("ParsePEMFile() got %d certificates, want 2", len(chain.Certificates))
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := ParsePEMFile(filepath.Join(tmpDir, "nonexistent.pem"))
		if err == nil {
			t.Error("ParsePEMFile() expected error for non-existent file, got nil")
		}
		if !strings.Contains(err.Error(), "failed to read file") {
			t.Errorf("ParsePEMFile() error = %q, want to contain %q", err.Error(), "failed to read file")
		}
	})
}

func TestCertTypeFromCert(t *testing.T) {
	chain, err := ParsePEM([]byte(testCACertPEM))
	if err != nil {
		t.Fatal(err)
	}
	if chain.Certificates[0].Type != "root" {
		t.Errorf("expected root type for self-signed CA, got %q", chain.Certificates[0].Type)
	}
}

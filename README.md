# tlsctl

A command-line tool to query and inspect TLS certificates from remote endpoints or local PEM files.

## Installation

```bash
go build -o tlsctl .
```

## Usage

### Query remote TLS endpoints

```bash
# Human-readable output (port defaults to 443)
tlsctl client google.com

# With explicit port
tlsctl client google.com:8443

# JSON output
tlsctl client -o json example.com

# YAML output
tlsctl client --output yaml example.com
```

### Parse PEM files

```bash
# Parse a single certificate
tlsctl pem cert.pem

# Parse a certificate chain (multiple certs in one file)
tlsctl pem chain.pem

# JSON output
tlsctl pem -o json cert.pem

# YAML output
tlsctl pem --output yaml cert.pem
```

## Output Formats

- `text` (default) - Human-readable output
- `json` - JSON format
- `yaml` - YAML format

## Certificate Fields

The tool extracts and displays:

- **Type**: leaf, intermediate, or root
- **Version**: X.509 certificate version
- **Serial Number**: Certificate serial number (hex formatted)
- **Signature Algorithm**: e.g., SHA256-RSA, ECDSA-SHA256
- **Issuer / Subject**: Distinguished name (DN)
- **Not Before / Not After**: Validity period (RFC3339 format)
- **Public Key Algorithm**: e.g., RSA, ECDSA
- **Key Usage**: Digital Signature, Key Encipherment, Certificate Sign, etc.
- **Extended Key Usage**: TLS Web Server Authentication, Client Authentication, etc.
- **Basic Constraints**: CA flag and path length
- **Subject/Authority Key ID**: Key identifiers (hex formatted)
- **Subject Alt Names**: DNS names
- **Email Addresses / IP Addresses**: Additional identifiers
- **OCSP Servers / CA Issuers / CRL Distribution Points**: Revocation info
- **Fingerprint**: SHA1 and SHA256 fingerprints
- **PEM**: The certificate in PEM format

## Example Output

### Text (default)

```
[LEAF]
Version:               3
Serial Number:         0a:bc:de:...
Signature Algorithm:   SHA256-RSA
Issuer:                CN=WR2,O=Google Trust Services,C=US
Subject:               CN=*.google.com
Not Before:            2025-12-09T17:08:50Z
Not After:             2026-03-03T17:08:49Z
Public Key Algorithm:  ECDSA
Key Usage:             Digital Signature
Extended Key Usage:    TLS Web Server Authentication
Subject Key ID:        AB:CD:EF:...
Authority Key ID:      12:34:56:...
Subject Alt Names:     *.google.com, *.appengine.google.com, ...
OCSP Servers:          http://ocsp.pki.goog/wr2
CA Issuers:            http://pki.goog/repo/certs/wr2.der
PEM:
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----

[INTERMEDIATE]
Version:               3
...
```

### JSON

```json
{
  "certificates": [
    {
      "type": "leaf",
      "version": 3,
      "serial_number": "0a:bc:de:...",
      "signature_algorithm": "SHA256-RSA",
      "issuer": "CN=WR2,O=Google Trust Services,C=US",
      "subject": "CN=*.google.com",
      "common_name": "*.google.com",
      "not_before": "2025-12-09T17:08:50Z",
      "not_after": "2026-03-03T17:08:49Z",
      "public_key_algorithm": "ECDSA",
      "key_usage": ["Digital Signature"],
      "extended_key_usage": ["TLS Web Server Authentication"],
      "subject_key_id": "AB:CD:EF:...",
      "authority_key_id": "12:34:56:...",
      "subject_alternative_names": ["*.google.com", "..."],
      "ocsp_servers": ["http://ocsp.pki.goog/wr2"],
      "issuing_cert_url": ["http://pki.goog/repo/certs/wr2.der"],
      "fingerprint": {
        "sha1": "ab:cd:ef:...",
        "sha256": "12:34:56:..."
      },
      "pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
    }
  ]
}
```

### YAML

```yaml
certificates:
  - type: leaf
    version: 3
    serial_number: "0a:bc:de:..."
    signature_algorithm: SHA256-RSA
    issuer: CN=WR2,O=Google Trust Services,C=US
    subject: CN=*.google.com
    common_name: "*.google.com"
    not_before: "2025-12-09T17:08:50Z"
    not_after: "2026-03-03T17:08:49Z"
    public_key_algorithm: ECDSA
    key_usage:
      - Digital Signature
    extended_key_usage:
      - TLS Web Server Authentication
    subject_alternative_names:
      - "*.google.com"
    fingerprint:
      sha1: "ab:cd:ef:..."
      sha256: "12:34:56:..."
    pem: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

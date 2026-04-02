
[![CI](https://github.com/catay/tlsctl/actions/workflows/ci.yaml/badge.svg)](https://github.com/catay/tlsctl/actions/workflows/ci.yaml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/catay/tlsctl)](https://github.com/catay/tlsctl/blob/main/go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/catay/tlsctl)](https://goreportcard.com/report/github.com/catay/tlsctl)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/catay/tlsctl/blob/main/LICENSE)
[![Release](https://img.shields.io/github/v/release/catay/tlsctl)](https://github.com/catay/tlsctl/releases/latest)

<h1>
<p align="center">
  <img src="images/tlsctl-192x192.png" alt="tlsctl logo" width="192" height="192">
  <br>tlsctl
</p>
</h1>

## Table of Contents

- [About](#about)
- [Why tlsctl?](#why-tlsctl)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Basic usage](#basic-usage)
- [Advanced usage](#advanced-usage)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [Status indicators](#status-indicators)
- [Quiet mode](#quiet-mode)
- [Disabling color](#disabling-color)
- [Configuration file](#configuration-file)
- [Revocation checking](#revocation-checking)
- [Certificate fields](#certificate-fields)
- [Testing with badssl.com](#testing-with-badsslcom)
- [Shell completion](#shell-completion)
- [License](#license)

## About

**tlsctl** is a fast, zero-config command-line tool for inspecting TLS certificates from remote endpoints or local PEM files. Get instant visibility into certificate chains, expiry status, revocation state, and more — all from your terminal.

```
$ tlsctl client github.com
github.com (secure, expires in 84 days) ✓
  Subject:  CN=github.com
  Issuer:   CN=Sectigo Public Server Authentication CA DV E36,O=Sectigo Limited,C=GB
  Validity: 2026-03-06 → 2026-06-03
  SANs:     github.com, www.github.com

  Chain: github.com → Sectigo Public Server Authentication CA DV E36 → Sectigo Public Server Authentication Root E46 (3 certificates)
```

## Why tlsctl?

- **Instant insights** — One command shows certificate status, chain, SANs, and expiry at a glance
- **Multiple output formats** — Human-readable, JSON, YAML, concise CSV, full CSV, verbose text, or raw PEM
- **Revocation checking** — Built-in CRL and OCSP support to detect revoked certificates
- **PEM file parsing** — Inspect local certificate files with the same rich output
- **Custom CA support** — Validate against private CAs with `--cacert`
- **STARTTLS** — Upgrade plaintext connections for SMTP, IMAP, POP3, and LDAP with `--starttls`
- **SNI override** — Set a custom server name with `--servername` for IP-based targets with virtual hosts
- **Proxy aware** — Connect through HTTP proxies with `--proxy` or environment variables
- **Cross-platform** — Pre-built binaries for Linux, macOS, and Windows (amd64 & arm64)
- **Lightweight** — Single static binary, no runtime dependencies

## Installation

### Pre-built binaries (recommended)

Download the latest release for your platform from the [GitHub Releases](https://github.com/catay/tlsctl/releases/latest) page.

| Platform       | Architecture | Archive |
|----------------|-------------|---------|
| Linux          | amd64       | [`tlsctl_1.2.0_linux_amd64.tar.gz`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_linux_amd64.tar.gz) |
| Linux          | arm64       | [`tlsctl_1.2.0_linux_arm64.tar.gz`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_linux_arm64.tar.gz) |
| macOS          | amd64       | [`tlsctl_1.2.0_darwin_amd64.tar.gz`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_darwin_amd64.tar.gz) |
| macOS          | arm64       | [`tlsctl_1.2.0_darwin_arm64.tar.gz`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_darwin_arm64.tar.gz) |
| Windows        | amd64       | [`tlsctl_1.2.0_windows_amd64.zip`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_windows_amd64.zip) |
| Windows        | arm64       | [`tlsctl_1.2.0_windows_arm64.zip`](https://github.com/catay/tlsctl/releases/download/v1.2.0/tlsctl_1.2.0_windows_arm64.zip) |

```bash
# Example: install on Linux amd64
curl -sL https://github.com/catay/tlsctl/releases/latest/download/tlsctl_1.2.0_linux_amd64.tar.gz | tar xz
sudo mv tlsctl /usr/local/bin/
```

### Build from source

Requires [Go 1.25](https://go.dev/dl/) or later.

```bash
git clone https://github.com/catay/tlsctl.git
cd tlsctl
make build        # or: go build -o tlsctl .
```

### Docker

Pre-built images are published to Docker Hub on every release:

```bash
# Pull and run the latest release
docker run --rm cataybe/tlsctl client github.com

# Use a specific version
docker run --rm cataybe/tlsctl:v1.2.0 client github.com

# Inspect a local PEM file (mount it into the container)
docker run --rm -v /path/to/cert.pem:/cert.pem:ro cataybe/tlsctl pem /cert.pem
```

You can also build the image locally:

```bash
docker build -t tlsctl .
docker run --rm tlsctl client github.com
```

## Quick start

```bash
# Inspect any TLS endpoint (port 443 is the default)
tlsctl client example.com

# Inspect multiple endpoints from a file (one per line)
tlsctl client --file hosts.txt

# Probe supported TLS versions and cipher suites
tlsctl client --tls-versions example.com

# Use a custom port
tlsctl client example.com:8443

# Inspect a local PEM file
tlsctl pem cert.pem
```

## Basic usage

### Inspecting valid certificates

```
$ tlsctl client badssl.com
*.badssl.com (secure, expires in 40 days) ✓
  Subject:  CN=*.badssl.com
  Issuer:   CN=R13,O=Let's Encrypt,C=US
  Validity: 2026-01-20 → 2026-04-20
  SANs:     *.badssl.com, badssl.com

  Chain: *.badssl.com → R13 (2 certificates)
```

### Detecting expired certificates

```
$ tlsctl client expired.badssl.com
*.badssl.com (insecure, certificate expired, expired 3985 days ago) ✗
  Subject:  CN=*.badssl.com,OU=Domain Control Validated+OU=PositiveSSL Wildcard
  Issuer:   CN=COMODO RSA Domain Validation Secure Server CA,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
  Validity: 2015-04-09 → 2015-04-12
  SANs:     *.badssl.com, badssl.com

  Chain: *.badssl.com → COMODO RSA Domain Validation Secure Server CA → COMODO RSA Certification Authority (3 certificates)
```

### Detecting hostname mismatches

```
$ tlsctl client wrong.host.badssl.com
*.badssl.com (insecure, hostname mismatch, expires in 40 days) ✗
  Subject:  CN=*.badssl.com
  Issuer:   CN=R13,O=Let's Encrypt,C=US
  Validity: 2026-01-20 → 2026-04-20
  SANs:     *.badssl.com, badssl.com

  Chain: *.badssl.com → R13 (2 certificates)
```

### Detecting self-signed certificates

```
$ tlsctl client self-signed.badssl.com
*.badssl.com (insecure, unknown authority, expires in 729 days) ✗
  Subject:  CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US
  Issuer:   CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US
  Validity: 2026-03-10 → 2028-03-09
  SANs:     *.badssl.com, badssl.com
```

### Detecting untrusted root CAs

```
$ tlsctl client untrusted-root.badssl.com
*.badssl.com (insecure, unknown authority, expires in 729 days) ✗
  Subject:  CN=*.badssl.com,O=BadSSL,L=San Francisco,ST=California,C=US
  Issuer:   CN=BadSSL Untrusted Root Certificate Authority,O=BadSSL,L=San Francisco,ST=California,C=US
  Validity: 2026-03-10 → 2028-03-09
  SANs:     *.badssl.com, badssl.com

  Chain: *.badssl.com → BadSSL Untrusted Root Certificate Authority (2 certificates)
```

### Detecting incomplete certificate chains

```
$ tlsctl client incomplete-chain.badssl.com
*.badssl.com (insecure, incomplete chain, expires in 39 days) ✗
  Subject:  CN=*.badssl.com
  Issuer:   CN=R13,O=Let's Encrypt,C=US
  Validity: 2026-01-20 → 2026-04-20
  SANs:     *.badssl.com, badssl.com
```

### Revocation checking with CRL

```
$ tlsctl client --revocation crl revoked.badssl.com
revoked.badssl.com (secure, expires in 89 days) ✓
  Subject:  CN=revoked.badssl.com
  Issuer:   CN=E8,O=Let's Encrypt,C=US
  Validity: 2026-03-10 → 2026-06-08
  SANs:     revoked.badssl.com
  Revocation: REVOKED (CRL)

  Chain: revoked.badssl.com → E8 (2 certificates)
```

### Revocation checking with OCSP

```
$ tlsctl client --revocation ocsp google.com
*.google.com (secure, expires in 46 days) ✓
  Subject:  CN=*.google.com
  Issuer:   CN=WR2,O=Google Trust Services,C=US
  Validity: 2026-02-02 → 2026-04-27
  SANs:     *.google.com, *.appengine.google.com, *.bdn.dev, *.origin-test.bdn.dev, *.cloud.google.com (+132 more)
  Revocation: not revoked (OCSP)

  Chain: *.google.com → WR2 → GTS Root R1 (3 certificates)
```

### Probing TLS versions and cipher suites

Use `--tls-versions` to probe supported TLS versions and enumerate server-side cipher suites in preferred order:

```
$ tlsctl client --tls-versions badssl.com
*.badssl.com (secure, expires in 40 days) ✓
  Subject:  CN=*.badssl.com
  Issuer:   CN=R13,O=Let's Encrypt,C=US
  Validity: 2026-01-20 → 2026-04-20
  SANs:     *.badssl.com, badssl.com
  TLS:      TLS 1.0, TLS 1.1, TLS 1.2
  Ciphers (TLS 1.0):
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    ...
  Ciphers (TLS 1.1):
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    ...
  Ciphers (TLS 1.2):
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ...

  Chain: *.badssl.com → R13 (2 certificates)
```

For TLS 1.0–1.2, cipher suites are enumerated by performing repeated handshakes to
determine the server's full preference order. For TLS 1.3, only the negotiated cipher
suite is reported because Go's `crypto/tls` does not allow configuring TLS 1.3 cipher
suites individually.

In human output, insecure cipher suites are highlighted in red and tagged with `(insecure)`.
In non-human outputs (`json`, `yaml`, `csv-full`, and `text`), cipher suites are split into
`secure_cipher_suites` and `insecure_cipher_suites`.

### Verbose text output

Use `-o text` for the full certificate details:

```
$ tlsctl client -o text badssl.com
[LEAF]
Version:               3
Serial Number:         06:17:1e:8f:ca:26:0a:2a:33:19:4f:1b:e5:a7:75:e1:c5:ed
Signature Algorithm:   SHA256-RSA
Issuer:                CN=R13,O=Let's Encrypt,C=US
Subject:               CN=*.badssl.com
Not Before:            2026-01-20T20:02:51Z
Not After:             2026-04-20T20:02:50Z
Public Key Algorithm:  RSA
Key Length:            2048 bits
Key Usage:             Digital Signature, Key Encipherment
Extended Key Usage:    TLS Web Server Authentication, TLS Web Client Authentication
Basic Constraints:     CA:FALSE
Subject Key ID:        2F:70:81:3B:C8:46:E1:26:35:CD:23:DB:C7:65:DA:30:CE:90:E7:44
Authority Key ID:      E7:AB:9F:0F:2C:33:A0:53:D3:5E:4F:78:C8:B2:84:0E:3B:D6:92:33
Subject Alt Names:     *.badssl.com, badssl.com
CA Issuers:            http://r13.i.lencr.org/
CRL Distribution:      http://r13.c.lencr.org/110.crl

[INTERMEDIATE]
Version:               3
Serial Number:         5a:00:f2:12:d8:d4:b4:80:f3:92:41:57:ea:29:83:05
Signature Algorithm:   SHA256-RSA
Issuer:                CN=ISRG Root X1,O=Internet Security Research Group,C=US
Subject:               CN=R13,O=Let's Encrypt,C=US
Not Before:            2024-03-13T00:00:00Z
Not After:             2027-03-12T23:59:59Z
Public Key Algorithm:  RSA
Key Length:            2048 bits
Key Usage:             Digital Signature, Certificate Sign, CRL Sign
Extended Key Usage:    TLS Web Client Authentication, TLS Web Server Authentication
Basic Constraints:     CA:TRUE, pathlen:0
Subject Key ID:        E7:AB:9F:0F:2C:33:A0:53:D3:5E:4F:78:C8:B2:84:0E:3B:D6:92:33
Authority Key ID:      79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
CA Issuers:            http://x1.i.lencr.org/
CRL Distribution:      http://x1.c.lencr.org/
```

### JSON output

Use `-o json` for machine-readable structured output:

```bash
$ tlsctl client -o json badssl.com
```

```json
{
  "certificates": [
    {
      "type": "leaf",
      "version": 3,
      "serial_number": "06:17:1e:8f:ca:26:0a:2a:33:19:4f:1b:e5:a7:75:e1:c5:ed",
      "signature_algorithm": "SHA256-RSA",
      "issuer": "CN=R13,O=Let's Encrypt,C=US",
      "subject": "CN=*.badssl.com",
      "common_name": "*.badssl.com",
      "not_before": "2026-01-20T20:02:51Z",
      "not_after": "2026-04-20T20:02:50Z",
      "public_key_algorithm": "RSA",
      "key_length": 2048,
      "key_usage": ["Digital Signature", "Key Encipherment"],
      "extended_key_usage": ["TLS Web Server Authentication", "TLS Web Client Authentication"],
      "subject_alternative_names": ["*.badssl.com", "badssl.com"],
      "fingerprint": {
        "sha1": "71:03:e9:e6:7c:f1:0e:e0:a7:29:28:fe:85:49:a6:4f:e5:66:e0:48",
        "sha256": "b4:5a:53:24:32:d9:8f:62:b6:ea:f1:47:32:06:10:f1:..."
      }
    }
  ],
  "verified": true
}
```

When `--tls-versions` is enabled, each `tls_versions` entry includes:

```json
{
  "version": "TLS 1.2",
  "cipher_suites": ["..."],
  "secure_cipher_suites": ["..."],
  "insecure_cipher_suites": ["..."]
}
```

### YAML output

Use `-o yaml` for YAML-formatted output:

```bash
$ tlsctl client -o yaml badssl.com
```

```yaml
certificates:
  - type: leaf
    version: 3
    serial_number: 06:17:1e:8f:ca:26:0a:2a:33:19:4f:1b:e5:a7:75:e1:c5:ed
    signature_algorithm: SHA256-RSA
    issuer: CN=R13,O=Let's Encrypt,C=US
    subject: CN=*.badssl.com
    common_name: '*.badssl.com'
    not_before: "2026-01-20T20:02:51Z"
    not_after: "2026-04-20T20:02:50Z"
    public_key_algorithm: RSA
    key_length: 2048
    key_usage:
      - Digital Signature
      - Key Encipherment
    subject_alternative_names:
      - '*.badssl.com'
      - badssl.com
verified: true
```

### CSV output

Use `-o csv` for a concise, spreadsheet-friendly summary. Each input produces one row based on the leaf certificate:

```bash
$ tlsctl client -o csv badssl.com
```

```csv
target,common_name,issuer,not_before,not_after,days_remaining,sha256,subject_alternative_names
badssl.com:443,*.badssl.com,"CN=R13,O=Let's Encrypt,C=US",2026-01-20T20:02:51Z,2026-04-20T20:02:50Z,90,b4:5a:53:24:32:d9:8f:62:b6:ea:f1:47:32:06:10:f1:...,"*.badssl.com; badssl.com"
```

Use `-o csv-full` if you want the row-per-certificate export with the wider field set.

### Raw PEM output

Use `-o raw` to extract the PEM-encoded certificates:

```bash
# Save the certificate chain to a file
tlsctl client -o raw badssl.com > chain.pem

# Pipe to openssl for further inspection
tlsctl client -o raw badssl.com | openssl x509 -noout -text
```

### Skip certificate verification

Use `-k` or `--insecure` to skip TLS certificate verification entirely:

```bash
tlsctl client -k self-signed.example.com
tlsctl client --insecure internal.example.com
```

### Custom CA certificate

Use `--cacert` to validate certificates against a private CA:

```bash
tlsctl client --cacert /path/to/internal-ca.pem internal.example.com
tlsctl pem --cacert /path/to/ca.pem server-cert.pem
```

### Proxy support

Connect through an HTTP proxy with `--proxy` (or `-x`):

```bash
tlsctl client --proxy http://proxy.corp.example.com:8080 example.com
tlsctl client -x http://proxy:3128 example.com
```

The `--proxy` flag falls back to `HTTPS_PROXY` / `HTTP_PROXY` environment variables if not set.

### SNI override

Use `--servername` to override the TLS Server Name Indication (SNI) value. This is useful when connecting to an IP address that hosts multiple virtual hosts:

```bash
tlsctl client --servername example.com 93.184.216.34:443
```

### STARTTLS support

Use `--starttls` to negotiate a plaintext-to-TLS upgrade before inspecting the certificate. Supported protocols: `smtp`, `imap`, `pop3`, `ldap`.

When `--starttls` is used without an explicit port, the default port for the protocol is used automatically:

| Protocol | Default port |
|----------|-------------|
| `smtp`   | 587         |
| `imap`   | 143         |
| `pop3`   | 110         |
| `ldap`   | 389         |

```bash
# SMTP STARTTLS (connects to port 587 by default)
tlsctl client --starttls smtp mail.example.com

# SMTP on a custom port
tlsctl client --starttls smtp mail.example.com:25

# IMAP STARTTLS
tlsctl client --starttls imap mail.example.com

# POP3 STARTTLS
tlsctl client --starttls pop3 mail.example.com

# LDAP STARTTLS
tlsctl client --starttls ldap ldap.example.com
```

### Parsing PEM files

```bash
# Parse a single certificate
tlsctl pem cert.pem

# Parse a certificate chain (multiple certs in one file)
tlsctl pem chain.pem

# Read PEM data from stdin (use '-' or omit the file argument)
cat cert.pem | tlsctl pem -
cat chain.pem | tlsctl pem

# Fetch a certificate via openssl and inspect it
echo | openssl s_client -connect github.com:443 2>/dev/null | openssl x509 | tlsctl pem -

# Inspect a certificate fetched via curl
curl -s https://example.com/ca.pem | tlsctl pem -

# Verbose output
tlsctl pem -o text cert.pem

# JSON output
tlsctl pem -o json cert.pem

# YAML output
tlsctl pem -o yaml cert.pem

# CRL revocation check on a PEM file
tlsctl pem --revocation crl cert.pem
```

## Advanced usage

The JSON output (`-o json`) pairs well with [jq](https://jqlang.github.io/jq/) for extracting specific fields:

```bash
# Get the SHA-256 fingerprint of the leaf certificate
tlsctl client -o json example.com | jq -r '.certificates[] | select(.type == "leaf") | .fingerprint.sha256'

# List all Subject Alternative Names (SANs)
tlsctl client -o json example.com | jq -r '.certificates[] | select(.type == "leaf") | .subject_alternative_names[]'

# Show expiry date for each certificate in the chain
tlsctl client -o json example.com | jq -r '.certificates[] | "\(.type): \(.common_name) expires \(.not_after)"'

# Check if the certificate is verified
tlsctl client -o json example.com | jq '.verified'

# Extract the issuer and subject of the leaf certificate
tlsctl client -o json example.com | jq '.certificates[] | select(.type == "leaf") | {subject, issuer}'

# Get serial numbers of all certificates in the chain
tlsctl client -o json example.com | jq -r '.certificates[] | "\(.type): \(.serial_number)"'

# Count the number of SANs on the leaf certificate
tlsctl client -o json example.com | jq '.certificates[] | select(.type == "leaf") | .subject_alternative_names | length'

# Check multiple hosts and report their expiry dates
tlsctl client -o json google.com github.com | jq -r '.[] | .certificates[] | select(.type == "leaf") | "\(.common_name) expires \(.not_after)"'
```

## Output formats

| Format | Flag | Description |
|--------|------|-------------|
| Human | *(default)* or `-o human` | Brief human-readable summary with color-coded status |
| Text | `-o text` | Verbose output with all certificate fields |
| JSON | `-o json` | Full structured JSON, ideal for scripting and automation |
| YAML | `-o yaml` | Full structured YAML |
| CSV | `-o csv` | Concise one-row-per-input summary using the leaf certificate |
| CSV Full | `-o csv-full` | Wide row-per-certificate export for detailed tabular processing |
| Raw | `-o raw` | PEM-encoded certificates |

## Exit codes

- `0` ok
- `1` runtime error (e.g., connection or parsing failure)
- `2` insecure or invalid (unverified, expired, or revoked)
- `3` revocation error (revocation check failed)
- `4` expiring soon (certificate expires within 30 days, configurable via `--expiry-warning`)

## Status indicators

The default output uses color-coded status indicators:

| Indicator | Color | Meaning |
|-----------|-------|---------|
| `✓` **secure** | Green | Certificate is valid and verified |
| `⚠` **secure** | Yellow | Certificate is verified but expires within the warning threshold (default: 30 days, configurable via `--expiry-warning`) |
| `✗` **insecure** | Red | Certificate verification failed (with reason) |

## Quiet mode

Use `-q` or `--quiet` to suppress all informational and warning output. Only error messages are displayed. Exit codes are preserved, making this ideal for scripting and monitoring:

```bash
tlsctl client -q example.com
echo $?   # 0 = ok, 2 = insecure, 4 = expiring soon, etc.
```

## Disabling color

Use `--no-color` to strip ANSI color codes from output, useful for piping to other tools or log ingestion:

```bash
tlsctl client --no-color example.com
tlsctl client --no-color example.com | tee cert.log
```

## Configuration file

`tlsctl` supports a `settings.json` configuration file for defining default values per subcommand. Configuration values are applied in the following order of precedence:

1. **CLI arguments** (highest priority)
2. **Subcommand-specific values from `settings.json`**
3. **Global values from `settings.json`**
4. **Built-in defaults** (lowest priority)

### File location

The configuration file is stored in the OS-specific configuration directory:

| Platform | Path |
|----------|------|
| Linux    | `$XDG_CONFIG_HOME/tlsctl/settings.json` or `~/.config/tlsctl/settings.json` |
| macOS    | `~/Library/Application Support/tlsctl/settings.json` |
| Windows  | `%AppData%\tlsctl\settings.json` |

Use `--config <path>` to override the default location:

```bash
tlsctl --config /path/to/settings.json client example.com
```

If the default configuration file is missing, `tlsctl` runs with built-in defaults. If `--config` points to a missing file, an error is reported.

### Example configuration

```json
{
  "global": {
    "no-color": false,
    "quiet": false,
    "expiry-warning": 30,
    "output": "json",
    "cacert": "/etc/ssl/certs/ca.pem",
    "revocation": "ocsp",
    "revocation-timeout": "10s",
    "revocation-soft-fail": true
  },
  "client": {
    "quiet": true,
    "expiry-warning": 21,
    "proxy": "http://proxy:8080",
    "tls-versions": true,
    "revocation-soft-fail": false
  },
  "pem": {
    "expiry-warning": 7,
    "output": "yaml"
  }
}
```

The `global` section applies to all subcommands and supports: `no-color`, `quiet`, `expiry-warning`, `output`, `cacert`, `revocation`, `revocation-timeout`, and `revocation-soft-fail`. Each subcommand section (`client`, `pem`) can override any global value with subcommand-specific settings. Only set the values you want to override — omitted keys inherit from `global` or use built-in defaults.

Invalid JSON, unknown keys, and invalid values (e.g., out-of-range `expiry-warning`) produce clear error messages.

## Revocation checking

Both `client` and `pem` subcommands support certificate revocation checking via the `--revocation` flag.

| Flag | Default | Description |
|------|---------|-------------|
| `--revocation` | | Revocation check mode: `crl` or `ocsp` (disabled if not set) |
| `--revocation-timeout` | `5s` | Timeout for revocation requests |
| `--revocation-soft-fail` | `true` | Treat unreachable revocation endpoints as non-fatal |

```bash
# CRL-based revocation check
tlsctl client --revocation crl example.com

# OCSP-based revocation check
tlsctl client --revocation ocsp example.com

# Custom timeout for slow networks
tlsctl client --revocation ocsp --revocation-timeout 10s example.com
```

## Certificate fields

The tool extracts and displays the following X.509 certificate fields:

| Field | Description |
|-------|-------------|
| Type | Leaf, intermediate, or root |
| Version | X.509 certificate version |
| Serial Number | Hex-formatted serial number |
| Signature Algorithm | e.g., SHA256-RSA, ECDSA-SHA256 |
| Issuer / Subject | Distinguished name (DN) |
| Validity | Not Before / Not After in RFC 3339 format |
| Public Key Algorithm | e.g., RSA, ECDSA |
| Key Length | Public key size in bits (e.g., 2048, 4096, 256) |
| Key Usage | Digital Signature, Key Encipherment, Certificate Sign, etc. |
| Extended Key Usage | TLS Web Server Authentication, Client Authentication, etc. |
| Basic Constraints | CA flag and path length |
| Subject / Authority Key ID | Hex-formatted key identifiers |
| Subject Alt Names | DNS names |
| Email / IP Addresses | Additional identifiers |
| OCSP / CA Issuers / CRL | Revocation and issuer endpoints |
| Revocation Status | CRL or OCSP result (when `--revocation` is enabled) |
| Fingerprint | SHA-1 and SHA-256 fingerprints |

## Testing with badssl.com

[badssl.com](https://badssl.com) provides various endpoints for testing TLS certificate scenarios. Here are some useful ones to try with `tlsctl`:

```bash
# Valid certificate
tlsctl client badssl.com

# Expired certificate
tlsctl client expired.badssl.com

# Wrong hostname
tlsctl client wrong.host.badssl.com

# Self-signed certificate
tlsctl client self-signed.badssl.com

# Untrusted root CA
tlsctl client untrusted-root.badssl.com

# Incomplete certificate chain
tlsctl client incomplete-chain.badssl.com

# Revoked certificate (check via CRL)
tlsctl client --revocation crl revoked.badssl.com

# ECC certificate
tlsctl client ecc256.badssl.com
```

## Shell completion

Generate autocompletion scripts for your shell:

```bash
# Bash
tlsctl completion bash > /etc/bash_completion.d/tlsctl

# Zsh
tlsctl completion zsh > "${fpath[1]}/_tlsctl"

# Fish
tlsctl completion fish > ~/.config/fish/completions/tlsctl.fish
```

## License

[MIT](LICENSE)

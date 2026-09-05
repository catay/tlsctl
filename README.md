# tlsctl

[![CI](https://github.com/catay/tlsctl/actions/workflows/ci.yaml/badge.svg)](https://github.com/catay/tlsctl/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/catay/tlsctl)](https://github.com/catay/tlsctl/releases/latest)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<p align="center"><img src="images/tlsctl-192x192.png" alt="tlsctl logo" width="192" height="192"></p>

Inspect TLS certificates from endpoints, PEM files, or stdin. See certificate
trust, expiry, revocation, and negotiated TLS details in your terminal, or export
the same results as JSON, YAML, or CSV.

**Release preparation:** This README targets 2.0.0. The versioned downloads and
Docker images below become available after the separately approved release is
published.

**Upgrading from 1.x?** Version 2.0.0 changes structured output for both `client`
and `pem` and removes `--format-version`. Read the
[migration notes](#migrating-from-1x) before updating scripts.

## Table of contents

- [Installation](#installation)
  - [Pre-built binaries](#pre-built-binaries)
  - [Build from source](#build-from-source)
  - [Docker](#docker)
- [Quick start](#quick-start)
- [Output and exit codes](#output-and-exit-codes)
- [Connection and certificate checks](#connection-and-certificate-checks)
  - [PEM verification](#pem-verification)
  - [Revocation policy](#revocation-policy)
  - [TLS probes](#tls-probes)
- [Configuration](#configuration)
- [Color and completion](#color-and-completion)
- [Migrating from 1.x](#migrating-from-1x)
- [Development](#development)
- [License](#license)

## Installation

### Pre-built binaries

Download an archive and `checksums.txt` from
[GitHub Releases](https://github.com/catay/tlsctl/releases).

| Platform | Architecture | Archive |
| --- | --- | --- |
| Linux | amd64 | [tlsctl_2.0.0_linux_amd64.tar.gz](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_linux_amd64.tar.gz) |
| Linux | arm64 | [tlsctl_2.0.0_linux_arm64.tar.gz](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_linux_arm64.tar.gz) |
| macOS | amd64 | [tlsctl_2.0.0_darwin_amd64.tar.gz](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_darwin_amd64.tar.gz) |
| macOS | arm64 | [tlsctl_2.0.0_darwin_arm64.tar.gz](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_darwin_arm64.tar.gz) |
| Windows | amd64 | [tlsctl_2.0.0_windows_amd64.zip](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_windows_amd64.zip) |
| Windows | arm64 | [tlsctl_2.0.0_windows_arm64.zip](https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_windows_arm64.zip) |

Linux amd64 installation, in an empty working directory:

```bash
curl -fLO https://github.com/catay/tlsctl/releases/download/v2.0.0/tlsctl_2.0.0_linux_amd64.tar.gz
curl -fLO https://github.com/catay/tlsctl/releases/download/v2.0.0/checksums.txt
sha256sum --check --ignore-missing checksums.txt
# Continue only if checksum verification succeeds.
tar -xzf tlsctl_2.0.0_linux_amd64.tar.gz
sudo install -m 755 tlsctl /usr/local/bin/tlsctl
tlsctl version
```

On macOS, compare `shasum -a 256 ARCHIVE` with its entry in `checksums.txt`.
On Windows, use `Get-FileHash ARCHIVE -Algorithm SHA256`.

### Build from source

Requires Go **1.26.8 or later**. Use a current patched toolchain for a TLS tool.

```bash
git clone https://github.com/catay/tlsctl.git
cd tlsctl
make build
./tlsctl version
```

`make build` uses Go and embeds the repository version, commit, and build date.
A plain `go build -o tlsctl .` also works, with development version metadata.

### Docker

```bash
docker run --rm cataybe/tlsctl:v2.0.0 client example.com
docker run --rm -v /path/to/chain.pem:/chain.pem:ro cataybe/tlsctl:v2.0.0 pem /chain.pem
docker run --rm -i cataybe/tlsctl:v2.0.0 pem - < chain.pem

# Build the source image locally.
docker build -t tlsctl .
docker run --rm tlsctl version
```

Images run as an unprivileged user and include the system CA bundle. Mounted
files must be readable by that user. The `latest` image tag tracks releases.

## Quick start

```bash
# Inspect an endpoint; the default port is 443.
tlsctl client example.com
tlsctl client example.com:8443

# Inspect a file or stdin.
tlsctl pem chain.pem
tlsctl pem - < chain.pem

# Query several endpoints, retaining failures in structured output.
tlsctl client -o json example.com missing.example.invalid

# Read endpoints from a file, with up to eight concurrent targets by default.
tlsctl client --file hosts.txt --concurrency 8 -o csv

# Advertise ALPN and inspect the negotiated protocol.
tlsctl client --alpn h2,http/1.1 example.com

# Inspect SMTP using STARTTLS.
tlsctl client --starttls smtp mail.example.com
```

Human output identifies the input, followed by certificate status, subject,
issuer, validity, handshake details when available, and the certificate chain.
Revoked certificates are reported as insecure. Unavailable soft-fail revocation
checks remain visible as warnings.

Inputs are hosts or IP addresses with optional ports, including `[::1]:443`,
`[::1]`, and `::1`. URLs and paths are rejected. Endpoint files accept blank
lines and `#` comments. File inputs precede positional targets; results retain
input order and duplicate targets are retained.

## Output and exit codes

| Format | Flag | Contract |
| --- | --- | --- |
| Human | `-o human` (default) | Concise certificate summary |
| Text | `-o text` | Detailed certificate fields, fingerprints, and check results |
| JSON | `-o json` | One `status` / `summary` / `results` envelope |
| YAML | `-o yaml` | The same envelope as JSON |
| CSV | `-o csv` | One row per input, including failed inputs |
| CSV-full | `-o csv-full` | One row per certificate; one error row for failed inputs |
| Raw | `-o raw` | PEM certificates for successful inputs |

There is one structured format contract, shared by `client` and `pem`.
For PEM, `target` is the filename or `stdin`; all certificates in that input
belong to one result. JSON and YAML omit the PEM payload itself.

The envelope's `status` is `success`, `partial_success`, or `failure`.
Per-result `status` describes whether inspection succeeded. A successfully
inspected certificate can still be invalid: `tls_status` is `secure`,
`expiring`, `insecure`, or `revocation_error`. Failed inputs have `error`
and omit `result` and `tls_status`.

```bash
# Leaf fingerprint for each successfully inspected input.
tlsctl client -o json example.com |
  jq -r '.results[] | select(.status == "success") | .result.certificates[0].fingerprint.sha256'

# Endpoint and failure reason.
tlsctl client --file hosts.txt -o json |
  jq -r '.results[] | select(.status == "failure") | "\(.target): \(.error)"'

# Export the chain as PEM.
tlsctl client -o raw example.com > chain.pem
```

| Exit code | Meaning |
| --- | --- |
| `0` | No failing checks or expiry warnings |
| `1` | Invocation, configuration, connection, input, timeout, or output error |
| `2` | Invalid, untrusted, expired, not-yet-valid, or revoked certificate |
| `3` | Required revocation check could not establish a result |
| `4` | Verified certificate expires within the warning threshold |

For mixed results, precedence is `1 > 3 > 2 > 4 > 0`; it is not numeric order.
The expiry threshold defaults to 30 days and can be set with `--expiry-warning`
(1–10000 days). The comparison uses elapsed time, including the exact threshold;
displayed days are rounded down for future expiry.

Use `--quiet` (`-q`) to suppress stdout and retain exit codes and operational
errors. Structured modes include per-input errors in stdout; quiet mode instead
reports them on stderr. Invocation and configuration errors always go to stderr.
When piping to another command, use your shell's `pipefail` option if you need
to preserve tlsctl's failure status.

`secure` means the certificate passed the applicable trust and validity checks.
It is not a complete security assessment of the server or its TLS configuration.
Revocation is checked only when requested. A soft-fail revocation result can leave
`tls_status` as `secure`; inspect `result.certificates[0].revocation.overall_status`
to determine whether revocation was established. The chain's `verified` field
reports certificate verification independently of revocation and expiry warnings.

## Connection and certificate checks

```bash
# Add private CAs to system trust.
tlsctl client --cacert private-ca.pem internal.example.com
tlsctl pem --cacert private-ca.pem chain.pem

# Override both SNI and the hostname used for certificate verification.
tlsctl client --servername example.com 192.0.2.1:443

# Set bounds for an entire target and each connection phase.
tlsctl client --timeout 30s --connect-timeout 3s --handshake-timeout 5s example.com

# Probe TLS versions and cipher suites implemented by Go.
tlsctl client --tls-versions example.com

# Check revocation, failing when no usable result can be established.
tlsctl client --revocation ocsp --revocation-soft-fail=false example.com

# Inspect through an HTTP or HTTPS proxy.
tlsctl client --proxy http://proxy.example.com:8080 example.com
```

`--timeout` defaults to one minute per target, including TLS probes and
revocation; it starts when a worker begins that target. `--connect-timeout`
defaults to 5 seconds per connection. `--handshake-timeout` defaults to 10 seconds
per proxy negotiation and per STARTTLS/TLS handshake phase. All timeouts must be
positive. `--concurrency` accepts 1–256 and defaults to 8. Ctrl-C cancels ongoing
network work.

Supported STARTTLS protocols and default ports are SMTP (587), IMAP (143),
POP3 (110), and LDAP (389). An explicit port takes precedence.

Without `--proxy`, target connections use `HTTPS_PROXY` and `NO_PROXY`
(including lowercase variants). There is no `HTTP_PROXY` fallback for target
TLS connections. Explicit proxies override environment exclusions.
Revocation HTTP requests independently use the standard HTTP(S) proxy environment
settings. The explicit `--proxy` flag applies only to target connections.
Only HTTP and HTTPS CONNECT proxies are supported; omitted proxy ports default
to 80 and 443 respectively.

### PEM verification

Supply the leaf certificate first, followed by intermediates. The first certificate
determines status and is the subject of any requested revocation check. Other
certificates in a bundle are displayed but are not verified as separate inputs.
Included roots do not automatically become trusted; `--cacert` adds certificates
to system trust.

PEM verification checks trust and validity without requiring a hostname or a
particular extended key usage. Client verification also checks the hostname and
server-authentication usage. Invalid peer certificates remain inspectable: the
client collects and explicitly verifies them on the same connection without
sending application data.

### Revocation policy

Both commands accept `--revocation crl` or `--revocation ocsp`. Checks are
disabled by default and apply to the primary certificate only.

| Result | Soft-fail (default) | `--revocation-soft-fail=false` |
| --- | --- | --- |
| Usable good response | `good` | `good` |
| Confirmed revoked response | `revoked`, exit `2` | `revoked`, exit `2` |
| No usable response | Uncertainty is reported; no failure solely for uncertainty | `error`, exit `3` |

Other failures can still determine the exit code. In particular, an exhausted
client `--timeout` is an input-processing failure, even with soft-fail enabled.

Responders are tried in certificate order until a usable good or revoked result
is found; failed attempts remain in `revocation.results`. Each request has a
`--revocation-timeout` of 5 seconds by default and shares the client's overall
target deadline.

CRLs require the actual issuer, a valid signature, and freshness. Unsupported
critical CRL extensions are rejected. OCSP delegated responders must authorize
OCSP signing and have a currently valid certificate. Issuers are selected by
certificate relationships, not their position in the input. Missing issuers are
not downloaded through AIA.

`ThisUpdate` must be present and no more than five minutes in the future.
`NextUpdate`, when present, must follow `ThisUpdate` and be later than the
current time. Without `NextUpdate`, responses are accepted for at most 24 hours.
Response bodies are bounded to 10 MiB for CRLs and 1 MiB for OCSP. Unsupported
responses and missing issuer/responder information are uncertainty, not evidence
that a certificate is unrevoked.

### TLS probes

`--tls-versions` probes TLS 1.0–1.3, including legacy-only endpoints. TLS 1.0–1.2
cipher enumeration repeatedly removes the negotiated suite from the offered list.
Results reflect observed negotiation order and cover only suites implemented by
Go. TLS 1.3 reports only the negotiated cipher suite because Go does not permit
configuring those suites individually.

Cipher security categories follow Go's classification. Legacy protocol support
does not change certificate trust status by itself, and a failed probe is not
proof that the protocol is unsupported. An exhausted overall deadline produces a
failure instead of a supposedly complete probe result.

STARTTLS text reply lines and LDAP responses are bounded to 64 KiB. Malformed
or unsuccessful upgrade replies are reported as connection failures.

## Configuration

Configuration is JSON at the OS-specific location:

| Platform | Default path |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/tlsctl/settings.json` or `~/.config/tlsctl/settings.json` |
| macOS | `~/Library/Application Support/tlsctl/settings.json` |
| Windows | `%AppData%\tlsctl\settings.json` |

Override the path with `--config PATH`. A missing default file is allowed; a
missing explicitly selected file is an error. Precedence is explicit CLI flags,
then the command section, then `global`, then built-in defaults.

```json
{
  "global": {
    "expiry-warning": 21,
    "no-color": true
  },
  "client": {
    "output": "json",
    "concurrency": 8,
    "timeout": "1m"
  },
  "pem": {
    "output": "yaml"
  }
}
```

Unknown keys, trailing JSON, and invalid values are rejected. Remove the old
`format-version` setting when upgrading. Help, completion, and version reporting
do not depend on certificate configuration. All supplied values are validated,
including settings overridden by CLI flags. Explicit `false` flags override
configured `true` values.

Common settings in `global`, `client`, and `pem`:

| Key | Type | Default |
| --- | --- | --- |
| `no-color` | Boolean | Automatic terminal/environment detection |
| `quiet` | Boolean | `false` |
| `expiry-warning` | Integer, 1–10000 | `30` |
| `output` | Format name | `human` |
| `cacert` | PEM path | System trust |
| `revocation` | `crl`, `ocsp`, or empty | Disabled |
| `revocation-timeout` | Positive duration string | `5s` |
| `revocation-soft-fail` | Boolean | `true` |

Client-only settings:

| Key | Type | Default |
| --- | --- | --- |
| `file` | Endpoint filename or `-` | None |
| `proxy` | HTTP(S) URL | `HTTPS_PROXY` / `NO_PROXY` |
| `tls-versions` | Boolean | `false` |
| `alpn` | Comma-separated protocols | None |
| `servername` | Verification/SNI hostname | Target hostname |
| `starttls` | Protocol name | Disabled |
| `concurrency` | Integer, 1–256 | `8` |
| `timeout` | Positive duration string | `1m` |
| `connect-timeout` | Positive duration string | `5s` |
| `handshake-timeout` | Positive duration string | `10s` |

`connect-timeout` and `handshake-timeout` may also be set in `global`, but only
apply to `client`. PEM configuration rejects these connection-only keys.

## Color and completion

Use `--no-color` or `NO_COLOR=1` to disable ANSI color. Color is also disabled
automatically when stdout is not a terminal. Status words remain meaningful
without color.

```bash
tlsctl completion bash > tlsctl.bash
tlsctl completion zsh > _tlsctl
tlsctl completion fish > tlsctl.fish
```

Source the Bash script or install the generated file in your shell's completion
directory. Output formats, revocation modes, and STARTTLS protocols have value
completion.

## Migrating from 1.x

Version 2.0.0 removes structured format v1. Remove `--format-version` from commands
and `format-version` from configuration; both are rejected rather than ignored.
The former v2 contract is now the only structured format for both commands,
including single endpoints and PEM input.

For a successfully inspected single input, JSON/YAML paths change as follows:

| Legacy path | 2.0.0 path |
| --- | --- |
| `.certificates` | `.results[0].result.certificates` |
| `.verified` | `.results[0].result.verified` |
| `.negotiated_tls` | `.results[0].result.negotiated_tls` |
| `.verification_error` | `.results[0].result.verification_error` |

For batches, iterate `.results[]`, select `.status == "success"`, and then access
`.result`. The existing client v2 envelope is retained; PEM now uses it too.
One PEM file or stdin is one result containing all its certificates.

Both CSV modes begin with `target,status,tls_status,error`. PEM uses `target`
instead of the old `source` header. Read columns by name, not old numeric positions.
CSV-full still emits one row per certificate; failed inputs produce one error row.

Soft-fail and hard-fail revocation handling have been corrected as described
[above](#revocation-policy). Missing or malformed CA files and output-write failures
return exit `1`. Invalid options are rejected even with `--quiet`. Exit-code
numbers and precedence remain `1 > 3 > 2 > 4 > 0`.

New client defaults are eight concurrent targets and a one-minute overall timeout
per target. Existing connection-phase timeouts continue to apply. Human and text
output identify the actual target/source, and expiry warnings use the exact
threshold instead of a truncated day count.

The Go module path is now `github.com/catay/tlsctl/v2`, with Go 1.26.8 or later
required. Module-based installation after publication uses:

```bash
go install github.com/catay/tlsctl/v2@v2.0.0
```

Module-based installation uses development version metadata. Use release archives
or `make build` when embedded release metadata is needed.

## Development

```bash
make             # Formatting check, lint, race-enabled tests, and build
make fmt         # Apply Go formatting
make test        # Race-enabled tests
make vuln        # Scan reachable Go vulnerabilities
make release-local  # Build snapshot archives and images without publishing
```

The full `make` target requires `golangci-lint` v2.11 or later, built with a
compatible Go toolchain. Snapshot releases additionally require GoReleaser v2
and Docker with Buildx. Release workflows validate before tagging and can resume
publication for a tag pointing at the same commit.

The implementation and release use separate PRs. Merging implementation changes
does not publish a release; the separately approved `chore: bump version to 2.0.0`
PR updates `VERSION` and triggers release publication. The README's installation
examples already target 2.0.0.

## License

[MIT](LICENSE)

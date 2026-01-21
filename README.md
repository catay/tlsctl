# tlsctl

A command-line tool to query TLS certificate information.

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

## Example Output

### Text (default)

```
[LEAF]
Common Name:           *.google.com
Issuer:                WR2
Valid From:            2025-12-09T17:08:50Z
Valid Until:           2026-03-03T17:08:49Z
Subject Alt Names:     *.google.com, *.appengine.google.com, ...

[INTERMEDIATE]
Common Name:           WR2
Issuer:                GTS Root R1
Valid From:            2023-12-13T09:00:00Z
Valid Until:           2029-02-20T14:00:00Z
```

### JSON

```json
{
  "certificates": [
    {
      "common_name": "*.google.com",
      "issuer": "WR2",
      "not_before": "2025-12-09T17:08:50Z",
      "not_after": "2026-03-03T17:08:49Z",
      "subject_alternative_names": ["*.google.com", "..."],
      "type": "leaf"
    }
  ]
}
```

### YAML

```yaml
certificates:
  - commonname: '*.google.com'
    issuer: WR2
    notbefore: "2025-12-09T17:08:50Z"
    notafter: "2026-03-03T17:08:49Z"
    subjectaltnames:
      - '*.google.com'
    type: leaf
```

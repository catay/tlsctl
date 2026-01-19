# tlsctl

A command-line tool to query TLS certificate information.

## Installation

```bash
go build -o tlsctl .
```

## Usage

```bash
# Human-readable output (port defaults to 443)
tlsctl google.com

# With explicit port
tlsctl google.com:8443

# JSON output
tlsctl --json example.com
```

## Example Output

```
Common Name:           www.google.com
Issuer:                GTS CA 1C3
Valid From:            2025-01-10T08:04:05Z
Valid Until:           2025-04-09T08:04:05Z
Subject Alt Names:     www.google.com, google.com
```

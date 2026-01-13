# tlsq

A command-line tool to query TLS certificate information.

## Installation

```bash
go build -o tlsq .
```

## Usage

```bash
# Human-readable output
tlsq google.com:443

# JSON output
tlsq --json example.com:443
```

## Example Output

```
Common Name:           www.google.com
Issuer:                GTS CA 1C3
Valid From:            2025-01-10T08:04:05Z
Valid Until:           2025-04-09T08:04:05Z
Subject Alt Names:     www.google.com, google.com
```

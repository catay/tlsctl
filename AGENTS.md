# AGENTS.md

## Overview

This repository contains **tlsq**, a small Go command-line application for querying TLS certificate information for a given endpoint.

The tool accepts an argument in the form:

```
FQDN:PORT
```

It connects using TLS and prints certificate metadata including:

- Common Name (CN)
- Issuer
- Not Before (creation date)
- Not After (expiration date)
- Subject Alternative Names (SANs)

The application:

- is written in **Go**
- uses **Cobra** for CLI structure
- supports **JSON output via a flag** (e.g., `--json`)
- avoids unnecessary dependencies

---

## Goals for AI Coding Agents

When assisting on this project, agents should:

### Primary goals

- follow idiomatic **Go style**
- produce **readable** and **maintainable** code
- keep dependencies minimal
- design for future extensibility (more TLS features later)
- ensure robust error handling and edge case testing

### Secondary goals

- support running on Linux/macOS/Windows
- ensure code builds with:
  ```
  go build ./...
  ```
- prefer standard library unless there is clear justification otherwise

---

## Tech Stack & Constraints

- **Language:** Go (1.21+ preferred)
- **CLI Framework:** `spf13/cobra`
- **TLS:** Go standard library `crypto/tls`, `crypto/x509`
- **JSON output:** use Go stdlib `encoding/json`

Avoid:

- shelling out to `openssl`
- complex abstractions for simple flows
- unnecessary global state

---

## Project Structure (recommended)

```
tlsq/
 ├─ cmd/
 │   └─ root.go
 │   └─ inspect.go
 ├─ internal/
 │   └─ tlsquery/
 │       └─ query.go
 ├─ main.go
 ├─ go.mod
 ├─ AGENTS.md
 └─ README.md
```

---

## CLI Requirements

### Base command

```
tlsq FQDN:PORT
```

Examples:

```
tlsq google.com:443
tlsq example.org:8443
```

### Flags

| Flag | Description |
|------|-------------|
| `--json` | Output machine-readable JSON |
| `-h, --help` | Standard Cobra help |

---

## Output Requirements

### Human-readable

Example (no strict format required):

```
Common Name:           www.example.com
Issuer:                Let's Encrypt Authority X3
Valid From:            2025-01-10 08:04:05 UTC
Valid Until:           2025-04-09 08:04:05 UTC
Subject Alt Names:     www.example.com, example.com
```

### JSON output

Keys expected:

```json
{
  "common_name": "www.example.com",
  "issuer": "Let's Encrypt Authority X3",
  "not_before": "2025-01-10T08:04:05Z",
  "not_after": "2025-04-09T08:04:05Z",
  "subject_alternative_names": [
    "www.example.com",
    "example.com"
  ]
}
```

---

## Testing Expectations

Agents should produce:

- unit tests for certificate parsing logic
- basic integration test for known public endpoint (optional)
- mockable TLS dialing

---

## Commit Message Rules (Conventional Commits)

All contributions MUST follow **Conventional Commits**:

**Format**

```
<type>(optional scope): <description>
```

**Allowed types**

- `feat` — new user-facing feature
- `fix` — bug fix
- `docs` — documentation only
- `refactor` — restructuring without behavior change
- `test` — test-only changes
- `chore` — tooling/config build metadata
- `perf` — performance improvement
- `ci` — continuous integration related changes
- `style` — formatting only

**Examples**

```
feat(cli): add JSON output flag
fix(tlsquery): handle missing SAN extension
docs: add usage examples to README
refactor: move TLS logic into internal package
```

---

## Non-Goals for Agents

Agents should NOT:

- replace Go TLS validation with home-rolled crypto
- introduce external TLS binaries
- build GUI frontends
- implement unrelated features (HTTP probing, OCSP, etc.) in v1

---

## Future Roadmap Suggestions (not for first iteration)

- OCSP stapling status
- certificate chain display
- output PEM option
- expiration warning thresholds
- Kubernetes secret integration
- CSV export option

---

## Definition of Done — v1

The project is considered complete for v1 when:

- `tlsq` builds
- accepts `FQDN:PORT`
- performs TLS handshake
- retrieves leaf certificate
- prints required fields
- supports `--json`
- has basic README instructions

---

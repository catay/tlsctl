# AGENTS.md

## Commands
- Build: `make build` or `go build -o tlsctl .`
- Test all: `make test` or `go test ./...`
- Test single: `go test -run TestName ./path/to/pkg`
- Clean: `make clean`
- Format: `gofmt -w .`
- **Always run `make` after code changes and ensure there are no errors.**

## Architecture
- `cmd/` - Cobra CLI commands (root, client, pem)
- `internal/tlsquery/` - Core TLS query and PEM parsing logic
- Dependencies: spf13/cobra (CLI), gopkg.in/yaml.v3 (output)

## Documentation
- **Update `README.md` when there are user-facing behaviour changes (new flags, commands, output changes, etc.).**

## Code Style
- Use standard Go formatting (`gofmt`) and idiomatic Go patterns
- Prefer stdlib over external dependencies
- Use table-driven tests; keep functions small and focused
- Error handling: return errors, don't panic; wrap with context

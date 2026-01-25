# AGENTS.md

## Commands
- Build: `make build` or `go build -o tlsctl .`
- Test all: `make test` or `go test ./...`
- Test single: `go test -run TestName ./path/to/pkg`
- Clean: `make clean`
- Format: `gofmt -w .`

## Architecture
- `cmd/` - Cobra CLI commands (root, client, pem)
- `internal/tlsquery/` - Core TLS query and PEM parsing logic
- Dependencies: spf13/cobra (CLI), gopkg.in/yaml.v3 (output)

## Code Style
- Use standard Go formatting (`gofmt`) and idiomatic Go patterns
- Prefer stdlib over external dependencies
- Use table-driven tests; keep functions small and focused
- Error handling: return errors, don't panic; wrap with context
- Conventional Commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`

## Git Workflow
- Branch naming: `feat/feature-name`, `fix/bug-name`
- Squash commits; run tests before committing
- Request approval before merging to `main`

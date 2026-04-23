# Project Rules — psst

## General

- **psst** — secrets manager for AI agents. Written in Go, CLI-only (no SDK/library).
- Repository: `github.com/aatumaykin/psst`
- License: MIT
- Go version: 1.25+
- Requires CGo (mattn/go-sqlite3)

## Repository Structure

```
cmd/psst/main.go       — Entry point (minimal: calls cli.Execute())
internal/
  cli/                  — Cobra commands (14+ commands)
  crypto/               — AES-256-GCM encryption (Encryptor interface)
  store/                — SQLite persistence (SecretStore interface)
  keyring/              — OS keychain + env var fallback (KeyProvider interface)
  vault/                — Business logic facade (Vault struct)
  output/               — Human/JSON/quiet formatting (Formatter)
  runner/               — Subprocess execution + output masking
docs/
  rules/                — This directory: AI agent rules
  ru/                   — Russian documentation
```

## Build & Development

```bash
make build              # Build binary → ./psst
make test               # Run all tests: go test ./... -v
make clean              # Remove binary
make build-linux-amd64  # Cross-compile for Linux amd64
make build-linux-arm64  # Cross-compile for Linux arm64
```

- Before committing, run `make test` and ensure all tests pass.
- No linter config in repo yet — follow `gofmt` and `go vet` conventions.

## Branches & Commits

- `main` — stable branch.
- Commit messages follow conventional commits style: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`.
- Examples from history:
  - `feat(cli): added completion command`
  - `fix: explicit error on init without keychain and PSST_PASSWORD`
  - `docs: translate documentation to Russian`

## Dependencies

| Package | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `mattn/go-sqlite3` | SQLite driver (CGo) |
| `zalando/go-keyring` | OS keychain integration |
| `golang.org/x/sys` | System calls (indirect) |

- Do not add new dependencies without justification.
- `renovate.json` is configured for automated dependency updates.

## Files to Never Modify

- `docs/superpowers/` — internal planning artifacts, not part of the product.
- `renovate.json` — managed by Renovate bot.

## Exit Codes

- `0` — success
- `1` — general error
- `3` — vault not found
- `5` — authentication/unlock failed

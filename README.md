# psst

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go 1.26+](https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go)](https://go.dev/)

**[Документация на русском](docs/ru/README.md)**

Secrets manager for AI agents. Agents use secrets without seeing their values.

Rewritten in Go from [Michaelliv/psst](https://github.com/Michaelliv/psst) (original in TypeScript/Bun).

## Why

When you paste API keys into an AI agent's context, they end up in:

- The model's context window
- Terminal history
- Log files
- Screenshots

psst injects secrets into the subprocess environment at runtime. The agent orchestrates, psst handles the secrets.

```
# Agent writes:
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com

# What the agent sees:
# ✓ Command executed successfully

# What actually ran:
# curl -H "Authorization: Bearer sk_live_abc123..." https://api.stripe.com
```

## Installation

### From source

```bash
git clone https://github.com/aatumaykin/psst.git && cd psst
make build
sudo install psst /usr/local/bin/
```

### Requirements

- Go 1.26+ (for building)
- On Linux: `libsecret` headers (for OS keyring support)

## Quick Start

```bash
# Create vault (encryption key stored in OS keychain)
psst init

# On a server without OS keychain — use PSST_PASSWORD:
export PSST_PASSWORD="your-password"
psst init                    # creates vault with key derived from password

# Add secrets
echo "sk-live-abc123" | psst set STRIPE_KEY --stdin
echo "postgres://db:5432/app" | psst set DATABASE_URL --stdin
psst set API_KEY                    # interactive prompt

# Verify
psst list

# Use with an agent
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com
psst run -- ./deploy.sh             # inject all secrets
```

> **Note:** On Linux without `libsecret` (servers, CI), the key cannot be stored in OS keychain.
> Use `PSST_PASSWORD` — it must be set before each invocation:
> ```bash
> export PSST_PASSWORD="your-password"
> psst init
> psst set KEY --stdin <<< "value"
> psst list
> ```

## Commands

### Managing Secrets

```bash
psst init [--global] [--env <name>]   # Create vault
psst set <NAME> [--stdin] [--tag T]   # Add/update secret
psst get <NAME>                       # Show value (debugging only)
psst list [--tag T]                   # List secret names
psst rm <NAME>                        # Delete secret + history
psst migrate                          # Upgrade vault to latest KDF
```

### Using Secrets

```bash
psst run <command> [args...]              # Run with all secrets
psst <SECRET>... -- <command> [args...]    # Run with specific secrets
```

### Import / Export

```bash
psst import .env                      # Import from .env file
psst import --stdin                   # Import from stdin
psst import --from-env                # Import from environment variables
psst export                           # Export to stdout (.env format)
psst export --env-file .env           # Export to file
```

### History & Rollback

```bash
psst history <NAME>                   # View version history (last 10)
psst rollback <NAME> --to <version>   # Restore previous version
```

### Tags

```bash
psst tag <NAME> <TAG>                 # Add tag
psst untag <NAME> <TAG>               # Remove tag
psst list --tag prod                  # Filter by tag (OR logic)
psst --tag aws -- aws s3 ls           # Run with tagged secrets only
```

### Self-Update

```bash
psst update check                     # Check for newer version
psst update install                   # Download and install latest
psst update install --force           # Reinstall current version
```

### Secret Scanner

```bash
psst scan                             # Check git-tracked files
psst scan --staged                    # Only staged files
psst scan --path ./src                # Specific directory
```

Scans files for actual vault secret values — no regex false positives.

### Environments

```bash
psst init --env prod                  # Create vault for "prod"
psst --env prod set API_KEY --stdin
psst --env prod list
psst --env prod API_KEY -- curl ...

psst list-envs                        # List all environments
```

Stored in `.psst/envs/<name>/vault.db` (or `~/.psst/envs/<name>/` with `--global`).

### Global Flags

All commands support:

```
--json              Structured JSON output
-q, --quiet         Minimal output
-g, --global        Use global vault (~/.psst/)
--env <name>        Use specific environment
--tag <name>        Filter by tag (repeatable, OR logic)
--no-mask           Disable output masking (debugging only)
```

Fallback environment variables: `PSST_GLOBAL=1`, `PSST_ENV=<name>`.

## Security

- Secrets encrypted at rest with **AES-256-GCM**
- **Argon2id** KDF for password-based vaults (v2), SHA-256 for legacy (v1)
- Unique random IV per encryption
- Encryption key stored in OS keychain (libsecret on Linux)
- Secrets automatically redacted in command output (`[REDACTED]`)
- Secrets never exposed to agent context
- `PSST_PASSWORD` removed from child process environment
- Vault database file permissions set to `0600`
- Best-effort memory zeroing for keys and plaintext

## CI / Headless Environments

When OS keychain is unavailable (servers, Docker, CI), use `PSST_PASSWORD`:

```bash
export PSST_PASSWORD="your-password"   # set once per session
psst init                              # create vault
psst set API_KEY --stdin <<< "value"
psst run -- ./deploy.sh                # secrets injected into env, output masked
```

Key is derived from password via Argon2id (new vaults) or SHA-256 (legacy vaults, upgrade with `psst migrate`). `PSST_PASSWORD` must be set before each psst invocation.

## Architecture

```
cmd/psst/main.go          Entry point (DI wiring)
internal/
├── crypto/               AES-256-GCM encryption (Encryptor interface)
├── store/                SQLite storage (SecretStore interface)
├── keyring/              OS keychain + env var fallback (KeyProvider interface)
├── vault/                Business logic facade
├── output/               Human/JSON/quiet formatting
├── runner/               Subprocess execution + output masking
├── updater/              Self-update mechanism (GitHub releases)
├── version/              Build-time version info (ldflags)
└── cli/                  Cobra commands (18 root commands + exec pattern)
```

### Key Interfaces

```go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    KeyToBufferV2(key string) ([]byte, error)
    KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyDeriver interface {
    KeyToBuffer(key string) ([]byte, error)
    KeyToBufferV2(key string) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyProvider interface {
    GetRawKey(service, account string) (string, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}

type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    GetAllSecrets() ([]StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
    // ... (full interface in internal/store/store.go)
}
```

## Development

```bash
make build              # Build binary
make test               # Run all tests
make clean              # Remove binary

# Cross-compilation
make build-linux-amd64
make build-linux-arm64
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `modernc.org/sqlite` | Pure Go SQLite driver (no CGo) |
| `zalando/go-keyring` | OS keychain integration |
| `golang.org/x/term` | Secure terminal input |
| `golang.org/x/crypto` | Argon2id KDF |

### SQLite Schema

```sql
CREATE TABLE vault_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE secrets (
    name TEXT PRIMARY KEY,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    tags TEXT DEFAULT '[]'
);

CREATE TABLE secrets_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    tags TEXT DEFAULT '[]',
    archived_at TEXT,
    UNIQUE(name, version)
);
```

## Differences from Original (TypeScript/Bun)

| Property | Original (TS) | This (Go) |
|----------|---------------|-----------|
| Runtime | Bun | Static binary |
| SQLite | bun:sqlite / better-sqlite3 | modernc.org/sqlite (pure Go) |
| Crypto | Web Crypto API | stdlib crypto/aes + crypto/cipher |
| Keychain | CLI utility calls | zalando/go-keyring |
| CLI | Manual argument parsing | spf13/cobra |
| Platforms | macOS, Linux, Windows | Linux (amd64, arm64) |
| SDK | Yes (importable library) | CLI only |

## License

[MIT](LICENSE)

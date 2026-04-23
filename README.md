# psst

AI-native secrets manager. Agents use secrets without seeing them.

Go rewrite of [Michaelliv/psst](https://github.com/Michaelliv/psst) (original in TypeScript/Bun).

## Why

When you paste API keys into an AI agent's context, they end up in:

- The model's context window
- Terminal history
- Log files
- Screenshots

psst injects secrets into subprocess environment at runtime. The agent orchestrates, psst handles the secrets.

```
# Agent writes this:
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com

# What the agent sees:
# ✓ Command executed successfully

# What actually ran:
# curl -H "Authorization: Bearer sk_live_abc123..." https://api.stripe.com
```

## Install

### From source

```bash
git clone <repo-url> && cd psst
make build
sudo install psst /usr/local/bin/
```

### Requirements

- Go 1.22+ (for building)
- gcc (for CGo — mattn/go-sqlite3)
- On Linux: `libsecret` dev headers (for OS keyring support)

## Quick Start

```bash
# Create vault (stores encryption key in OS keychain)
psst init

# Add secrets
echo "sk-live-abc123" | psst set STRIPE_KEY --stdin
echo "postgres://db:5432/app" | psst set DATABASE_URL --stdin
psst set API_KEY                    # interactive prompt

# Verify
psst list

# Use with agent
psst STRIPE_KEY -- curl -H "Authorization: Bearer $STRIPE_KEY" https://api.stripe.com
psst run -- ./deploy.sh             # all secrets injected
```

## Commands

### Managing Secrets

```bash
psst init [--global] [--env <name>]   # Create vault
psst set <NAME> [--stdin] [--tag T]   # Add/update secret
psst get <NAME>                       # View value (debugging)
psst list [--tag T]                   # List secret names
psst rm <NAME>                        # Delete secret + history
```

### Using Secrets

```bash
psst run <command> [args...]          # Run with all secrets
psst <SECRET>... -- <command> [args]  # Run with specific secrets
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

### Scanning

```bash
psst scan                             # Scan git-tracked files
psst scan --staged                    # Scan staged files only
psst scan --path ./src                # Scan specific directory
```

Checks files for actual vault secret values — no regex false positives.

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
-q, --quiet         Suppress output
-g, --global        Use global vault (~/.psst/)
--env <name>        Use specific environment
--tag <name>        Filter by tag (repeatable, OR logic)
```

Environment variable fallbacks: `PSST_GLOBAL=1`, `PSST_ENV=<name>`.

## Security

- Secrets encrypted at rest with **AES-256-GCM**
- Unique random IV per encryption
- Encryption key stored in OS keychain (libsecret on Linux)
- Secrets automatically redacted in command output (`[REDACTED]`)
- Secrets never exposed to agent context
- `PSST_PASSWORD` removed from child process environment

## CI / Headless Environments

When OS keychain is unavailable, use `PSST_PASSWORD`:

```bash
export PSST_PASSWORD="your-master-password"
psst STRIPE_KEY -- ./deploy.sh
```

The key is derived from the password via SHA-256.

## Architecture

```
cmd/psst/main.go          Entry point (DI wiring)
internal/
├── crypto/               AES-256-GCM encryption (Encryptor interface)
├── store/                SQLite persistence (SecretStore interface)
├── keyring/              OS keychain + env var fallback (KeyProvider interface)
├── vault/                Business logic facade
├── output/               Human/JSON/quiet formatting
├── runner/               Subprocess execution + output masking
└── cli/                  Cobra commands (14 commands)
```

### Key Interfaces

```go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}

type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
    // ... (full interface in internal/store/store.go)
}
```

## Development

```bash
make build              # Build binary
make test               # Run all tests
make clean              # Remove binary

# Cross-compile
make build-linux-amd64
make build-linux-arm64
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `mattn/go-sqlite3` | SQLite driver (CGo) |
| `zalando/go-keyring` | OS keychain integration |

### SQLite Schema

```sql
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

| Feature | Original (TS) | This (Go) |
|---------|---------------|-----------|
| Runtime | Bun | Static binary |
| SQLite | bun:sqlite / better-sqlite3 | mattn/go-sqlite3 |
| Crypto | Web Crypto API | stdlib crypto/aes + crypto/cipher |
| Keychain | CLI tool calls | zalando/go-keyring |
| CLI | Manual arg parsing | spf13/cobra |
| Platforms | macOS, Linux, Windows | Linux (amd64, arm64) |
| SDK | Yes (importable library) | CLI only |

## License

MIT

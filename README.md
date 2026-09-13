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
- gcc (for CGo — mattn/go-sqlite3)
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

### Git Storage (multi-machine)

```bash
psst init --storage git --remote git@github.com:me/psst-vault.git
# or a local bare repo: --remote /path/to/vault.git
echo "sk-live-abc" | psst set STRIPE_KEY --stdin
psst sync
```

- Every command pulls before reading and rebases+pushes on writes.
- Reads work offline; writes require the remote (or warn on local-only repos).
- One file per secret, tags are directories (`secrets/prod/DB_PASS.enc`), a
  single tag per secret; history is git history.
- Same `PSST_PASSWORD` on every machine (or the interactive prompt).
- `psst migrate storage --to git` converts an existing SQLite vault.

Migration from SQLite: `psst migrate kdf` first if the vault is on the legacy
KDF, then `psst migrate storage --to git --remote <url>`.

### Web UI

```bash
psst serve [--listen 127.0.0.1:7788] [--token <tok>] [--timeout 30m]
# psst server:  http://127.0.0.1:7788
# auth token:   <generated>   (shown once)
```

Requires git storage (`psst migrate storage --to git`). The token is generated at
startup and printed once; pass one via `--token` (visible in `ps` output on
multi-user hosts) or `PSST_SERVE_TOKEN`. The vault password is entered in the UI
(unlock, 30-minute inactivity timeout). Secret values are shown only through the
explicit reveal action.

Remote access: `ssh -L 7788:127.0.0.1:7788 <host>`, then open
`http://127.0.0.1:7788` locally.

### Render templates

```bash
psst render --in deploy.env.tpl --out deploy.env           # output is always 0600
psst render --in config.yaml.tpl --out config.yaml --tag prod
psst render --in app.ini.tpl --out app.ini --strict
```

- `{{KEY}}` — must resolve; unresolved names fail the command (fail-closed: a literal
  `{{KEY}}` never ships). Note: templates mixing another `{{ }}` templating system
  (Helm, Go templates) cannot be rendered — every `{{...}}` span must resolve.
- `$KEY` / `${KEY}` — replaced when the secret exists, left as-is otherwise.
- `--strict` — unresolved `$` placeholders fail too.
- Rendered files are plaintext secrets: add them to `.gitignore` (only `.env`/`.env.*`
  are ignored by default); `psst scan` catches tracked leaks.

Protocol-independent recipes (no proxy needed):

```bash
psst SSHPASS -- sshpass -e ssh user@host            # env injection
psst API_KEY -- python deploy.py                    # os.environ["API_KEY"]
psst API_KEY -- node deploy.js                      # process.env.API_KEY
psst render --in deploy.env.tpl --out deploy.env    # file generation
docker --env-file <(psst export) run ...            # container env
```

### Key rotation

```bash
echo "new-password" | psst rotate --stdin   # old password via PSST_PASSWORD or prompt
psst sync --accept-rotation                 # on every other machine
```

- `psst rotate` (git storage only) mints a new salt and re-encrypts every secret plus
  the updated `psst.yaml` as ONE commit; the rotating machine re-pins itself.
- `psst rotate --kdf` also strengthens the KDF parameters to the defaults in the same
  commit — never weakens: on a vault already at defaults it is a params no-op (the salt
  still rotates), and on a vault stronger than defaults it fails closed (there is no CLI
  path to lower parameters, by design).
- On every other machine the old password fails with
  `vault salt changed; run 'psst sync --accept-rotation' (or re-clone)`. Acceptance
  verifies the NEW password before the pin moves — a wrong password leaves the clone
  refused (never silently re-pinned) and can be retried.
- Acceptance refuses when the clone has unpushed local commits (rebasing old-key
  commits onto the rotation would mix keys permanently): drop them with
  `psst sync --discard-local` (values remain in the reflog), then retry — plain
  `psst sync` cannot push old-key commits once the rotation has landed.
- If `psst rotate` aborts midway, the remote is untouched — upstream IS the
  pre-rotation state; reset the working tree with `psst sync --discard-local`.
- A running `psst serve` needs no restart: until the rotation is accepted on the
  server host, the next operation fails naming `psst sync --accept-rotation` and
  drops all unlocks; after accepting there, one re-unlock prompt may appear, then
  unlock works with the new password.

### Global Flags

All commands support:

```
--json              Structured JSON output
-q, --quiet         Minimal output
-g, --global        Use global vault (~/.psst/)
--env <name>        Use specific environment
--tag <name>        Filter by tag (repeatable, OR logic)
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
└── cli/                  Cobra commands (15 commands)
```

### Key Interfaces

```go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    KeyToBufferV2(key string) ([]byte, error)
    GenerateKey() ([]byte, error)
}

type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    GetRawKey(service, account string) (string, error)
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

# Cross-compilation
make build-linux-amd64
make build-linux-arm64
```

### Dependencies

| Package | Purpose |
|---------|---------|
| `spf13/cobra` | CLI framework |
| `mattn/go-sqlite3` | SQLite driver (CGo) |
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
| SQLite | bun:sqlite / better-sqlite3 | mattn/go-sqlite3 |
| Crypto | Web Crypto API | stdlib crypto/aes + crypto/cipher |
| Keychain | CLI utility calls | zalando/go-keyring |
| CLI | Manual argument parsing | spf13/cobra |
| Platforms | macOS, Linux, Windows | Linux (amd64, arm64) |
| SDK | Yes (importable library) | CLI only |

## License

[MIT](LICENSE)

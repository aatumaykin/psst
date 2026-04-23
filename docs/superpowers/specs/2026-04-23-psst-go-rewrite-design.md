# psst Go Rewrite — Design Spec

**Date:** 2026-04-23
**Status:** Approved
**Target:** Full 1:1 rewrite of https://github.com/Michaelliv/psst (TypeScript/Bun) in Go
**Platforms:** Linux amd64 + arm64

## Overview

psst — AI-native secrets manager. CLI-инструмент, позволяющий AI-агентам использовать секреты (API keys, passwords) без прямого доступа к их значениям. Секреты шифруются (AES-256-GCM), хранятся в SQLite vault, а ключ шифрования — в OS keychain.

Переписываем на Go для: единого бинарника без runtime-зависимостей, производительности, простоты дистрибуции.

## Architecture

### Approach: Idiomatic Go with interfaces and DI

Структура проекта:

```
psst/
├── cmd/
│   └── psst/
│       └── main.go              # entry point: DI wiring, cobra execute
├── internal/
│   ├── cli/                     # cobra commands
│   │   ├── root.go              # root + persistent flags
│   │   ├── init.go              # psst init
│   │   ├── set.go               # psst set
│   │   ├── get.go               # psst get
│   │   ├── list.go              # psst list / list envs
│   │   ├── rm.go                # psst rm
│   │   ├── run.go               # psst run
│   │   ├── exec.go              # psst SECRET -- cmd
│   │   ├── import.go            # psst import
│   │   ├── export.go            # psst export
│   │   ├── scan.go              # psst scan
│   │   ├── history.go           # psst history
│   │   ├── rollback.go          # psst rollback
│   │   └── tag.go               # psst tag/untag
│   ├── vault/                   # business logic facade
│   │   ├── vault.go             # Vault struct (main entry point)
│   │   ├── types.go             # Secret, SecretMeta, SecretHistoryEntry, etc.
│   │   └── vault_test.go
│   ├── store/                   # persistence layer
│   │   ├── store.go             # SecretStore interface
│   │   ├── sqlite.go            # SQLite implementation
│   │   ├── migrations.go        # schema creation + ALTER TABLE
│   │   └── sqlite_test.go
│   ├── crypto/                  # encryption
│   │   ├── crypto.go            # Encryptor interface
│   │   ├── aesgcm.go            # AES-256-GCM implementation
│   │   └── aesgcm_test.go
│   ├── keyring/                 # encryption key storage
│   │   ├── keyring.go           # KeyProvider interface
│   │   ├── oskeyring.go         # zalando/go-keyring (libsecret on Linux)
│   │   ├── envvar.go            # PSST_PASSWORD env var fallback
│   │   └── keyring_test.go
│   ├── runner/                  # subprocess execution
│   │   ├── runner.go            # Runner struct
│   │   ├── mask.go              # output masking
│   │   └── runner_test.go
│   └── output/                  # output formatting
│       ├── output.go            # Formatter + human/json/quiet modes
│       └── output_test.go
├── go.mod
├── go.sum
└── .gitignore
```

### DI wiring (main.go)

```go
func main() {
    enc := crypto.NewAESGCM()
    kp := keyring.NewProvider()  // oskeyring with envvar fallback
    store := store.NewSQLite(vaultPath)
    v := vault.New(enc, kp, store)
    r := runner.New()
    fmt := output.NewFormatter(jsonMode, quietMode)

    cli.Execute(v, r, fmt)
}
```

## Interfaces

### Encryptor (`internal/crypto/crypto.go`)

```go
type Encryptor interface {
    Encrypt(plaintext []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
}
```

### KeyProvider (`internal/keyring/keyring.go`)

```go
type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}
```

### SecretStore (`internal/store/store.go`)

```go
type StoredSecret struct {
    Name           string
    EncryptedValue []byte
    IV             []byte
    Tags           []string
    CreatedAt      string
    UpdatedAt      string
}

type SecretMeta struct {
    Name      string
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type HistoryEntry struct {
    Version  int
    Tags     []string
    ArchivedAt string
}

type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
    DeleteSecret(name string) error
    DeleteHistory(name string) error
    ListSecrets() ([]SecretMeta, error)
    GetHistory(name string) ([]HistoryEntry, error)
    AddHistory(name string, version int, encValue, iv []byte, tags []string) error
    PruneHistory(name string, keepVersions int) error
    Close() error
}
```

### Formatter (`internal/output/output.go`)

```go
type Formatter interface {
    Success(msg string)
    Error(msg string)
    Warning(msg string)
    Bullet(msg string)
    SecretList(secrets []vault.SecretMeta)
    SecretValue(name, value string)
    History(name string, current *vault.Secret, entries []vault.SecretHistoryEntry)
    ScanResult(results []runner.ScanResult)
    JSON(data any) error
}
```

## Crypto (AES-256-GCM)

**Package:** `internal/crypto/`
**Implementation:** `crypto/aes` + `crypto/cipher` + `crypto/rand` (stdlib)

### Constants
- Key length: 32 bytes (AES-256)
- IV length: 12 bytes (standard GCM)

### KeyToBuffer(key string) ([]byte, error)
1. Try base64 decode -> if result is exactly 32 bytes, use directly
2. Otherwise: SHA-256 hash of the string -> use as key

### Encrypt(plaintext []byte) (ciphertext, iv []byte, err error)
1. Generate random 12-byte IV via `crypto/rand`
2. Create AES cipher block from key
3. Create GCM mode (`cipher.NewGCM`)
4. Seal: `gcm.Seal(nil, iv, plaintext, nil)`
5. Return ciphertext + iv

### Decrypt(ciphertext, iv []byte) ([]byte, error)
1. Create AES cipher block from key
2. Create GCM mode
3. Open: `gcm.Open(nil, iv, ciphertext, nil)`
4. Return plaintext

## SQLite Schema

**Package:** `internal/store/`
**Driver:** `github.com/mattn/go-sqlite3`

### Table: secrets

```sql
CREATE TABLE IF NOT EXISTS secrets (
    name TEXT PRIMARY KEY,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    created_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    updated_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    tags TEXT DEFAULT '[]'
);
```

### Table: secrets_history

```sql
CREATE TABLE IF NOT EXISTS secrets_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    encrypted_value BLOB NOT NULL,
    iv BLOB NOT NULL,
    tags TEXT DEFAULT '[]',
    archived_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
    UNIQUE(name, version)
);

CREATE INDEX IF NOT EXISTS idx_secrets_history_name ON secrets_history(name);
```

### Migrations

Run on every `InitSchema()`:
1. `CREATE TABLE IF NOT EXISTS` for both tables (idempotent)
2. Check if `tags` column exists in `secrets` via `PRAGMA table_info` -> if not, `ALTER TABLE secrets ADD COLUMN tags TEXT DEFAULT '[]'`
3. Same for `secrets_history`

## Keyring

**Package:** `internal/keyring/`
**Library:** `github.com/zalando/go-keyring`

### KeyProvider implementations

#### oskeyring (Linux)
- `GetKey`: `keyring.Get(service, account)` -> base64 decode -> 32 bytes
- `SetKey`: base64 encode -> `keyring.Set(service, account, encoded)`
- `IsAvailable`: try `keyring.Get("psst", "test")`, check for `keyring.ErrNotFound` vs other errors
- `GenerateKey`: `crypto/rand` -> 32 bytes -> base64

#### envvar (fallback)
- `GetKey`: read `PSST_PASSWORD` from env -> `KeyToBuffer()`
- `SetKey`: no-op (env var is read-only)
- `IsAvailable`: `os.Getenv("PSST_PASSWORD") != ""`

### Provider selection
```go
func NewProvider() KeyProvider {
    os := &OSKeyring{}
    if os.IsAvailable() {
        return os
    }
    return &EnvVarProvider{}
}
```

### Constants
- Service: `"psst"`
- Account: `"vault-key"`

## Vault (Facade)

**Package:** `internal/vault/`

### Types

```go
type Secret struct {
    Name      string
    Value     string    // decrypted
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type SecretMeta struct {
    Name      string
    Tags      []string
    CreatedAt string
    UpdatedAt string
}

type SecretHistoryEntry struct {
    Version    int
    Tags       []string
    ArchivedAt string
}
```

### Vault struct

```go
type Vault struct {
    enc    crypto.Encryptor
    kp     keyring.KeyProvider
    store  store.SecretStore
    key    []byte
    open   bool
}
```

### Key methods

- `New(enc, kp, store) *Vault`
- `Init(opts InitOptions) error` — create directory, init schema, generate key, store in keychain
- `Unlock() error` — get key from keychain/PSST_PASSWORD
- `SetSecret(name, value string, tags []string) error` — archive current to history, encrypt, store
- `GetSecret(name string) (*Secret, error)` — read, decrypt
- `ListSecrets() ([]SecretMeta, error)`
- `DeleteSecret(name string) error` — delete secret + history
- `GetHistory(name string) ([]SecretHistoryEntry, error)`
- `Rollback(name string, version int) error` — archive current, restore version
- `AddTag(name, tag string) error`
- `RemoveTag(name, tag string) error`
- `GetSecretsByTags(tags []string) ([]SecretMeta, error)` — OR logic
- `GetAllSecrets() ([]Secret, error)` — decrypt all (for run/export)
- `Close()`

### Vault discovery (from original)

```go
func FindVaultPath(global bool, env string) (string, error)
```

Priority:
1. If `--global`: `~/.psst/` (or `~/.psst/envs/<name>/`)
2. If `--env`: `.psst/envs/<name>/` (local) or `~/.psst/envs/<name>/` (global)
3. Default: `.psst/` in current directory

## Runner (Subprocess Execution)

**Package:** `internal/runner/`

### Exec (named secrets)

```go
func (r *Runner) Exec(secrets map[string]string, command string, args []string, opts ExecOptions) (int, error)
```

1. Build env: `os.Environ()` + secrets map - `PSST_PASSWORD`
2. Expand `$VAR` and `${VAR}` in args using secrets map
3. `exec.Command(command, expandedArgs...)`
4. Set `cmd.Env`
5. If `opts.MaskOutput`: pipe stdout/stderr through masking, else inherit
6. Wait for completion, return exit code

### Run (all secrets)

Same as Exec but secrets come from `vault.GetAllSecrets()`.

### Output Masking

```go
func MaskSecrets(text string, secrets []string) string {
    for _, s := range secrets {
        if len(s) > 0 {
            text = strings.ReplaceAll(text, s, "[REDACTED]")
        }
    }
    return text
}
```

Applied to stdout/stderr streams in real-time.

### Env var expansion

```go
func ExpandEnvVars(arg string, env map[string]string) string
```

Replaces `$NAME` and `${NAME}` patterns with values from env map.

## CLI Commands

**Package:** `internal/cli/`
**Framework:** `github.com/spf13/cobra`

### Root command

Persistent flags:
- `--json` / `-j`: JSON output
- `--quiet` / `-q`: Quiet mode
- `--global` / `-g`: Global vault
- `--env <name>`: Environment name
- `--tag <name>` (repeatable): Tag filter

Env var fallbacks: `PSST_GLOBAL`, `PSST_ENV`

### Command list

| Command | Description |
|---------|-------------|
| `psst init [--global] [--env <name>]` | Create vault, generate key, store in keychain |
| `psst set <name> [--stdin] [--tag <t>]...` | Set secret (interactive prompt or stdin) |
| `psst get <name>` | Print decrypted value |
| `psst list [envs] [--tag <t>]...` | List secret names (or environments) |
| `psst rm <name>` | Delete secret + history |
| `psst run <command> [args...]` | Run with all secrets injected |
| `psst <SECRET>... -- <command> [args...]` | Run with specific secrets |
| `psst import [--stdin \| --from-env \| <file>]` | Import from .env/stdin/env |
| `psst export [--env-file <path>]` | Export in .env format |
| `psst scan [--staged] [--path <dir>]` | Scan files for leaked secrets |
| `psst history <name>` | Show version history |
| `psst rollback <name> --to <version>` | Restore previous version |
| `psst tag <name> <tag>` | Add tag to secret |
| `psst untag <name> <tag>` | Remove tag from secret |

### Exec pattern handling

The `psst SECRET1 SECRET2 -- command args` pattern requires custom parsing before cobra:
1. Find `--` index in args
2. Everything before `--` = secret names (or empty if tags present)
3. Everything after `--` = command + args
4. Delegate to `exec.go` command

This is handled in `root.go`'s `PreRunE` or as a special case in arg parsing.

## Output Formatting

**Package:** `internal/output/`

Three modes controlled by flags:
- **Human** (default): colored output, Unicode symbols (✓, ✗, ●)
- **JSON** (`--json`): `encoding/json` marshaling
- **Quiet** (`--quiet`): minimal output, exit codes only

Colors: use ANSI escape codes directly (no library needed for Linux-only).

## Exit Codes

```go
const (
    ExitSuccess    = 0
    ExitError      = 1
    ExitUserError  = 2
    ExitNoVault    = 3
    ExitAuthFailed = 5
)
```

## Secret Scanner

**Package:** `internal/runner/` (or `internal/cli/scan.go`)

### Algorithm:
1. Get all decrypted secrets from vault
2. Collect file list: git tracked files, staged files, or specific path
3. For each file:
   - Skip binary files (null byte check)
   - Skip files > 1MB
   - Skip non-text extensions
   - For each secret (len >= 4): `strings.Contains(content, secretValue)`
4. Report: filename:line -> which secret was found

### Scan result type:
```go
type ScanResult struct {
    File    string
    Line    int
    Secret  string  // secret name, not value
}
```

## Import/Export

### Import
- Parse `.env` files: `KEY=VALUE` with quote handling (single, double, no quotes)
- `--stdin`: read from stdin
- `--from-env`: read from `os.Environ()`
- Validate names: `^[A-Z][A-Z0-9_]*$`

### Export
- Write `KEY=VALUE` format to stdout or file
- Quote values containing spaces/special chars

## Environments

- Default vault: `.psst/vault.db` (local) or `~/.psst/vault.db` (global)
- Named env: `.psst/envs/<name>/vault.db` or `~/.psst/envs/<name>/vault.db`
- `psst list envs`: scan both local and global for env directories
- `PSST_ENV` env var as fallback for `--env`

## History & Rollback

- On every `SetSecret`: archive current value to `secrets_history` with incremented version
- Auto-prune: keep last 10 versions
- `Rollback(name, version)`: archive current (as new version), then restore specified version
- Rollback is reversible (current is never lost)

## Tags

- Stored as JSON array in `tags` TEXT column
- `AddTag` / `RemoveTag`: read JSON, modify, write back
- Filter by tags with OR logic: secret matches if it has ANY of the requested tags

## Dependencies

```
github.com/spf13/cobra        # CLI framework
github.com/mattn/go-sqlite3   # SQLite driver (CGo)
github.com/zalando/go-keyring # OS keychain integration
```

Stdlib packages used:
- `crypto/aes`, `crypto/cipher`, `crypto/rand`, `crypto/sha256` — encryption
- `encoding/base64`, `encoding/json` — encoding
- `os/exec` — subprocess execution
- `database/sql` — SQLite interface
- `fmt`, `text/template` — output formatting

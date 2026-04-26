# Architecture — psst

## Overview

Layered architecture with dependency injection via interfaces. Direction: `cli → vault → {crypto, store, keyring}`. The `cli` layer is the outermost; `crypto`, `store`, and `keyring` are leaf packages with no cross-dependencies.

## Layers

```
┌─────────────────────────────────┐
│  cmd/psst/main.go               │  Entry point (DI wiring via cli.Execute)
├─────────────────────────────────┤
│  cli/                           │  Cobra commands — parsing, validation, I/O
├─────────────────────────────────┤
│  vault/                         │  Business logic facade — CRUD, history, tags
├──────────┬──────────┬───────────┤
│  crypto/ │  store/  │ keyring/  │  Infrastructure — encryption, DB, OS keychain
└──────────┴──────────┴───────────┘
│  output/                        │  Presentation — human/JSON/quiet formatting
│  runner/                        │  Execution — subprocess + output masking
│  updater/                       │  Self-update — GitHub release check + install
│  version/                       │  Build-time version info (injected via ldflags)
```

## Dependency Rules

1. **Allowed:** `cli → vault`, `cli → runner`, `cli → output`, `cli → crypto`, `cli → store`, `cli → keyring`, `vault → crypto`, `vault → store`, `vault → keyring`.
2. **Prohibited:** `crypto → store`, `crypto → keyring`, `store → crypto`, `store → keyring`, `keyring → store`. Leaf packages must not depend on each other.
3. **Prohibited:** `vault → cli`, `store → cli`, any upward dependency from inner to outer layers.
4. `output/` may import `vault/` types only (for `vault.SecretMeta`, `vault.SecretHistoryEntry`). No business logic in output. `output/` must NOT import `version/` — version data is passed as parameter via `VersionData` struct.
5. `runner/` is standalone — no imports from `vault`, `store`, `keyring`.

## Key Interfaces

```go
// crypto/crypto.go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    KeyToBufferV2(key string) ([]byte, error)
    KeyToBufferV2WithSalt(key string, salt []byte) ([]byte, error)
    GenerateKey() ([]byte, error)
}

// keyring/keyring.go
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

// store/store.go
type SecretStore interface {
    InitSchema() error
    GetSecret(name string) (*StoredSecret, error)
    GetAllSecrets() ([]StoredSecret, error)
    SetSecret(name string, encValue, iv []byte, tags []string) error
    DeleteSecret(name string) error
    DeleteHistory(name string) error
    ListSecrets() ([]SecretMeta, error)
    GetHistory(name string) ([]HistoryEntry, error)
    AddHistory(name string, version int, encValue, iv []byte, tags []string) error
    PruneHistory(name string, keepVersions int) error
    ExecTx(fn func() error) error
    GetMeta(key string) (string, error)
    SetMeta(key, value string) error
    IncrementMetaInt(key string, increment int) (int, error)
    Close() error
}
```

## DI Wiring

All dependency wiring happens in `cli/root.go` via `createDependencies()` and `getUnlockedVault()`:

func createDependencies() (crypto.Encryptor, keyring.KeyProvider) {
    enc := crypto.NewAESGCM()
    kp := keyring.NewProvider(enc)
    return enc, kp
}
```

No DI container, no global state. Each command creates its own instances.

## Data Flow

### Secret Write
`cli → vault.SetSecret(name, value, tags) → crypto.Encrypt(value, key) → store.SetSecret(name, ciphertext, iv, tags)`

### Secret Read
`cli → vault.GetSecret(name) → store.GetSecret(name) → crypto.Decrypt(ciphertext, iv, key)`

### Command Execution
`cli → vault.GetAllSecrets() → runner.Exec(secrets, cmd, args) → subprocess + output masking`

## Storage

- SQLite with WAL mode (`?_journal_mode=WAL`).
- Tables: `secrets` (name PK), `secrets_history` (versioned backup, max 10 versions per secret).
- Tags stored as JSON array in `TEXT` column.
- Schema migration via `migrations.go` — checks column existence before ALTER.

## Encryption

- AES-256-GCM with random 12-byte IV per encryption.
- Key derivation via Argon2id (v2, current) or SHA-256 (v1, legacy). New vaults use Argon2id by default; upgrade via `psst migrate`.
- KDF version and salt stored in `vault_meta` table.
- `PSST_PASSWORD` is stripped from child process environment.

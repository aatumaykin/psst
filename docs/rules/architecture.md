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
```

## Dependency Rules

1. **Allowed:** `cli → vault`, `cli → runner`, `cli → output`, `cli → crypto`, `cli → store`, `cli → keyring`, `vault → crypto`, `vault → store`, `vault → keyring`.
2. **Prohibited:** `crypto → store`, `crypto → keyring`, `store → crypto`, `store → keyring`, `keyring → store`. Leaf packages must not depend on each other.
3. **Prohibited:** `vault → cli`, `store → cli`, any upward dependency from inner to outer layers.
4. `output/` may import `vault/` types only (for `vault.SecretMeta`, `vault.SecretHistoryEntry`). No business logic in output.
5. `runner/` is standalone — no imports from `vault`, `store`, `keyring`.

## Key Interfaces

```go
// crypto/crypto.go
type Encryptor interface {
    Encrypt(plaintext, key []byte) (ciphertext, iv []byte, err error)
    Decrypt(ciphertext, iv, key []byte) ([]byte, error)
    KeyToBuffer(key string) ([]byte, error)
    GenerateKey() ([]byte, error)
}

// keyring/keyring.go
type KeyProvider interface {
    GetKey(service, account string) ([]byte, error)
    SetKey(service, account string, key []byte) error
    IsAvailable() bool
    GenerateKey() ([]byte, error)
}

// store/store.go
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

## DI Wiring

All dependency wiring happens in `cli/root.go` via `getUnlockedVault()`:

```go
enc := crypto.NewAESGCM()
kp := keyring.NewProvider(enc)       // auto-selects OS keyring or env var
s, _ := store.NewSQLite(vaultPath)
v := vault.New(enc, kp, s)
v.Unlock()
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
- Key: 32 bytes from OS keychain (base64-encoded) or derived from `PSST_PASSWORD` via SHA-256.
- `PSST_PASSWORD` is stripped from child process environment.

# Refactoring Design — psst

## Goal

Fix all identified code quality, architecture, and correctness issues across all layers of the psst project using a bottom-up (store → vault → cli → runner) approach.

## Layer 1: Store

### 1a. Transaction support in SecretStore

Add `ExecTx(fn func() error) error` to `SecretStore` interface and implement in `SQLiteStore` using `db.Begin()`, `tx.Commit()`, `tx.Rollback()`.

### 1b. Batch method to eliminate N+1

Add `GetAllSecrets() ([]StoredSecret, error)` to `SecretStore` — single `SELECT` of all secrets. `Vault.GetAllSecrets` calls this, then decrypts in loop.

### 1c. Unify types

Replace `vault.SecretMeta` and `vault.SecretHistoryEntry` with aliases/embeddings of `store.SecretMeta` and `store.HistoryEntry`. Remove boilerplate conversions in `ListSecrets()`, `GetHistory()`, `GetSecretsByTags()`.

## Layer 2: Vault

### 2a. Interfaces instead of concrete types

Change `Vault` struct fields:
- `enc *crypto.AESGCM` → `enc crypto.Encryptor`
- `store *store.SQLiteStore` → `store store.SecretStore`

Update `New()` constructor signature accordingly.

### 2b. Error handling

- `SetSecret`: check `GetSecret` error before `existing != nil` check
- `SetSecret`: check errors from `GetHistory`, `AddHistory`, `PruneHistory`
- `sqlite.go`: check `json.Marshal` error
- Remove dead `parseTagsJSON` function

### 2c. Transactional SetSecret

Wrap history archival + store update in `store.ExecTx()` call.

## Layer 3: CLI

### 3a. DI factory

Extract `createDependencies()` returning `(crypto.Encryptor, keyring.KeyProvider)`. Use in both `getUnlockedVault` and `initCmd`.

### 3b. Simplify argument parsing

Move `parseGlobalFlagsFromArgs`, `filterSecretNames`, `containsFlag` to new file `cli/args.go`.

### 3c. Remove duplicates

Remove `envsSubCmd` in `list_envs.go` — `list-envs` is already a standalone command.

## Layer 4: Runner

### 4a. Safe ExpandEnvVars order

Sort map keys by length (descending) before substitution to prevent `$API_KEY` from matching inside `$API_KEY_EXTRA`.

## Files Changed

| File | Changes |
|------|---------|
| `internal/store/store.go` | +ExecTx, +GetAllSecrets in interface |
| `internal/store/sqlite.go` | Implement new methods, fix json.Marshal error |
| `internal/vault/vault.go` | Interfaces, errors, transactions, remove dead code |
| `internal/vault/types.go` | Unify with store types |
| `internal/vault/vault_test.go` | Adapt to interfaces |
| `internal/cli/root.go` | DI factory |
| `internal/cli/init.go` | Use DI factory |
| `internal/cli/list_envs.go` | Remove duplicate |
| `internal/cli/args.go` (new) | Extract argument parsing |
| `internal/runner/expand.go` | Safe substitution order |

## Verification

- `make test` passes after each layer
- No new dependencies introduced
- All existing behavior preserved

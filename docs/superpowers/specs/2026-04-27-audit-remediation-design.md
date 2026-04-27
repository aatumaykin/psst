# Audit Report & Remediation Plan — psst

**Date:** 2026-04-27
**Scope:** Full codebase audit — security, risks, refactoring opportunities
**Approach:** Priority-based (CRITICAL → HIGH → MEDIUM → LOW)

## Project Stats

- ~8000 LOC production, ~3000 LOC tests (ratio > 1.0)
- 5 dependencies (all current, stable)
- 48 linters in golangci-lint
- Previous audit remediation already applied (commit 9cce397)

---

## CRITICAL — 0 issues

Crypto implementation is solid: AES-256-GCM + Argon2id + per-vault random salt. Output masking is mature (two-phase replacement with chunk-boundary awareness).

---

## HIGH — 3 issues

### H1. Key copies not zeroed in GetSecret / GetAllSecrets

**Files:** `internal/vault/secrets.go:63`, `internal/vault/secrets.go:123`

`SetSecret` correctly calls `defer crypto.ZeroBytes(key)`, but `GetSecret` and `GetAllSecrets` do not zero the key copy after use. Multiple calls accumulate key copies in heap.

**Risk:** Memory dump / core dump may expose derived encryption keys.

**Fix:** Add `defer crypto.ZeroBytes(key)` to both functions.

**Effort:** 2 lines.

### H2. `make test` without `-race`

**File:** `Makefile`

Project uses `sync.RWMutex`, `atomic.Pointer`, goroutines in runner — all concurrent patterns. Tests run without `-race`, so data races go undetected.

**Risk:** Subtle race conditions in production under concurrent access.

**Fix:** Change `go test ./... -v` to `go test -race ./... -v` in `make test` and CI.

**Effort:** 1 line.

### H3. Unlock always loads ALL encrypted secrets

**File:** `internal/vault/unlock.go:64`

`GetAllSecrets` is called before checking `verify_data`. For vaults with thousands of secrets, this is an unnecessary load of all encrypted blobs.

**Risk:** Performance degradation + unnecessary exposure of encrypted data during unlock.

**Fix:** Check `verify_data` first. Only call `GetAllSecrets` as fallback when `verify_data` is absent.

**Effort:** ~15 lines.

---

## MEDIUM — 5 issues

### M1. `string(v)` creates immortal copies of secrets

**Files:** `runner/runner.go:176`, `runner/expand.go:31`

Go strings are immutable and cannot be zeroed. These string conversions persist in heap until GC.

- `runner.go:176`: `fmt.Sprintf("%s=%s", k, string(v))` — unavoidable for env vars (OS requires strings).
- `expand.go:31`: `string(env[name])` — occurs in pattern struct even when `ExpandArgs` is false (but `ExpandEnvVars` is only called when needed, so impact is limited).

**Fix:** Minimize `string()` conversions. For env vars — unavoidable. For expand — already gated behind `ExpandArgs`, acceptable.

**Effort:** Documentation only.

### M2. N+1 decrypt in GetSecretsByTagValues

**File:** `internal/vault/tags.go:90-103`

Loops through names, calls `GetSecret` per name — N separate store queries + N decrypts + N unzeroed key copies (compounds H1).

**Fix:** Use `GetAllSecrets` + filter by names. One query, one key copy (zeroed once).

**Effort:** ~15 lines.

### M3. SetMeta errors silently swallowed in failUnlock

**File:** `internal/vault/unlock.go:107-123`

All `SetMeta` calls use `_ =`, so if metadata can't be persisted (disk full, permissions), brute-force protection is bypassed.

**Risk:** Rate-limiting can be circumvented if disk writes fail.

**Fix:** Return error from `failUnlock` wrapping the SetMeta failure, or at minimum log to stderr.

**Effort:** ~5 lines.

### M4. Duplicate zeroBytes in runner and crypto

**Files:** `runner/runner.go:199-203`, `crypto/aesgcm.go:114-119`

Identical functions. If one changes, the other may be forgotten.

**Fix:** Remove from runner, use `crypto.ZeroBytes` everywhere.

**Effort:** 3 lines.

### M5. Fragile manual flag parsing in args.go

**Files:** `cli/args.go`, `cli/root.go`

`parseGlobalFlagsFromArgs` manually mirrors cobra flags. Adding a new global flag requires updating two places. Comment warns about this, but it's still a risk.

**Fix:** Extract flag definitions into a shared structure, or use cobra's partial parsing for pre-`--` args.

**Effort:** ~40 lines.

---

## LOW — 4 issues

### L1. Deprecated KeyToBufferV2 with hardcoded salt

**File:** `crypto/aesgcm.go:100-103`

Kept for backward compatibility. New vaults use `KeyToBufferV2WithSalt`. Not a bug, but should have a removal timeline.

### L2. maxSecretValueLen = 4096 may be too small

TLS certificates and SSH keys can exceed 4096 bytes. Consider increasing to 32768 or making configurable.

### L3. Incomplete output test coverage

Untested: `ScanResults()`, `EnvList()`, `EnvListWriter()`, `VersionInfo()`, `EnvironmentList()`.

### L4. Incomplete integration test coverage

Missing tests for: `update`, `completion`, `migrate`, `--global`, `--env`, exec-pattern with `--tag`, `--expand-args`.

---

## Remediation Plan (ordered by priority)

| Step | Issue | Files | Effort |
|------|-------|-------|--------|
| 1 | H1: Zero key copies | `vault/secrets.go` | 2 lines |
| 2 | H2: Add -race to make test | `Makefile` | 1 line |
| 3 | H3: Lazy-load secrets in Unlock | `vault/unlock.go` | ~15 lines |
| 4 | M3: Handle SetMeta errors in failUnlock | `vault/unlock.go` | ~5 lines |
| 5 | M2: Refactor GetSecretsByTagValues | `vault/tags.go` | ~15 lines |
| 6 | M4: Deduplicate zeroBytes | `runner/runner.go` | 3 lines |
| 7 | M5: Unify flag parsing | `cli/args.go`, `cli/root.go` | ~40 lines |
| 8 | L3: Add output tests | `output/output_test.go` | ~80 lines |
| 9 | L4: Add integration tests | `tests/integration_test.go` | ~150 lines |

### Acceptance Criteria

- All fixes pass `make test` (with `-race`)
- All fixes pass `make lint`
- No regression in existing tests
- Each step is independently committable

### Out of Scope

- L1 (deprecated KDF removal) — requires migration plan
- L2 (max value length increase) — requires design decision
- M1 (string conversions in env vars) — unavoidable OS limitation

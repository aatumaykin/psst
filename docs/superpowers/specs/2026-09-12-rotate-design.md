# `psst rotate` — Password / Salt Rotation (Phase 4) Design

Date: 2026-09-12
Status: draft (pending subagent review)
Scope: implements the recorded direction of master spec §5 (`docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md`): key rotation for git-storage vaults. Git storage only; SQLite vaults keep the documented manual procedure (new vault + `migrate storage`).

## Problem

Changing the shared password with the same salt gains nothing against attackers holding ciphertext (offline guessing is unbounded). Real rotation = **new salt + re-encryption of every `.enc` file + updated `psst.yaml` as ONE atomic commit**. Because the salt pin (§1.1) is strict, every other machine must adopt the rotation explicitly — the pin fires, there is no silent adoption. Master spec §5 named the acceptance command `psst sync --accept-rotation`; this spec fixes the full contract.

## Decisions (brainstorm, approved by maintainer)

| Decision | Choice |
|---|---|
| New-password input | TTY: `New password:` + `Confirm:` prompts (mismatch/empty → abort); scripting: `--stdin` reads the new password as one line. The OLD password flows through the existing unlock path (`PSST_PASSWORD` or TTY prompt) |
| Acceptance UX | `psst rotate` on one machine; `psst sync --accept-rotation` on every other (master spec's example); fresh clone remains an alternative |
| Scope | Git storage only (`psst rotate`/`sync` on SQLite → existing git-only errors) |
| KDF params | Preserved by rotation (strengthening stays a separate `psst migrate kdf`); a rotation commit carrying weaker params than the local pin is rejected on acceptance |
| Same old/new password | Allowed — salt rotation alone is the security operation; the summary notes `password unchanged` |
| Server invalidation | No new mechanism: the phase-2 salt-change mapping already closes all UI unlocks (500); after `sync --accept-rotation` on the server host, the server self-heals via the §3.2 recovery without restart |

## 1. `psst rotate`

```
psst rotate [--stdin]
```

- Requires git storage (SQLite → error pointing at `psst migrate storage --to git`), vault present (exit 3 path as usual), unlock with the OLD password (`PSST_PASSWORD` or prompt; exit 5 on failure).
- **Pre-flight decrypt of every current value** (fail-closed before any mutation): if any secret fails to decrypt under the old key → `rotate aborted: secret <NAME> is undecryptable under the current key`, exit 1, nothing staged, nothing committed. An empty vault rotates trivially (salt + `psst.yaml` only).
- New password: interactive `New password:` / `Confirm:` via `term.ReadPassword` (both hidden; mismatch or empty → abort); with `--stdin`, one line from stdin (trailing newline stripped; empty → abort). In a non-TTY without `--stdin` → error with the `--stdin` hint.
- New salt: 16 bytes `crypto/rand` → base64. New key = `DeriveKeyFromPassword(newPassword, newSalt, <current params>)`; new AAD = `psst:v1:argon2id:<newSaltB64>`.
- **One atomic `ExecTx`**: for every secret — decrypt with the old key, encrypt with the new key + new AAD, `store.SetSecret` (tags preserved; file moves follow tag dirs as usual); then `store.RotateSalt(newSaltB64)` rewrites `psst.yaml` and stages it. Exactly one commit lands: `psst: rotate`. Push failure → the existing phase-1 semantics (change is local; `psst sync` hint).
- After success: the rotating machine re-pins itself (new salt + params written to `.psst/config.yaml` through the existing config helpers) and prints `✓ Rotated: N secrets re-encrypted, new salt pinned`. `N=0` prints the empty-vault variant.

## 2. `psst sync --accept-rotation`

- `--accept-rotation` and `--discard-local` are mutually exclusive → flag-parse error.
- Sequence on an un-accepted clone (its pin fired with `vault salt changed` on any command):
  1. **Tolerant pull** (new store method, see §4): `git pull --rebase --autostash` under the repo lock; rebase conflict → the usual `ErrConflict` error; then re-read `psst.yaml` from disk. The new meta must pass strict validation and its KDF params must be equal-or-stronger than the local pin (weaker/mixed → reject: a rotation must not smuggle in a parameter downgrade).
  2. **Password + probe**: the NEW password via `PSST_PASSWORD` or a single TTY prompt (no confirmation — this is verification, not setting). Derive the key from the new meta, decrypt-probe one secret (the first by `ListSecrets`); failure → `wrong password or undecryptable secret <NAME>` exit 1, **pin unchanged** (the clone stays in the refused state; retry with the right password). An empty vault accepts without a probe (documented residual, mirroring serve unlock).
  3. **Re-pin**: write the new salt + params to the local config; print `✓ Rotation accepted`. The clone is immediately usable with the new password.
- Running `--accept-rotation` with no rotation pending is a harmless no-op success (pull + verify current password + re-pin the same values).

## 3. Error UX and integration

- The generic un-accepted-clone error (every vault command via `InitSchema`) gains the actionable suffix: `vault metadata changed since last open: vault salt changed; run 'psst sync --accept-rotation' (or re-clone)`. One-line change in the CLI error formatting; the store sentinel `ErrSaltChanged` is untouched.
- **History**: pre-rotation versions are old-salt ciphertext — rollback onto them fails closed with the existing `version N predates a KDF migration` (phase 1). Documented; no code change.
- **serve (phase 2)**: already maps `ErrSaltChanged` → 500 + close-all unlocks. After `sync --accept-rotation` runs on the server host, the next store operation trips `ErrRemoteMetaChanged` → the §3.2 recovery refreshes the cache against the now-matching pin → subsequent unlocks derive the new key. No server restart. (Property of the phase-2 per-call `loadPins` fix.)

## 4. Interface changes (complete list)

1. `internal/store/git.go` — two additive methods:
   - `func (g *GitStore) RotateSalt(saltB64 string) error` — validates base64/16 bytes, updates the in-memory meta salt, rewrites `psst.yaml`, `git add psst.yaml`, `markDirty`; MUST be called inside an open `ExecTx` (error `rotate salt must run inside a transaction` otherwise). Salt immutability elsewhere is untouched — `SetMeta` still refuses `kdf_salt`.
   - `func (g *GitStore) SyncAcceptRotation() (*VaultMeta, error)` — lock, tolerant pull (rebase conflict → `ErrConflict`), strict-parse `psst.yaml` from disk, enforce equal-or-stronger params vs `g.opts.LoadPins()`, install the new meta into the in-memory cache, return it. Never touches pins itself (the CLI re-pins after the password probe).
2. `internal/vault/vault.go` — `func (v *Vault) Rotate(newPassword string) error`: pre-flight decrypt-all (fail-closed); mint the new salt/key/AAD (same KDF params); one `ExecTx` re-encrypting every secret and calling `store.RotateSalt`; on success swap `v.key`/`v.aad` and refresh `SetUnlockedFingerprint`. Zeroing rules unchanged (`Vault.Close`).
3. `internal/cli/rotate.go` — the command (flags `--stdin`; git-only gate; prompt/confirm or stdin for the new password; post-success self re-pin via `LoadVaultConfig`/`SaveVaultConfig`).
4. `internal/cli/sync.go` — `--accept-rotation` branch: mutual exclusion with `--discard-local`, `SyncAcceptRotation`, probe through a one-shot vault (`keyring.NewPasswordProvider(enc, true)` + `vault.New` + `Unlock` + `GetSecret`), re-pin, success message.
5. CLI error-formatting touch: the salt-changed hint names `psst sync --accept-rotation` (§3).
6. Documentation: `docs/rules/security.md` gains a Rotation section (procedure replaces the manual one); `README.md` + `docs/ru/README.md` rotate sections.
7. No `SecretStore` interface changes; no new dependencies.

## 5. Security review points

- The rotation commit is atomic: other machines observe old-or-new, never mixed ciphertext/salt. The transient on-disk mixed state exists only in the rotating machine's working tree inside the tx.
- Acceptance requires proving knowledge of the NEW password (decrypt probe) BEFORE the pin moves — a wrong password leaves the clone refused, never silently re-pinned.
- Weaker-params smuggling through a rotation is rejected at acceptance (monotonic rule reused).
- No plaintext handling changes: values exist in memory during re-encryption only; nothing logged; commit messages carry no secrets.
- `psst rotate` never rewrites remote history; old commits (old-key ciphertext) remain reachable via git but are fail-closed for rollback.

## 6. Testing

Real temporary git repos (bare remote pattern), fake values only, `PSST_NO_KEYCHAIN=1` (`make test`).

- Rotate happy path (store/vault level): two tagged secrets; `Rotate("new-password")` → exactly ONE new commit; every value/tag round-trips under the new password; `psst.yaml` salt changed; params unchanged.
- Old-key death: after rotation, deriving with the old password fails to decrypt (AAD/salt binding).
- Pre-flight abort: seed an undecryptable secret (raw garbage as ciphertext via store-level `SetSecret`); `Rotate` errors naming it; commit count unchanged; salt unchanged.
- Empty vault rotation: one commit, new salt.
- Second-clone flow (integration, binary): machine A rotates + pushes; machine B (existing clone) → any command exits with the `accept-rotation` hint; `sync --accept-rotation` with wrong password → exit 1, pin unchanged (still hinting); with the right password → success; CRUD works under the new password; rollback onto a pre-rotation version → fail-closed message.
- No-rotation-pending accept → no-op success.
- `--accept-rotation` + `--discard-local` → flag error.
- Push failure during rotate (read-only remote) → existing hint; remote untouched.
- Rotation carrying weaker params (hand-crafted second-store commit) → acceptance rejects; equal/stronger accepted.
- rotate on SQLite vault → git-only error.
- serve self-heal (optional, one test): rotate behind a running server's back, accept on its host, next op → 409 reunlock once, then unlock with the new password succeeds.

## 7. Non-goals

- No scheduled/automatic rotation; no password strength policy.
- No rotation for SQLite vaults (manual procedure stays documented).
- No history rewriting or pruning of old-key commits.
- No params strengthening inside rotate (`psst migrate kdf` remains the tool).

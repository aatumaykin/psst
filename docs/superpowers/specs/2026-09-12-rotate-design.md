# `psst rotate` — Password / Salt Rotation (Phase 4) Design

Date: 2026-09-12
Status: reviewed — round 1: 2 critical / 3 major / 6 minor / 3 nit, all addressed (pin-less probe store, in-tx set derivation, ExecTxMsg, unpushed-commit refusal at accept, abort recovery, serve self-heal wording, salt minting ownership, fingerprint refresh, empty-vault residual, hint scoping, zeroing pre-flight, test additions)

Scope: implements the recorded direction of master spec §5 (`docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md`): key rotation for git-storage vaults. Git storage only; SQLite vaults keep the documented manual procedure (new vault + `migrate storage`).

## Problem

Changing the shared password with the same salt gains nothing against attackers holding ciphertext (offline guessing is unbounded). Real rotation = **new salt + re-encryption of every `.enc` file + updated `psst.yaml` as ONE atomic commit**. Because the salt pin (§1.1) is strict, every other machine must adopt the rotation explicitly — the pin fires, there is no silent adoption. Master spec §5 named the acceptance command `psst sync --accept-rotation`; this spec fixes the full contract.

## Decisions (brainstorm, approved by maintainer)

| Decision | Choice |
|---|---|
| New-password input | TTY: `New password:` + `Confirm:` prompts (mismatch/empty → abort); scripting: `--stdin` reads the new password as one line. The OLD password flows through the existing unlock path (`PSST_PASSWORD` or TTY prompt) |
| Acceptance UX | `psst rotate` on one machine; `psst sync --accept-rotation` on every other (master spec's example); fresh clone remains an alternative |
| Scope | Git storage only (`psst rotate`/`sync` on SQLite → existing git-only errors); `vault.Rotate` itself hard-errors on a non-GitStore (defense in depth) |
| KDF params | Preserved by rotation (strengthening stays a separate `psst migrate kdf`); a rotation commit carrying weaker params than the local pin is rejected on acceptance |
| Same old/new password | Allowed — salt rotation alone is the security operation; the summary notes `password unchanged` |
| KDF params in rotate | Preserved by default; `--kdf` strengthens to defaults in the same commit (never weakens — hard error) |
| Server invalidation | No new mechanism: with a live unlock the phase-2 `ErrRemoteMetaChanged` 409 recovery closes all UI unlocks and refreshes the cache; with no unlock the next pull refreshes silently (worst case one 500 during the accept race, cache untouched then). After `sync --accept-rotation` on the server host, unlocks derive the new key — no restart |

## 1. `psst rotate`

```
psst rotate [--stdin] [--kdf]
```

- `--kdf`: strengthen the KDF parameters to `crypto.DefaultKDFParams()` IN THE SAME single commit as the salt/password rotation (one re-encryption pass instead of rotate + `migrate kdf`). Rotation never weakens: a target below the current params is a hard error at `Rotate` before anything is staged. Acceptance needs no change — `SyncAcceptRotation` already enforces equal-or-stronger vs the local pin. Defaults are the parse floor (`kdf_time` ≥ 3, `kdf_memory` ≥ 65536), so on a valid fresh vault `--kdf` is a params no-op (the salt still rotates), and on a vault already strengthened above defaults (e.g. `kdf_time: 4`) targeting defaults is itself a weakening attempt → the same hard error, fail-closed.

- Requires git storage (SQLite → error pointing at `psst migrate storage --to git`), vault present (exit 3 path as usual), unlock with the OLD password (`PSST_PASSWORD` or prompt; exit 5 on failure).
- New password: interactive `New password:` / `Confirm:` via `term.ReadPassword` (both hidden; mismatch or empty → abort); with `--stdin`, one line from stdin (trailing newline stripped; empty → abort). Non-TTY without `--stdin` → error with the `--stdin` hint. The CLI collects ONLY the new password (and, with `--kdf`, the target params) — salt/key/AAD are minted inside `vault.Rotate` (§4.2).
- **Salt/key minting and the whole rotation live in `vault.Rotate` (§4.2)**; the CLI calls it and then self re-pins.
- **Pre-flight is a UX pre-check only.** It iterates store-level ciphertext (`store.GetAllSecrets()`), decrypts each entry with the old key, verifies, and zeroes the plaintext buffer immediately — a full plaintext map is never materialized. Any failure → `rotate aborted: secret <NAME> is undecryptable under the current key`, exit 1, nothing staged. **The authoritative set is (re)derived INSIDE the transaction as its first statement** (post-pull working tree; `SyncPullRead` no-ops at `txDepth > 0`): any secret that arrived with the in-tx pull is part of the rotation, and any decrypt failure inside the tx aborts fail-closed. On a non-empty vault a wrong OLD password dies at the pre-flight; on an **empty vault the old password cannot be verified** (documented residual — same class as serve's empty-vault unlock; the summary notes `password not verified: vault is empty`).
- An empty vault rotates trivially (salt + `psst.yaml` only) in one commit.
- **Abort/recovery**: if the `ExecTx` fails midway (disk error, commit failure), the remote and history stay clean — the rotation never pushed. The working tree may hold staged new-key files; the abort error text ends with: `working tree may be dirty; run 'psst sync --discard-local' to reset to the remote (pre-rotation) state`. (`--discard-local` resets to upstream and drops OTHER unpushed local commits too — values remain in the reflog; the caveat is stated in the message docs.)
- After success: the rotating machine re-pins itself (new salt + params via the config helpers; a failed re-pin is recoverable by running `psst sync --accept-rotation` on the rotating machine itself) and prints `✓ Rotated: N secrets re-encrypted, new salt pinned`.

## 2. `psst sync --accept-rotation`

- `--accept-rotation` and `--discard-local` are mutually exclusive → flag-parse error.
- **Refusal on unpushed local commits**: before any pull, if the clone is ahead of `@{upstream}` (the `status -sb` `[ahead N]` marker — not merely behind the tracking ref, which a bare `git fetch` can produce; `psst sync` fast-forwards that away), acceptance refuses: `cannot accept rotation with unpushed local commits; run 'psst sync' first to push them, or 'psst sync --discard-local' to drop them (reflog retains values), then retry`. Rebasing old-key commits onto the rotation commit would produce a permanently mixed vault (old-key ciphertext under a new salt that no machine can decrypt and no later sync can repair, because the pin check blocks the push). A clone with no upstream at all (local-only git vault) mirrors `psst sync`: warning `working locally, no remote configured` and the accept is a no-op — nothing to pull, nothing to accept.
- Sequence on an accepted clone:
  1. **Tolerant pull** — `store.SyncAcceptRotation()` (§4.1): repo lock, `git pull --rebase --autostash` (rebase conflict → the usual `ErrConflict`), strict-parse `psst.yaml` from disk, enforce equal-or-stronger KDF params vs the local pin (weaker/mixed → reject: rotation must not smuggle a parameter downgrade), install the new meta into the in-memory cache, return it.
  2. **Password + probe on a pin-less store**: the still-old on-disk pin would fire inside any pull-backed read on the main store (`GetSecret` → `reloadMetaAndCheck` → `CheckPinned` → `ErrSaltChanged`), so the probe runs on a **separate `store.NewGitStore(repoDir, GitOptions{})` with nil pins** over the same repo dir (repo `flock` serializes it against the main store). The NEW password comes from `PSST_PASSWORD` (at accept time it must hold the password valid AFTER the command — the new one when a rotation is pending, the current one in the no-op case) or a single TTY prompt. Build a one-shot vault on the pin-less store, `Unlock`, decrypt-probe one secret (the first by `ListSecrets`); failure → `wrong password or undecryptable secret <NAME>` exit 1, **pin unchanged** (retryable). An empty vault accepts without a probe (documented residual). Close the pin-less store.
  3. **Re-pin**: write the new salt + params to the local config; print `✓ Rotation accepted`. The clone is immediately usable with the new password.
- Running `--accept-rotation` with no rotation pending is a harmless no-op success (pull + verify the current password + re-pin the same values).

## 3. Error UX and integration

- The un-accepted-clone hint is scoped to `ErrSaltChanged` ONLY: `vault salt changed; run 'psst sync --accept-rotation' (or re-clone)`. `ErrKDFWeakened` keeps a docs-pointer message (tampering; acceptance cannot fix it — it rejects weaker params). The current doubled prefix (`vault metadata changed since last open: vault metadata changed since last open: …` — InitSchema wraps, root.go wraps again) is collapsed to a single prefix in the same change.
- **History**: pre-rotation versions are old-salt ciphertext — rollback onto them fails closed with the existing `version N predates a KDF migration` (phase 1). Documented; no code change.
- **serve (phase 2)**: with a live session unlock, the next store operation trips `ErrRemoteMetaChanged` → 409 + the §3.2 recovery closes ALL unlocks and refreshes the cache against the now-matching pin → subsequent unlocks derive the new key. With no live unlock the pull-backed read refreshes the cache silently (worst case: one 500 during the accept race, cache untouched until the next request retries). No server restart. (Property of the phase-2 per-call `loadPins` fix.)

## 4. Interface changes (complete list)

1. `internal/store/git.go` — three additive methods:
   - `func (g *GitStore) ExecTxMsg(msg string, fn func() error) error` — the existing `ExecTx` machinery with a caller-supplied commit message; `ExecTx` becomes `ExecTxMsg("psst: batch", fn)`. Needed because the tx path commits with a fixed message today.
   - `func (g *GitStore) RotateSalt(saltB64 string) error` — validates base64/16 bytes, updates the in-memory meta salt, rewrites `psst.yaml`, `git add psst.yaml`, `markDirty`; MUST be called inside an open transaction (error `rotate salt must run inside a transaction` otherwise). Salt immutability elsewhere is untouched — `SetMeta` still refuses `kdf_salt`.
   - `func (g *GitStore) SyncAcceptRotation() (*VaultMeta, error)` — §2 step 1. Never touches pins (the CLI re-pins after the probe).
2. `internal/vault/vault.go` — two methods:
   - `func (v *Vault) VerifyAllDecryptable() error` — the pre-flight: iterates store-level ciphertext, decrypts each entry with the current key, zeroes the plaintext buffer, fails naming the first undecryptable secret.
   - `func (v *Vault) Rotate(newPassword string, params *kdf.Params) (int, error)` — returns the number of re-encrypted secrets (for the summary line); `params == nil` preserves the current params (all pre-existing callers), non-nil uses the given target and hard-errors if any field is below the current params (`rotation must not weaken KDF parameters`):
     - Non-GitStore store → hard error `rotate requires git storage` (defense in depth under the CLI gate).
   - Mints the new salt (16 bytes `crypto/rand` → base64), derives the new key (`DeriveKeyFromPassword(newPassword, newSalt, <target params: current when nil>)`) and new AAD (`psst:v1:argon2id:<newSaltB64>`); KDF params are preserved unless a non-nil target is given.
   - Wraps everything in `ExecTxMsg("psst: rotate", …)` whose **first statement re-derives the authoritative secret set** from the post-pull working tree (store-level ciphertext), then per secret: decrypt with the old key (failure → fail-closed abort; recovery §1), encrypt with the new key + new AAD, `store.SetSecret` (tags preserved); a non-nil target stages the params via the existing `SetMeta` (self-wrapped in `mutate`, which at `txDepth > 0` runs the op only — both writes land in the ONE commit, zero store changes); finally `store.RotateSalt(newSaltB64)` rewrites `psst.yaml` from the in-memory meta (new params + new salt).
   - On failure, zeroes the derived new-key material and the new password buffer (mirroring `Vault.Close`); on success swaps `v.key`/`v.aad` and immediately calls `SetUnlockedFingerprint(gs.FingerprintOfCurrent())` (the in-memory meta already holds the new salt) — a post-rotate write in the same process must not trip `ErrRemoteMetaChanged`.
3. `internal/cli/rotate.go` — the command (flags `--stdin`; git-only gate; prompt/confirm or stdin for the new password; calls `v.Rotate`; post-success self re-pin via `LoadVaultConfig`/`SaveVaultConfig`).
4. `internal/cli/sync.go` — `--accept-rotation` branch: mutual exclusion with `--discard-local`; unpushed-commit refusal; `SyncAcceptRotation`; pin-less probe store + one-shot vault (§2 step 2); re-pin; success message.
5. CLI error formatting: the `ErrSaltChanged`-scoped hint with a single prefix (§3).
6. Documentation: `docs/rules/security.md` gains a Rotation section (procedure replaces the manual one); `README.md` + `docs/ru/README.md` rotate sections.
7. No `SecretStore` interface changes; no new dependencies (`golang.org/x/term` already in `go.mod`).

## 5. Security review points

- The rotation commit is atomic: other machines observe old-or-new, never mixed ciphertext/salt in history. The mixed on-disk working-tree state exists only inside the tx — or after a failed tx, where recovery is `psst sync --discard-local` (the rotation never pushed; upstream IS the pre-rotation state), named in the abort error.
- The in-tx set re-derivation closes the pre-flight/pull gap: a secret arriving with the transaction's own pull is rotated too; nothing lands old-key under the new salt.
- Acceptance requires proving knowledge of the NEW password (decrypt probe on a pin-less store) BEFORE the pin moves — a wrong password leaves the clone refused, never silently re-pinned. Unpushed local commits block acceptance outright.
- Weaker-params smuggling through a rotation is rejected at acceptance (monotonic rule reused).
- No plaintext-map retention: pre-flight and rotation process one secret at a time, zeroing buffers; nothing logged; commit messages carry no secrets.
- Empty-vault residual: the old password is unverifiable when no secrets exist (rotate) and the new one when the vault is empty (accept) — documented, bounded (no data exists to lose).
- `psst rotate` never rewrites remote history; old commits (old-key ciphertext) remain reachable via git but are fail-closed for rollback.

## 6. Testing

Real temporary git repos (bare remote pattern), fake values only, `PSST_NO_KEYCHAIN=1` (`make test`).

- Rotate happy path (store/vault level): two tagged secrets; `Rotate("new-password", nil)` → exactly ONE new commit with subject `psst: rotate`; every value/tag round-trips under the new password; `psst.yaml` salt changed; params unchanged; a follow-up write in the same process succeeds (fingerprint freshness — the store/vault-level tests build stores with `GitOptions{}` nil pins, or run the re-pin first: with production pins the write trips `ErrSaltChanged` until re-pinned, which is the specified behavior, not a failure).
- `--kdf` rotation (reshaped — defaults ARE the parse floor, so a valid vault can never sit below them): (i) strengthen: `Rotate("new-password", &{time:4})` on a defaults vault → `psst.yaml` shows `kdf_time: 4`, values re-encrypted under the time=4-derived key, ONE commit, round-trip under the new password, second-clone `sync --accept-rotation` succeeds; (ii) weaken: after strengthening to `time=4`, a target below current (`&{time:3}` — i.e. defaults) → hard error `rotation must not weaken KDF parameters` BEFORE anything is staged (salt and commit count unchanged, vault still readable); (iii) `nil` preserves params (existing rotate tests). CLI integration: `rotate --stdin --kdf` on a fresh vault covers the reachable end-to-end path — a params no-op (defaults equal the initial params) with success + round-trip under the new password and `psst.yaml` still parsing at defaults while the salt rotates; `--kdf` on a vault above defaults → the fail-closed hard error (covered at vault level by (ii)).
- Old-key death: after rotation, deriving with the old password fails to decrypt (AAD/salt binding).
- Pre-flight abort: seed an undecryptable secret (raw garbage as ciphertext via store-level `SetSecret`); `Rotate` errors naming it; commit count unchanged; salt unchanged.
- **In-tx arrival**: seed a second store, and between the pre-flight and the tx (via a store hook or by pre-arranging the remote push) land a new secret; assert the rotation commit re-encrypts it too (decryptable under the new password). Implementable deterministically: push the extra secret from clone B AFTER clone A's pre-flight reads but before A's `Rotate` tx pull — or by injecting through `ExecTxMsg` ordering in a unit-style test.
- Empty vault rotation: one commit, new salt; wrong old password silently accepted (residual documented — assert the `password not verified` summary path).
- Second-clone flow (integration, binary): machine A rotates + pushes; machine B (existing clone) → any command exits with the `accept-rotation` hint; `sync --accept-rotation` with wrong password → exit 1, pin unchanged (still hinting); with the right password → success; CRUD works under the new password; rollback onto a pre-rotation version → fail-closed message.
- **Offline-write refusal**: machine B has an unpushed local commit → accept refuses with the recovery message; after `sync` (push) or `--discard-local`, accept succeeds.
- New-password aborts: confirmation mismatch (TTY test helper), empty `--stdin` value.
- No-rotation-pending accept → no-op success.
- `--accept-rotation` + `--discard-local` → flag error.
- Push failure during rotate (read-only remote) → existing hint; remote untouched; abort error mentions `--discard-local` recovery.
- Rotation carrying weaker params (hand-crafted second-store commit) → acceptance rejects; equal/stronger accepted.
- rotate on SQLite vault → git-only error.
- serve self-heal: server with a live unlock; rotate behind its back (second store); accept on the server host; next op → 409 reunlock once; unlock with the new password succeeds.

## 7. Non-goals

- No scheduled/automatic rotation; no password strength policy.
- No rotation for SQLite vaults (manual procedure stays documented).
- No history rewriting or pruning of old-key commits.
- No params strengthening inside rotate beyond the `--kdf`-to-defaults path (`psst migrate kdf` remains the legacy-KDF upgrade tool; explicit above-defaults targets are `vault.Rotate` API-only).

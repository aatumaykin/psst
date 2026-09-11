# Git Storage Backend, Web UI, and Secret Rendering — Design

Date: 2026-09-11
Status: approved in brainstorm; revised after three subagent review rounds (round 1: 1 critical / 13 major / 10 minor / 5 nit; round 2: 0 critical / 5 major / 9 minor / 2 nit; round 3 control: approve with changes — 0 critical / 2 major / 5 minor / 2 nit; all findings from all rounds addressed)
Scope: phased — phase 1 (GitStore) is this spec's implementation target; phases 2–3 recorded here as committed direction.

## Problem

1. psst stores secrets in a local SQLite vault. Synchronizing it across several LLM machines (symlinked DB in a repo, manual copy) is manual and fragile.
2. Proxy-based LLM secret-injection projects cover only HTTP traffic. SSH (login/password) and generated script/config files with literal placeholders are out of their reach.
3. Secret management across machines needs a UI, but running a full psst instance per machine is inconvenient.

## Decisions (from brainstorm)

| Decision | Choice |
|---|---|
| SQLite fate | GitStore as an option behind `SecretStore`; SQLite stays the default backend |
| Key distribution | Shared password: Argon2id + per-vault salt from the repo; **KDF parameters from `psst.yaml` are authoritative** for derivation (see 1.1) |
| Secret file format | `base64(IV ‖ AES-256-GCM ciphertext(value))` — value only; ciphertext bound to vault metadata via GCM AAD (see 1.1) |
| Grouping / tags | Subdirectories (`secrets/<tag>/NAME.enc`); exactly one tag per secret |
| Dates | From git log (`--diff-filter=A` for created, last commit for updated); nothing stored in files |
| Sync on unreachable remote | Reads: best-effort pull, work from local clone. Writes: strict pull --rebase → commit → push |
| Web server role | UI only; CLI machines talk to git directly, never to the server |
| Web server auth | localhost bind + mandatory token; vault password unlock in UI; SSH tunnel for remote |
| Substitution (idea 2) | New `psst render` command; env injection already covers subprocess cases |
| Git driver | System `git` via `os/exec`; no new dependencies |
| Key provider for git storage | Password-only derivation via a typed method that cannot hit the base64 passthrough (see 1.4) |
| Migration command | `psst migrate storage --to git` (subcommand; bare `psst migrate` keeps KDF semantics, `psst migrate kdf` added) |

Accepted trade-offs:

- Secret **names** are visible in the repo (file names), values never — same model as `pass`.
- No multi-tag secrets in git backend (a file lives in one directory). SQLite keeps multi-tag JSON. Multi-tag requests against a git vault fail closed at CLI validation.
- Ciphertext conflicts on the same key are not auto-merged (fail-closed), with an explicit recovery command (see 1.3).
- Writes carry an O(history-of-file) cost for version numbering (see 1.2, History).

## 1. Git Storage Backend (phase 1)

### 1.1 Repository layout

```
<vault-repo>/
├── psst.yaml                  # plaintext vault metadata (not secret)
└── secrets/
    ├── OPENAI_API_KEY.enc     # untagged secret
    ├── prod/                  # "tag" = subdirectory
    │   ├── DB_PASS.enc
    │   └── DB_USER.enc
    └── test/
        └── STRIPE_TEST.enc
```

`psst.yaml`:

```yaml
version: 1
kdf:
  algo: argon2id
  time: 3                      # iterations; memory is in KiB
  memory: 65536                # 64 MiB
  threads: 4
salt: <base64>                 # per-vault salt
cipher: aes-256-gcm
```

These defaults match the constants currently compiled into `internal/crypto/aesgcm.go` (`argon2Iterations=3`, `argon2Memory=64*1024` KiB, `argon2Threads=4`), so a git vault initialized today derives the same key as an existing v2+salt SQLite vault for the same password.

**Authoritative KDF parameters.** Today `KeyToBufferV2WithSalt` ignores any external parameters — they are compile-time constants. For git vaults this would make `psst.yaml` decorative and risk cross-version key skew. Phase 1 adds a parameterized derivation method to the `Encryptor`/`KeyDeriver` interfaces (see Interface changes below): `DeriveKeyFromPassword(password string, salt []byte, params KDFParams) ([]byte, error)` — always Argon2id, **no base64 passthrough** (the existing `KeyToBufferV2WithSalt` returns a 32-byte-decodable base64 string as the key directly, which would let a password-shaped-as-base64 skip the KDF entirely; git vaults must never use that path). `vault.Unlock()` on a git vault reads salt and parameters from `psst.yaml` and calls this method. Same password + same salt + same params ⇒ same key on every machine.

**AAD binding.** Each `.enc` file is encrypted with GCM additional authenticated data `psst:v1:<kdf-algo>:<salt-base64>`. This binds every ciphertext to the vault's format version, KDF algorithm, and salt: files from another vault/salt fail authentication with an explainable error, and future format changes have a migration point. The current `Encryptor` interface has no AAD parameter (`gcm.Seal(..., nil)`), so phase 1 extends it with `EncryptWithAAD(plaintext, key, aad)` / `DecryptWithAAD(ciphertext, iv, key, aad)`; the old `Encrypt`/`Decrypt` delegate to them with nil AAD. The vault layer composes the AAD from store metadata (`GetMeta`) — the store itself never touches crypto (architecture rule: no `store → crypto` dependency). The SQLite backend keeps nil AAD in phase 1 (existing ciphertext stays readable); it may adopt AAD in a later migration.

**Validation (fail-closed).** `psst.yaml` is untrusted input (it lives in a synced repo; GCM authenticates secret values, not vault metadata). On open GitStore validates:

- Required fields present; `version == 1`, `cipher == aes-256-gcm`, `kdf.algo == argon2id` — anything else is a hard error, no fallback.
- KDF minimums: `memory >= 64 MiB` (65536 KiB), `time >= 3`, `threads >= 1`. Weaker parameters are rejected (blocks parameter-downgrade attacks by someone with write access to the remote).
- Salt must be valid base64, 16+ bytes.
- Empty password is rejected at init and unlock.

**Immutability policy — split by field.**

- **Salt: strictly immutable.** If the salt differs from the one pinned in the local vault config for a previously opened repo → hard error pointing at the rotation procedure (section 5). No flag accepts a salt change in place.
- **KDF parameters (`time`/`memory`/`threads`): monotonic strengthening only.** If parameters differ from the local pin: strictly stronger (any parameter increased, none decreased) → accept with a notice and update the pin — this is the legitimate `psst migrate kdf` path (1.4); equal → no-op; anything weaker or mixed → hard error. Without a pin (first open / re-clone) → trust and pin (TOFU).

**Pinning mechanism.** The per-env local config (`.psst/config.yaml`, alongside the clone — see 1.4) records `salt`, `kdf params`, and `remote` after the first successful open. A re-clone resets the pin (TOFU); the pin protects continuity against in-repo tampering, not against a first-time attacker who controls the remote — HTTPS/SSH transports and the KDF minimums above are the defense there.

**Remote schemes — exhaustive allowlist.** `ssh://`, `https://`, `git@…` (SSH), and filesystem paths to bare repos are allowed. `http://` is rejected unless the user passes an explicit `--allow-insecure-remote`. `git://` and every other plaintext transport are always rejected, no exceptions.

### 1.2 GitStore (`internal/store/git.go`)

Implements the **full** existing `SecretStore` interface (`internal/store/store.go` — 14 methods):

| Interface method | GitStore behavior |
|---|---|
| `InitSchema` | Idempotent (called on every command by `getUnlockedVault`), **strictly non-destructive**: repo dir exists and `psst.yaml` is valid → no-op; repo dir exists but `psst.yaml` is missing or invalid → **hard error** (never regenerate — regenerating would mint a new salt and make every existing `.enc` permanently undecryptable). A new `psst.yaml` is written only when initializing a brand-new vault: `git init` for a local-only repo; `psst init --storage git --remote <url>` cloning an **empty** remote (the main onboarding case: clone → mint salt → write `psst.yaml` → initial commit → push); or clone where `psst.yaml` arrives from the remote and is never overwritten. Outside of `init`, an existing repo dir with a missing or invalid `psst.yaml` is always a hard error |
| `GetSecret` | read + decode file `secrets/[tag/]NAME.enc` |
| `GetAllSecrets` | read + decode every file (used by `run`, `scan`, `export`) |
| `SetSecret` | write file → `git add <exact path>` → commit → push (inside an `ExecTx` batch when one is open — see below) |
| `DeleteSecret` | `git rm <path>` + commit + push |
| `DeleteHistory` | no-op: history lives in commits; deleting history would rewrite shared history — forbidden |
| `ListSecrets` | walk `secrets/` tree; tag = directory name |
| `GetHistory` | `git log --follow -- <file>` + `git show <rev>:<path>` per commit to load blobs. **Excludes the current (HEAD) value** — history is archived versions only, matching SQLite semantics; the current value becomes history automatically when the next change lands (its commit joins the log). `Version` = 1-based ordinal from oldest to newest (recomputed per call; oldest-based numbering is stable — existing entries keep their ordinals when new commits append). Result order is newest-first (DESC), matching SQLite. `ID` = 0 (unused by git). `ArchivedAt` = commit time; `Author` = commit author |
| `AddHistory` | no-op (git owns history) |
| `PruneHistory` | no-op (pruning would rewrite shared history — forbidden) |
| `ExecTx` | **Reentrant batch**: depth counter per store instance; the outermost call does pull → `fn` → commit + push, nested calls (e.g. from `vault.SetSecret`, which self-wraps today) only run `fn`. `import` and `migrate storage` wrap their whole loop in one outer `ExecTx` — N secrets become one pull/commit/push, not N |
| `GetMeta` | reads `psst.yaml`: `kdf_version` (always `2` for git vaults), `kdf_salt` (from `salt`), plus the KDF parameters needed by the vault layer to build the derivation call and AAD. Never returns empty `kdf_version` for a valid vault — a git vault missing these fields fails validation (1.1) instead of letting `vault.Unlock()` fall back to the v1 SHA-256 path |
| `SetMeta` | writes the corresponding `psst.yaml` fields (only `kdf_*` keys are honored) as part of a commit |
| `Close` | no-op |

**History cost.** `vault.SetSecret` calls `GetHistory` before writing (to number the archive version), so a write costs O(commits touching the file) `git show` invocations; `AddHistory` then discards the number (no-op). Phase 1 accepts this cost (histories of individual secrets are naturally small); if profiling ever shows pain, ordinal caching in the local config is the recorded fallback — not phase 1.

- `psst rollback NAME --to N` uses the **existing** `vault.Rollback` flow: it resolves version N from `GetHistory`, **decrypts the target blob with the current key, and writes the plaintext through the normal `SetSecret` path (re-encryption)** — historical ciphertext is never copied byte-for-byte, because a version that predates a KDF migration is encrypted under an old key and would become undecryptable for every machine. If the target blob fails to decrypt → fail-closed error "version N predates a KDF migration". The same re-encrypt step fixes a latent bug in the current SQLite flow (`MigrateKDF` re-encrypts only current values, leaving `secrets_history` under the old key; `Rollback` copies historical ciphertext as-is) — phase 1 fixes it for both backends. Remote history is never rewritten; no separate rollback path is added.
- `psst tag NAME T` = `git mv secrets/[old/]NAME.enc secrets/T/NAME.enc` + commit + push. Tag = replace: the secret always ends up with exactly `T` (moving out of any previous directory). The CLI routes `tag`/`untag` on git vaults to this move operation directly — the SQLite-era `vault.AddTag`/`RemoveTag` (append/remove within a JSON array) is not used. Multi-tag inputs fail closed: `set --tag a --tag b` and any code path handing GitStore more than one tag is a CLI validation error with an explicit message — never silently flattened.
- `psst untag NAME [TAG]` = `git mv secrets/T/NAME.enc secrets/NAME.enc` + commit + push. On a git vault the optional `TAG` argument (kept for parity with the SQLite form `untag <name> <tag>`) must equal the secret's single current tag; without it, the secret must be tagged, else error.
- **Path safety.** A cloned repo is untrusted input. Tag names must match `[a-z][a-z0-9-]*`; secret names must match the existing `validName` rule (`[A-Z][A-Z0-9_]*`). The `secrets/` walk ignores (and reports) any entry that does not match the shape `secrets/[TAG/]NAME.enc`; all paths are constructed only from validated components. Directory traversal (`..`, absolute names) from repo content can never reach the filesystem.

**Interface/type changes in phase 1** (complete list — there are four):

1. `store.HistoryEntry` / `vault.SecretHistoryEntry` gain `Author` (git: commit author; SQLite: empty).
2. `Encryptor` gains `EncryptWithAAD`/`DecryptWithAAD`; existing `Encrypt`/`Decrypt` delegate with nil AAD.
3. `KeyDeriver` gains `DeriveKeyFromPassword(password string, salt []byte, params KDFParams)` plus the exported `KDFParams` type (1.1).
4. `KeyProvider` gains a password-only derivation path used by git vaults (1.4).

### 1.3 Sync protocol

**Subprocess environment (every git call):**

- `-c core.hooksPath=/dev/null` — repo-hosted hooks never execute.
- `GIT_TERMINAL_PROMPT=0` — no interactive prompts; a hung CLI agent is impossible.
- `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL` pointing at an empty file — system/user gitconfig (`url.*.insteadOf` redirects, `core.sshCommand` overrides, `credential.helper=store`) cannot silently alter transport or leak credentials.
- `GIT_ASKPASS` / `SSH_ASKPASS` unset.
- Subcommand allowlist: `clone, init, config (local only), fetch, pull, add, rm, mv, commit, push, log, show, status` (`init`/`config` are needed by `InitSchema` and machine identity; `rebase --abort` is allowed for conflict cleanup). One documented exception for recovery: the `reset --hard @{upstream}` performed **only** by `psst sync --discard-local` (below). No `clean`, no filters/LFS.

**Identity**: on clone/init set local `user.name = psst/<hostname>`, `user.email = psst@<hostname>` — history shows which machine changed a secret.

**Process lock.** All git-mutating sequences (and the read-pull) hold an exclusive process lock on the clone (`flock` on `repo/.psst.lock`). Two processes on one machine — CLI+CLI, or CLI + `psst serve` from phase 2 — serialize instead of racing on `index.lock` and half-written files. Lock waits with a timeout and fails with a clear message.

**Reads** (`get/list/run/history`, plus `export`, `scan`, and the exec pattern `psst SEC -- cmd` — all other vault-opening commands follow the read or write protocol by their operation type: `import`/`migrate` are writes): best-effort sync, two distinct outcomes:

- Network failure → work silently from the local clone.
- Diverged (`pull --ff-only` rejected because the clone has unpushed local commits) → operate locally **but print a warning to stderr on every read command**: "local clone has unpushed changes; run `psst sync`". Stale reads must never be silent.

**Post-pull metadata check (stale-key window).** The vault is unlocked (key derived from `psst.yaml`) *before* any pull runs. If a remote KDF migration arrives with that pull, the process would encrypt and push old-key ciphertext over a repo with new parameters. Therefore: after **every** pull (read-pull and write step 1), GitStore re-reads `psst.yaml` and compares against what the vault was unlocked with; on any change it **aborts the operation** with "vault parameters changed remotely; re-run the command" (fail-closed; re-running re-opens the vault with fresh parameters). Re-deriving the key in place is deliberately not done — it would require crypto inside the store (forbidden by the layering rules).

**Writes** (`set/rm/tag/untag/rollback` — rollback resolves the version with a read but records via `SetSecret`, so it runs the full write protocol), under the lock:

1. `git pull --rebase --autostash` (a repo without a remote configured is tolerated — see below).
2. On rebase conflict (two machines changed the same key between syncs): `git rebase --abort`, fail with "key changed remotely; re-set the value or run `psst sync --discard-local`". No silent last-write-wins. The abort does not lose local commits — but the conflicting local commit stays on the branch and will conflict again, so:
3. Apply change, `git add <exact secret path>` (never `-A`; no stray files in commits), `git commit -m "psst: <op> <NAME>"`.
4. `git push`; on failure: error with hint ("change is in the local clone; run `psst sync` later"). If no remote/upstream is configured at all: warning "working locally, no remote configured", not an error (local-only git vault is a valid setup).

**`psst sync`**: explicit `git pull --rebase --autostash` + `git push` for offline recovery, under the lock. On rebase conflict it behaves exactly like a write: `rebase --abort` + the same error pointing at `--discard-local`.
**`psst sync --discard-local`**: recovery for the conflict deadlock — `git reset --hard @{upstream}` under the lock, dropping local unpushed psst commits. Prints what is being discarded and requires `--confirm` in non-interactive use. This is the only place `reset` is allowed (documented allowlist exception); values in dropped commits remain recoverable from the local reflog.

### 1.4 CLI UX

```bash
psst init --storage git --remote git@github.com:me/psst-vault.git [--env prod]
psst set DB_PASS --stdin                 # unchanged UX, GitStore inside
psst sync [--discard-local --confirm]
psst migrate kdf                         # explicit form of KDF migration (bare `psst migrate` keeps working, same semantics)
psst migrate storage --to git --remote <url>   # SQLite vault -> git repo
```

- **Command naming**: `migrate` becomes a parent with subcommands `kdf` and `storage`; the existing bare `psst migrate` remains as the KDF migration for backward compatibility. `psst migrate storage --to git` **rejects vaults on KDF v1** (SHA-256, no salt) with a pointer to `psst migrate kdf` first — carrying v1 ciphertext into an argon2id-declared `psst.yaml` would produce a vault that cannot be decrypted. `migrate storage` decrypts from the old vault and re-encrypts into the new one (values, tags→directories), using one outer `ExecTx`: one commit + push at the end. SQLite accepts arbitrary tag strings while git directories require `[a-z][a-z0-9-]*` — `migrate storage` pre-flight validates all tags and aborts **before any write**, listing every secret with a non-conforming tag (`Prod`, `My Tag`, …) so the user can re-tag first.
- **KDF migration on git vaults** (`psst migrate kdf`): writes stronger parameters to `psst.yaml` + re-encrypts all `.enc` files as **one atomic commit** (one outer `ExecTx`), so other machines never observe a half-migrated vault; the monotonic-strengthening rule (1.1) lets them accept the new parameters on next open and update their pins. Salt never changes.
- **Storage selection priority**: `--storage` flag > persisted default in `.psst/config.yaml` (written by `init --storage git`) > autodetect from directory contents. If selection conflicts with actual contents (e.g. config says git but only `vault.db` exists) → explicit error. `--storage git` on any command before `init` → error with hint. The flag is valid on all vault-opening commands.
- **Key provider: password-only.** Git vaults derive the key strictly from the password via `DeriveKeyFromPassword` (Argon2id + salt + params from `psst.yaml`; no base64 passthrough — 1.1). The OS keychain provider is never consulted for git vaults — `keyring.NewProvider`'s auto-selection would otherwise hand back a machine-local random key from the SQLite era and every decryption would fail. `init --storage git` never writes to the keychain. Empty password is rejected.
- **Interactive password prompt** is new functionality (today only `PSST_PASSWORD` exists): when the env var is unset and stdin is a TTY, prompt via `golang.org/x/term` (already a dependency, `go.mod`).
- **Wiring**: a single store factory in the CLI wiring (config → `NewSQLite` | `NewGitStore`); `FindVaultPath` generalizes to return the env directory (SQLite appends `vault.db`, GitStore uses `repo/`). The per-env `.psst/config.yaml` also holds the immutability pins and the persisted storage default (1.1).
- Local clone location: `~/.psst/envs/<name>/repo` (global) or `.psst/envs/<name>/repo` (project), mirroring the existing SQLite layout. One environment = one repository = one password (same isolation as today: one env = one DB).
- `psst list-envs` detects environments by `<env>/vault.db` **or** `<env>/repo/psst.yaml`.
- `psst scan` is unchanged: it compares decrypted values against working-tree files; `.enc` files contain ciphertext and never match. Scanning the vault repo itself is unnecessary by design.

### 1.5 Testing

Real temporary git repositories (`git init --bare` in `t.TempDir()` as remote):

- Full CRUD cycle through GitStore, all 14 interface methods.
- Two clones racing on the same key → conflict path (abort + error), then recovery via `sync --discard-local`; `psst sync` on a conflicted clone → abort + error too.
- Two clones racing on different keys → both land after rebase.
- Offline read: remote removed, reads work; **diverged clone (local commit, failed push) → every read warns on stderr**.
- Offline write: push fails with the `psst sync` hint; no-remote repo → warning, not error.
- `InitSchema` non-destructiveness: existing repo with corrupted `psst.yaml` → hard error, salt never regenerated, no commit/push of a broken state.
- Migration from SQLite vault (values, tags→dirs); v1-KDF vault rejected by `migrate storage`.
- `migrate kdf` on git vault: one commit; second machine accepts stronger params and updates its pin; weaker params rejected.
- Stale-key window: a write on a clone that missed a remote KDF migration aborts after pull ("vault parameters changed remotely") and never pushes old-key ciphertext.
- Rollback across a KDF-migration boundary: pre-migration version → fail-closed "predates a KDF migration"; post-migration version → re-encrypted and lands as a new commit.
- Remote scheme allowlist: `git://` always rejected; `http://` rejected without `--allow-insecure-remote`.
- Concurrent processes on one clone (CLI + CLI) → serialized by the lock, no `index.lock` errors.
- Nested `ExecTx` (import of N secrets) → exactly one pull/commit/push.
- Malicious repo: hooks present must never execute; non-conforming paths (`secrets/../x`, bad tag names) ignored/reported by the walk; path construction never escapes `secrets/`.
- `psst.yaml` validation: missing fields, wrong version/cipher/algo, weak KDF params, salt change after first open → all hard errors; base64-shaped password still goes through Argon2 (no passthrough).
- AAD: a ciphertext from another salt/vault fails with the explainable error; SQLite vaults with nil AAD keep decrypting (old `Encrypt`/`Decrypt` path).
- History: `Version` ordinals stable across new commits and rollback; HEAD excluded; DESC order; `Author` populated.
- Concurrent `tag`/`untag` → single-tag invariant holds (replace semantics).

No new dependencies (`os/exec`, `syscall` flock, `golang.org/x/term` already present). Binary stays CGo-free.

## 2. Web UI — `psst serve` (phase 2)

```
psst serve [--listen 127.0.0.1:7788] [--token <tok>]
# psst server: http://127.0.0.1:7788
# auth token:  a3f9c2e1...   (printed once)
```

**Model**: the server is just another client of the git repository, using the same GitStore logic (sync → write → commit → push) and the same process lock (1.3). No own database; git remains the single source of truth. If the server dies, CLI machines are unaffected. `serve` requires git storage (with SQLite it errors, pointing at `psst migrate storage`).

**Auth — two barriers**:
1. **Server token — always mandatory** (even on localhost: other local users of a multi-user host can reach `127.0.0.1`): if `--token` is not passed, a token is generated at startup and printed once. Token check is constant-time; success issues an httpOnly session cookie with `SameSite=Strict`. Middleware additionally validates `Host` (`127.0.0.1:<port>` or `localhost:<port>`; rejects foreign Host headers — DNS-rebinding defense) and requires a matching `Origin` header on every mutating request. Default bind `127.0.0.1`; remote access via `ssh -L 7788:127.0.0.1:7788` (documented). `--listen 0.0.0.0` prints an explicit warning.
2. **Vault password unlock**: Argon2id key derived in memory, bound to the session, 30-minute inactivity timeout, logout wipes the key. Without unlock the UI shows only names/tags/dates (already public in git), never values.

**Screens**: secret list (tree by tag directories, dates from git log, commit author as "changed by machine"), create/edit (`set`), delete, history with rollback. Values are shown only through an explicit reveal action — served by a dedicated endpoint, never embedded in list payloads.

**Tech**: `go:embed` static assets in the binary, vanilla JS, stdlib `net/http`. UI-private REST API behind the session cookie:
`GET /api/secrets`, `POST /api/secrets/{name}`, `DELETE /api/secrets/{name}`, `GET /api/secrets/{name}/history`, `POST /api/secrets/{name}/rollback`, `GET /api/secrets/{name}/value` (reveal; unlock required).

No new dependencies.

## 3. `psst render` (phase 3; independent of phases 1–2)

```bash
psst render --in deploy.env.tpl --out deploy.env       # out file always 0600
psst render --in config.yaml.tpl --out config.yaml --tag prod
```

Placeholder semantics — fail-closed by syntax:

- `{{KEY}}` — unambiguous psst syntax: missing secret is an **error** listing the unresolved names (never ship a literal `{{KEY}}` to prod).
- `$KEY`, `${KEY}` — replaced if the secret exists, left as-is otherwise (legitimate shell syntax that must not break scripts).
- `--strict` — all three syntaxes fail on unresolved names.

**Single-pass substitution.** Placeholders are matched only in the original template; substituted values are never re-scanned. A secret value that itself contains `$OTHER` or `{{OTHER}}` stays literal. This rules out the cascading-substitution behavior of `runner.ExpandEnvVars` (which re-scans the accumulated result); render implements its own single-pass matcher for `$KEY`/`${KEY}` and does not reuse `ExpandEnvVars` directly.

**Output file perms**: after writing, an explicit `chmod 0600` is enforced (write + chmod; failure to chmod is an error) — `O_CREAT 0600` alone does not fix permissions of an already-existing wider file.

Source: whole vault or `--tag` filter. stdout reports only "rendered N placeholders → <file>"; values never go to stdout.

Docs gain a recipes section: `ssh + sshpass -e`, python `os.environ`, node, `docker --env-file` — protocol-independent substitution, closing the HTTP-only proxy gap.

## 4. Security rules update (`docs/rules/security.md`)

"Never send secrets over network" is refined to:

1. The git remote contains only ciphertext (values encrypted and AAD-bound; names visible by design).
2. Web UI: localhost + mandatory token + unlock; value reveal only via the dedicated reveal endpoint after unlock; Host/Origin checks and `SameSite=Strict`.
3. Remote UI access only through an SSH tunnel.
4. Plaintext egress inventory: the child process environment (runner) is the existing channel; phase 3 adds exactly one new channel — the 0600 file produced by `render`. `psst get` and `psst export` remain the existing explicit operator-initiated exceptions; phase 2 adds the UI reveal as one more explicit, operator-initiated exception.

This formalizes, not weakens, the local-only principle.

## 5. Password / key rotation (out of scope for phase 1 — recorded direction)

Changing the shared password with the same salt changes nothing for attackers who only have ciphertext; rotation means a **new salt + re-encryption of every `.enc` file + updated `psst.yaml` as one atomic commit** (`ExecTx`), which invalidates all UI sessions. Because the salt pin (1.1) is strict, a future `psst rotate` necessarily requires an explicit acceptance step on every machine (e.g. `psst sync --accept-rotation` after re-entering the password, or a fresh clone) — the pin must fire; there is no silent adoption. Phase 1 ships no `rotate` command; the documented manual procedure is: create a new vault repo with the new password, `migrate storage` into it, retire the old repo.

## 6. Implementation phases

| Phase | Content | Depends on |
|---|---|---|
| 1 | GitStore (all 14 methods + `Author` field + `Encryptor`/`KeyProvider` extensions), sync protocol with lock + recovery, `init --storage git`, `psst sync`, `psst migrate kdf`/`storage`, `docs/rules/security.md` refinement (ships in the same PR — ciphertext leaves for a remote from the first commit) | — |
| 2 | `psst serve`, UI, session/unlock | phase 1 |
| 3 | `psst render`, recipes docs | none (parallelizable) |

Each phase gets its own spec→plan→implementation cycle. This document is the phase-1 spec and the committed direction for phases 2–3.

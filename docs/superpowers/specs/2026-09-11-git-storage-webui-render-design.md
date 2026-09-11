# Git Storage Backend, Web UI, and Secret Rendering — Design

Date: 2026-09-11
Status: approved in brainstorm, revised after subagent code review (1 critical / 13 major / 10 minor / 5 nit — all addressed below)
Scope: phased — phase 1 (GitStore) is this spec's implementation target; phases 2–3 recorded here as committed direction.

## Problem

1. psst stores secrets in a local SQLite vault. Synchronizing it across several LLM machines (symlinked DB in a repo, manual copy) is manual and fragile.
2. Proxy-based LLM secret-injection projects cover only HTTP traffic. SSH (login/password) and generated script/config files with literal placeholders are out of their reach.
3. Secret management across machines needs a UI, but running a full psst instance per machine is inconvenient.

## Decisions (from brainstorm)

| Decision | Choice |
|---|---|
| SQLite fate | GitStore as an option behind `SecretStore`; SQLite stays the default backend |
| Key distribution | Shared password: Argon2id (v2 KDF) + per-vault salt stored in the repo |
| Secret file format | `base64(IV ‖ AES-256-GCM ciphertext(value))` — value only; ciphertext bound to vault metadata via GCM AAD (see 1.1) |
| Grouping / tags | Subdirectories (`secrets/<tag>/NAME.enc`); exactly one tag per secret |
| Dates | From git log (`--diff-filter=A` for created, last commit for updated); nothing stored in files |
| Sync on unreachable remote | Reads: best-effort pull, work from local clone. Writes: strict pull --rebase → commit → push |
| Web server role | UI only; CLI machines talk to git directly, never to the server |
| Web server auth | localhost bind + mandatory token; vault password unlock in UI; SSH tunnel for remote |
| Substitution (idea 2) | New `psst render` command; env injection already covers subprocess cases |
| Git driver | System `git` via `os/exec`; no new dependencies |
| Key provider for git storage | Password-only; OS keychain is never consulted for git vaults (see 1.4) |
| Migration command | `psst migrate storage --to git` (subcommand; bare `psst migrate` keeps KDF semantics, `psst migrate kdf` added) |

Accepted trade-offs:

- Secret **names** are visible in the repo (file names), values never — same model as `pass`.
- No multi-tag secrets in git backend (a file lives in one directory). SQLite keeps multi-tag JSON. Multi-tag requests against a git vault fail closed at CLI validation.
- Ciphertext conflicts on the same key are not auto-merged (fail-closed), with an explicit recovery command (see 1.3).

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
  time: 1
  memory: 65536
  threads: 4
salt: <base64>                 # per-vault salt; same password + salt => same key on every machine
cipher: aes-256-gcm
```

KDF parameters and salt are not secret (same as sops metadata). This reuses the existing v2 KDF: GitStore maps `GetMeta("kdf_salt")` / `GetMeta("kdf_version")` onto `psst.yaml` fields (see 1.2), so `vault.Unlock()` derives the key exactly as it does for SQLite vaults with per-vault salt.

**AAD binding.** Each `.enc` file is encrypted with GCM additional authenticated data `psst:v1:<kdf-algo>:<salt-base64>`. This binds every ciphertext to the vault's format version, KDF algorithm, and salt: files from another vault/salt fail authentication with an explainable error instead of a bare "message authentication failed", and future format or KDF changes have a migration point. Same AAD scheme may be adopted by the SQLite backend later; not required for phase 1.

**Validation (fail-closed).** `psst.yaml` is untrusted input (it lives in a synced repo; GCM authenticates secret values, not vault metadata). On open/init GitStore validates:

- Required fields present; `version == 1`, `cipher == aes-256-gcm`, `kdf.algo == argon2id` — anything else is a hard error, no fallback.
- KDF minimums: `memory >= 64 MiB`, `time >= 1`, `threads >= 1`. Weaker parameters are rejected (blocks parameter-downgrade attacks by someone with write access to the remote).
- Salt must be valid base64; **if the salt or KDF parameters change in a repo that was previously opened on this machine (recorded in the local vault config), that is an explicit error** pointing at the rotation procedure (see section 5), never a silent re-derivation.
- Empty password is rejected at init and unlock.

**Remote schemes.** `ssh://`, `https://`, `git@…`, and filesystem paths to bare repos are allowed. `http://` remotes are rejected unless the user passes an explicit `--allow-insecure-remote` flag (plaintext git transport would let a MITM swap ciphertext and metadata).

### 1.2 GitStore (`internal/store/git.go`)

Implements the **full** existing `SecretStore` interface (`internal/store/store.go` — 14 methods):

| Interface method | GitStore behavior |
|---|---|
| `InitSchema` | Idempotent (called on every command by `getUnlockedVault`): if the repo dir exists and `psst.yaml` is valid → no-op; otherwise clone/init + write `psst.yaml` + first commit. Cloning into a dir that already has a valid repo never rewrites `psst.yaml` (salt is immutable — see 1.1) |
| `GetSecret` | read + decode file `secrets/[tag/]NAME.enc` |
| `GetAllSecrets` | read + decode every file (used by `run`, `scan`, `export`) |
| `SetSecret` | write file → `git add <exact path>` → commit → push |
| `DeleteSecret` | `git rm <path>` + commit + push |
| `DeleteHistory` | no-op: history lives in commits; deleting history would rewrite shared history — forbidden |
| `ListSecrets` | walk `secrets/` tree; tag = directory name |
| `GetHistory` | `git log --follow -- <file>` + `git show <rev>:<path>` for each commit to load the blob; `Version` = 1-based ordinal from oldest to newest (recomputed per call, so `--to N` means "N-th from creation" and stays stable as new commits land); `ArchivedAt` = commit time; `Author` = commit author |
| `AddHistory` | no-op (git owns history) |
| `PruneHistory` | no-op (pruning would rewrite shared history — forbidden) |
| `ExecTx` | executes `fn` directly; atomicity comes from the git commit — **batch mode**: one pull at start, one commit + push at end. `import` and `migrate storage` use this to avoid N pull/push cycles |
| `GetMeta` | reads `psst.yaml`: `kdf_version` (always `2` for git vaults), `kdf_salt` (from `salt`). Never returns empty `kdf_version` for a valid vault — a git vault missing these fields fails validation (1.1) instead of letting `vault.Unlock()` fall back to the v1 SHA-256 path |
| `SetMeta` | writes the corresponding `psst.yaml` fields (only `kdf_*` keys are honored) as part of a commit |
| `Close` | no-op |

**`HistoryEntry.Author`** is a new field on `store.HistoryEntry` / `vault.SecretHistoryEntry`: GitStore fills it from the commit (machine identity, 1.3), SQLite leaves it empty. Output layer shows it when present. This is the only interface/type change in phase 1.

- `psst rollback NAME --to N` uses the **existing** `vault.Rollback` flow: it resolves version N from `GetHistory` and writes it via `SetSecret` as a **new** commit. Remote history is never rewritten. No separate rollback path is added.
- `psst tag NAME T` = `git mv secrets/NAME.enc secrets/T/NAME.enc` + commit + push. Tag = replace: the secret moves out of its previous directory (single tag invariant).
- `psst untag NAME` = `git mv secrets/T/NAME.enc secrets/NAME.enc` + commit + push (error if already untagged).
- Multi-tag requests against a git vault (`--tag a --tag b`, `tag` on an already-tagged secret with a *second* tag requested) are rejected at CLI validation with an explicit message — never silently flattened.

**Path safety.** A cloned repo is untrusted input. Tag names must match `[a-z][a-z0-9-]*`; secret names must match the existing `validName` rule (`[A-Z][A-Z0-9_]*`). The `secrets/` walk ignores (and reports) any entry that does not match the shape `secrets/[TAG/]NAME.enc`; all paths are constructed only from validated components. Directory traversal (`..`, absolute names) from repo content can never reach the filesystem.

### 1.3 Sync protocol

**Subprocess environment (every git call):**

- `-c core.hooksPath=/dev/null` — repo-hosted hooks never execute.
- `GIT_TERMINAL_PROMPT=0` — no interactive prompts; a hung CLI agent is impossible.
- `GIT_CONFIG_NOSYSTEM=1` and `GIT_CONFIG_GLOBAL` pointing at an empty file — system/user gitconfig (`url.*.insteadOf` redirects, `core.sshCommand` overrides, `credential.helper=store`) cannot silently alter transport or leak credentials.
- `GIT_ASKPASS` / `SSH_ASKPASS` unset.
- Subcommand allowlist: `clone, fetch, pull, add, rm, mv, commit, push, log, show, status` (+ `rebase --abort` for conflict cleanup). One documented exception for recovery: the `reset --hard @{upstream}` performed **only** by `psst sync --discard-local` (below). No `clean`, no filters/LFS.

**Identity**: on clone/init set local `user.name = psst/<hostname>`, `user.email = psst@<hostname>` — history shows which machine changed a secret.

**Process lock.** All git-mutating sequences (and the read-pull) hold an exclusive process lock on the clone (`flock` on `repo/.psst.lock`). Two processes on one machine — CLI+CLI, or CLI + `psst serve` from phase 2 — serialize instead of racing on `index.lock` and half-written files. Lock waits with a timeout and fails with a clear message.

**Reads** (`get/list/run/history/rollback`): best-effort sync, two distinct outcomes:

- Network failure → work silently from the local clone.
- Diverged (`pull --ff-only` rejected because the clone has unpushed local commits) → operate locally **but print a warning to stderr on every read command**: "local clone has unpushed changes; run `psst sync`". Stale reads must never be silent.

**Writes** (`set/rm/tag/untag`), under the lock:

1. `git pull --rebase --autostash` (a repo without a remote configured is tolerated — see below).
2. On rebase conflict (two machines changed the same key between syncs): `git rebase --abort`, fail with "key changed remotely; re-set the value or run `psst sync --discard-local`". No silent last-write-wins. The abort does not lose local commits — but the conflicting local commit stays on the branch and will conflict again, so:
3. Apply change, `git add <exact secret path>` (never `-A`; no stray files in commits), `git commit -m "psst: <op> <NAME>"`.
4. `git push`; on failure: error with hint ("change is in the local clone; run `psst sync` later"). If no remote/upstream is configured at all: warning "working locally, no remote configured", not an error (local-only git vault is a valid setup).

**`psst sync`**: explicit `git pull --rebase --autostash` + `git push` for offline recovery.
**`psst sync --discard-local`**: recovery for the conflict deadlock — `git reset --hard @{upstream}` under the lock, dropping local unpushed psst commits. Prints what is being discarded and requires `--confirm` in non-interactive use. This is the only place `reset` is allowed (documented allowlist exception); values in dropped commits remain recoverable from the local reflog.

### 1.4 CLI UX

```bash
psst init --storage git --remote git@github.com:me/psst-vault.git [--env prod]
psst set DB_PASS --stdin                 # unchanged UX, GitStore inside
psst sync [--discard-local --confirm]
psst migrate kdf                         # explicit form of KDF migration (bare `psst migrate` keeps working, same semantics)
psst migrate storage --to git --remote <url>   # SQLite vault -> git repo
```

- **Command naming**: `migrate` becomes a parent with subcommands `kdf` and `storage`; the existing bare `psst migrate` remains as the KDF migration for backward compatibility. `psst migrate storage --to git` **rejects vaults on KDF v1** (SHA-256, no salt) with a pointer to `psst migrate kdf` first — carrying v1 ciphertext into an argon2id-declared `psst.yaml` would produce a vault that cannot be decrypted. `migrate storage` decrypts from the old vault and re-encrypts into the new one (values, tags→directories), using `ExecTx` batch mode: one commit + push at the end.
- **KDF migration on git vaults** (`psst migrate kdf`): changes `psst.yaml` + re-encrypts all `.enc` files as **one atomic commit** (via `ExecTx`), so other machines never observe a half-migrated vault.
- **Storage selection priority**: `--storage` flag > persisted default in `.psst/config.yaml` (written by `init --storage git`) > autodetect from directory contents. If selection conflicts with actual contents (e.g. config says git but only `vault.db` exists) → explicit error. `--storage git` on any command before `init` → error with hint. The flag is valid on all vault-opening commands.
- **Key provider: password-only.** Git vaults derive the key strictly from the password (Argon2id + salt from `psst.yaml`). The OS keychain provider is never consulted for git vaults — `keyring.NewProvider`'s auto-selection would otherwise hand back a machine-local random key from the SQLite era and every decryption would fail. `init --storage git` never writes to the keychain. Empty password is rejected.
- **Interactive password prompt** is new functionality (today only `PSST_PASSWORD` exists): when the env var is unset and stdin is a TTY, prompt via `golang.org/x/term` (already a dependency).
- **Wiring**: a single store factory in the CLI wiring (config → `NewSQLite` | `NewGitStore`); `FindVaultPath` generalizes to return the env directory (SQLite appends `vault.db`, GitStore uses `repo/`).
- Local clone location: `~/.psst/envs/<name>/repo` (global) or `.psst/envs/<name>/repo` (project), mirroring the existing SQLite layout. One environment = one repository = one password (same isolation as today: one env = one DB).
- `psst list-envs` detects environments by `<env>/vault.db` **or** `<env>/repo/psst.yaml`.
- `psst scan` is unchanged: it compares decrypted values against working-tree files; `.enc` files contain ciphertext and never match. Scanning the vault repo itself is unnecessary by design.

### 1.5 Testing

Real temporary git repositories (`git init --bare` in `t.TempDir()` as remote):

- Full CRUD cycle through GitStore, all 14 interface methods.
- Two clones racing on the same key → conflict path (abort + error), then recovery via `sync --discard-local`.
- Two clones racing on different keys → both land after rebase.
- Offline read: remote removed, reads work; **diverged clone (local commit, failed push) → every read warns on stderr**.
- Offline write: push fails with the `psst sync` hint; no-remote repo → warning, not error.
- Migration from SQLite vault (values, tags→dirs); v1-KDF vault rejected by `migrate storage`.
- Concurrent processes on one clone (CLI + CLI) → serialized by the lock, no `index.lock` errors.
- Malicious repo: hooks present must never execute; non-conforming paths (`secrets/../x`, bad tag names) ignored/reported by the walk; path construction never escapes `secrets/`.
- `psst.yaml` validation: missing fields, wrong version/cipher/algo, weak KDF params, salt change after first open → all hard errors.
- AAD: a ciphertext from another salt/vault fails with the explainable error.
- History: `Version` ordinals stable across new commits; rollback via existing `vault.Rollback` produces a new commit.

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

**Screens**: secret list (tree by tag directories, dates from git log, commit author as "changed by machine"), create/edit (`set`), delete, history with rollback. Values shown only via an explicit reveal action (web analog of `psst get`, for the human operator).

**Tech**: `go:embed` static assets in the binary, vanilla JS, stdlib `net/http`. UI-private REST API behind the session cookie:
`GET /api/secrets`, `POST /api/secrets/{name}`, `DELETE /api/secrets/{name}`, `GET /api/secrets/{name}/history`, `POST /api/secrets/{name}/rollback`.

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
2. Web UI: localhost + mandatory token + unlock; value reveal only after unlock; Host/Origin checks and `SameSite=Strict`.
3. Remote UI access only through an SSH tunnel.
4. Plaintext values gain exactly two **new** places to leave the machine: the child process environment (runner, existing) and the 0600 file produced by `render` (new). `psst get`, `psst export`, and the UI reveal remain the existing explicit, operator-initiated exceptions.

This formalizes, not weakens, the local-only principle.

## 5. Password / key rotation (out of scope for phase 1 — recorded direction)

Changing the shared password with the same salt changes nothing for attackers who only have ciphertext; rotation means a **new salt + re-encryption of every `.enc` file + updated `psst.yaml` as one atomic commit** (`ExecTx`), which invalidates all UI sessions and requires every machine to re-enter the new password. Phase 1 ships no `rotate` command; the salt-immutability check (1.1) makes accidental drift impossible, and the documented manual procedure is: create a new vault repo with the new password, `migrate storage` into it, retire the old repo. A first-class `psst rotate` is a candidate for a later phase.

## 6. Implementation phases

| Phase | Content | Depends on |
|---|---|---|
| 1 | GitStore (all 14 methods + `Author` field), sync protocol with lock + recovery, `init --storage git`, `psst sync`, `psst migrate kdf`/`storage`, `docs/rules/security.md` refinement (ships in the same PR — ciphertext leaves for a remote from the first commit) | — |
| 2 | `psst serve`, UI, session/unlock | phase 1 |
| 3 | `psst render`, recipes docs | none (parallelizable) |

Each phase gets its own spec→plan→implementation cycle. This document is the phase-1 spec and the committed direction for phases 2–3.

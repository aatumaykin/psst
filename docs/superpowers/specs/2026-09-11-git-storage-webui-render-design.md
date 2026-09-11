# Git Storage Backend, Web UI, and Secret Rendering — Design

Date: 2026-09-11
Status: approved (brainstorm with maintainer)
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
| Secret file format | `base64(IV ‖ AES-256-GCM ciphertext(value))` — value only |
| Grouping / tags | Subdirectories (`secrets/<tag>/NAME.enc`); one tag per secret |
| Dates | From git log (`--diff-filter=A` for created, last commit for updated); nothing stored in files |
| Sync on unreachable remote | Reads: best-effort pull, work from local clone. Writes: strict pull --rebase → commit → push |
| Web server role | UI only; CLI machines talk to git directly, never to the server |
| Web server auth | localhost bind + generated token; vault password unlock in UI; SSH tunnel for remote |
| Substitution (idea 2) | New `psst render` command; env injection already covers subprocess cases |
| Git driver | System `git` via `os/exec`; no new dependencies |

Accepted trade-offs:

- Secret **names** are visible in the repo (file names), values never — same model as `pass`.
- No multi-tag secrets in git backend (a file lives in one directory). SQLite keeps multi-tag JSON.
- Ciphertext conflicts on the same key are not auto-merged (fail-closed).

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

KDF parameters and salt are not secret (same as sops metadata). This reuses the existing v2 KDF; only the salt location moves from `vault_meta` table to `psst.yaml`.

### 1.2 GitStore (`internal/store/git.go`)

Implements the existing `SecretStore` interface:

| Interface method | GitStore behavior |
|---|---|
| `InitSchema` | clone (or `git init`) + write `psst.yaml` + first commit |
| `SetSecret` | write file → `git add && commit && push` |
| `GetSecret` | read + decode file |
| `DeleteSecret` | `git rm` + commit + push |
| `ListSecrets` | walk `secrets/` tree; tag = directory name |
| `GetHistory` | `git log --follow -- <file>` |
| `AddHistory`, `PruneHistory` | no-op (git owns history; pruning would rewrite shared history — forbidden) |
| `Close` | no-op |

- `psst rollback NAME --to N`: extract blob from the Nth commit touching the file, write as a **new** commit. Remote history is never rewritten.
- `psst tag NAME T` = `git mv secrets/NAME.enc secrets/T/NAME.enc` + commit + push.
- `psst history NAME`: versions = commits touching the file; author = machine identity (see 1.3).

### 1.3 Sync protocol

All git invocations use `-c core.hooksPath=/dev/null` and `GIT_TERMINAL_PROMPT=0`.

**Identity**: on clone/init set local `user.name = psst/<hostname>`, `user.email = psst@<hostname>` — history shows which machine changed a secret.

**Reads** (`get/list/run/history/rollback`): best-effort `git pull --ff-only`; network failure is ignored, local clone serves the operation.

**Writes** (`set/rm/tag`):
1. `git pull --rebase --autostash` (tolerate "no upstream configured").
2. On rebase conflict (two machines changed the same key between syncs): `git rebase --abort`, fail with a clear message ("key changed remotely, re-set the value"). No silent last-write-wins.
3. Apply change, `git add -A secrets/`, `git commit -m "psst: <op> <NAME>"`.
4. `git push`; on failure: error with hint ("change is in the local clone; run `psst sync` later").

**`psst sync`**: explicit `git pull --rebase --autostash` + `git push` for offline recovery.

**Subcommand allowlist**: `clone, fetch, pull, add, rm, mv, commit, push, log, show, status` (+ `rebase --abort` for conflict cleanup). No `clean`, no `reset --hard`, no filters/LFS.

### 1.4 CLI UX

```bash
psst init --storage git --remote git@github.com:me/psst-vault.git [--env prod]
psst set DB_PASS --stdin                 # unchanged UX, GitStore inside
psst sync
psst migrate --to git --remote <url>     # SQLite vault -> git repo (secrets + tags as dirs)
```

- Storage selection: `--storage {sqlite,git}` flag on commands; after `init --storage git` the default is persisted in the vault config (`.psst/config.yaml`).
- Local clone location: `~/.psst/envs/<name>/repo` (global) or `.psst/envs/<name>/repo` (project), mirroring the existing SQLite layout.
- One environment = one repository = one password (same isolation as today: one env = one DB).
- Unlock: `PSST_PASSWORD` or interactive prompt; Argon2id params/salt from `psst.yaml`.
- Local "remote" is supported: any git URL including a filesystem path to a bare repo.

### 1.5 Testing

Real temporary git repositories (`git init --bare` in `t.TempDir()` as remote):

- Full CRUD cycle through GitStore.
- Two clones racing on the same key → conflict path (abort + error).
- Two clones racing on different keys → both land after rebase.
- Offline read: remote removed, reads still work.
- Offline write: push fails with the `psst sync` hint.
- Migration from SQLite vault (values, tags→dirs).
- Hook execution must never occur (repo with malicious hook in allowlisted path).

No new dependencies (`os/exec` only). Binary stays CGo-free.

## 2. Web UI — `psst serve` (phase 2)

```
psst serve [--listen 127.0.0.1:7788] [--token <tok>]
# psst server: http://127.0.0.1:7788
# auth token:  a3f9c2e1...   (printed once)
```

**Model**: the server is just another client of the git repository, using the same GitStore logic (sync → write → commit → push). No own database; git remains the single source of truth. If the server dies, CLI machines are unaffected.

**Auth — two barriers**:
1. **Server token** → httpOnly session cookie (constant-time compare). Default bind `127.0.0.1`; remote access via `ssh -L 7788:127.0.0.1:7788` (documented). `--listen 0.0.0.0` allowed only together with explicit `--token` and prints a warning.
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
- `$KEY`, `${KEY}` — replaced if the secret exists, left as-is otherwise (legitimate shell syntax that must not break scripts). Reuses `internal/runner/expand.go` logic.
- `--strict` — all three syntaxes fail on unresolved names.

Source: whole vault or `--tag` filter. stdout reports only "rendered N placeholders → <file>"; values never go to stdout.

Docs gain a recipes section: `ssh + sshpass -e`, python `os.environ`, node, `docker --env-file` — protocol-independent substitution, closing the HTTP-only proxy gap.

## 4. Security rules update (`docs/rules/security.md`)

"Never send secrets over network" is refined to:

1. The git remote contains only ciphertext (values encrypted; names visible by design).
2. Web UI: localhost + token + unlock; value reveal only after unlock.
3. Remote UI access only through an SSH tunnel.
4. Plaintext values leave the machine in exactly two places: the child process environment (runner) and the 0600 file produced by `render`.

This formalizes, not weakens, the local-only principle.

## 5. Implementation phases

| Phase | Content | Depends on |
|---|---|---|
| 1 | GitStore, sync protocol, `init --storage git`, `psst sync`, `psst migrate --to git` | — |
| 2 | `psst serve`, UI, session/unlock | phase 1 |
| 3 | `psst render`, recipes docs | none (parallelizable) |

Each phase gets its own spec→plan→implementation cycle. This document is the phase-1 spec and the committed direction for phases 2–3.

# Integration Plan: feat/phases-2-4 ← origin/main (audit-refactor wave)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Sequential tasks in ONE worktree with a single in-progress merge: /Users/atumaikin/Projects/psst/.worktrees/integration, branch integration/phases-2-4 (started from our main @ c1e71b9, `git merge origin/main --no-commit` already run — 28 conflicted files, 20 of their files auto-staged).

**Goal:** Integrate the remote security-audit/refactor wave (origin/main @ 4a2ee78, released up to v1.6.0) with our local phases 1–4 (git storage, serve, render, rotate + follow-up fixes). End state: one main that has BOTH their hardened architecture AND all our features; full suite green under `-race`; push fast-forwards origin.

**Governing principle:** THEIR architecture wins structurally (it is the released, audited line). Our features are PORTED into their shapes — never the reverse. Where both sides fixed the same bug independently (e.g. sqlite tx safety), prefer their version unless ours is strictly stronger, and note the choice.

## Inventory (from the recon merge)

- Conflicted (28): all of internal/cli/*.go (16 files — their withVault/named-exits/context refactor × our serve/render/rotate/sync additions), internal/vault/{vault.go, vault_test.go}, internal/crypto/{crypto.go, aesgcm.go, aesgcm_test.go}, internal/store/{sqlite.go, sqlite_test.go}, keyring.go, Makefile, README.md, docs/ru/README.md, docs/rules/{architecture,projectrules}.md.
- Clean from ours (their side never saw them): internal/store/git.go (GitStore), internal/server/*, internal/render/*, internal/cli/{serve,render,rotate}.go (NEW files — staged clean), sync.go (ours only), vaultconfig.go (ours only), tests/{git_storage,render,rotate}_test.go.
- Their auto-staged (20): vault split files (interface.go, unlock.go 213L with brute-force lockout, secrets.go, tags.go, history.go, init.go, migrate.go, path.go, validation.go), cli/verify.go, .github/*, SECURITY.md, .golangci.yml, etc.
- Their store.go: SecretStore → SecretReader/SecretWriter/HistoryStore/MetaStore + combined (70L, auto-merged; verify our SecretMeta.UpdatedBy survived).

## Semantic mapping (what ports where)

| Ours (old shape) | Ports into (their shape) |
|---|---|
| vault.go: Unlock git-branch (kdf_time/AAD/fingerprint), metaAtoi | internal/vault/unlock.go (alongside their brute-force lockout — the lockout counts attempts on the password path; keep our git derivation branch inside the same flow) |
| vault.go: Rotate, VerifyAllDecryptable | NEW internal/vault/rotate.go (clean file; ctx in signatures per their style) |
| vault.go: UpdatedBy mapping, git-aware ListSecrets | internal/vault/secrets.go |
| vault.go: RetagSecret, Batch | internal/vault/tags.go (RetagSecret) / interface.go (Batch) |
| SecretMeta.UpdatedBy | store.go (verify auto-merge kept it) |
| GitStore 14 methods (+ExecTxMsg/RotateSalt/SyncAcceptRotation/AheadOfUpstream) | stays one file; gains `ctx context.Context` first params to satisfy their sub-interfaces; flock/opMu unchanged |
| sqlite.go: our txMu + DSN pragmas | MERGE with their 372L security version: inspect whether their tx safety duplicates txMu (likely — 7a63f8d "transaction safety"); keep the stronger, add our `_pragma=journal_mode(WAL)` DSN + sidecar chmod if absent |
| crypto: KDFParams, EncryptWithAAD/DecryptWithAAD, DeriveKeyFromPassword | keep ALL (their hardening reformatted surroundings; our methods are load-bearing for git vaults) |
| cli: getUnlockedVault | their withVault/open path; our git-branch (PasswordProvider, no-keychain) must survive inside it |
| cli serve/render/rotate/sync | port call sites to ctx signatures + their exit constants; keep our command structure |
| server handlers | mechanical ctx adaptation; behavior contract unchanged (spec 2026-09-11-serve-webui-design.md) |
| confirmReveal (theirs, on get/export) | keep as-is; does NOT apply to serve reveal (different barrier model — document in review) |

## docs/superpowers

Their line deleted it (policy: planning artifacts). Our line re-added files post-deletion → merge leaves OUR files in place (no conflict reported). DECISION: after integration, REMOVE docs/superpowers from the tree to honor the released repo's policy (history preserves everything; process docs continue living in the working session, not the repo). Do this in the final docs task.

## Tasks (sequential, same worktree, merge stays uncommitted until T6)

- **T1 crypto** (unblocks T2/T3): resolve crypto.go (1 hunk), aesgcm.go (4), aesgcm_test.go — union merge: their hardening + our three method families. `go build ./internal/crypto/` green.
- **T2 store**: sqlite.go (6 hunks; keep stronger tx safety + ensure DSN pragmas + sidecar chmod survive; their sqlite_test.go merged with our WAL/perms/concurrency tests), verify store.go sub-interfaces + UpdatedBy, fit GitStore signatures to sub-interfaces (ctx params; git_test.go call sites updated mechanically). `go build ./internal/store/` + store tests green (with -race — make test now runs it).
- **T3 vault**: resolve vault.go (5 hunks → their 96L shell; distribute per mapping), vault_test.go (merge both test sets; helpers from both), new rotate.go, extend their interface.go with Rotate/VerifyAllDecryptable/RetagSecret/Batch. `go test ./internal/vault/ -race` green.
- **T4 cli**: resolve all 16 command files + root.go: their withVault/context/exit-constants as base; port serve/render/rotate/sync/init/migrate/tag/untag/list-envs on top (these exist only in our line — mostly they need signature adaptation, not conflict resolution). keyring.go conflict merged. `go build ./...` green.
- **T5 server + render + integration tests**: adapt internal/server handlers to ctx/vault shapes; tests/{git_storage,integration,render,rotate}_test.go merged (their integration_test.go changed -192L — reconcile helpers); FULL `make test` (now -race) green; manual smoke: sqlite CRUD, git vault CRUD+sync, serve curl-flow, render, rotate+accept.
- **T6 docs + finalize**: merge README/ru/rules (both sides' sections: their verify/vault-path/confirmReveal + our serve/render/rotate sections); remove docs/superpowers from tree; `git commit` the merge; fresh `make test`; THEN review subagent on the whole merge diff vs both parents; close findings; merge integration branch into main `--no-ff`; `git push origin main` (now fast-forward, remote is an ancestor); delete feat/phases-2-4 after push confirmed? NO — keep it (release lineage reference), remove only on maintainer request.

## Hard rules (carry over)

PSST_NO_KEYCHAIN=1 (make test); no comments (//nolint: only); fmt.Errorf %w; no new deps; fake secrets only; make test green before every task commit... NOTE: the merge itself stays UNCOMMITTED until T6 — per-task "green" means the touched package's tests pass, not the whole tree; only T5/T6 gate on full suite. Conventional commit for the merge: `merge: integrate audit-refactor wave with phases 2-4`.

# `psst serve` — Web UI (Phase 2) Design

Date: 2026-09-11
Status: reviewed — round 1: 4 major / 6 minor / 2 nit, all addressed; round 2 control: 12/12 fixes verified, 1 major / 2 nit new findings, addressed; round 3 control: pin advancement verified, 1 major (stale in-process `loadPins` snapshot) / 1 minor (retry wording) addressed via 7.4 and unlock-time `InitSchema`
Scope: phase 2 of the git-storage master spec (`docs/superpowers/specs/2026-09-11-git-storage-webui-render-design.md` §2). This document details §2 into a full implementation contract. Phase 1 (GitStore) is merged; the server is another *client* of the same git repository.

## Problem

The git vault needs a UI for browsing, editing, and auditing secrets across machines. The server must not introduce a second source of truth: it uses the existing `GitStore` (sync → write → commit → push), the existing process lock, and the existing sync protocol. CLI machines keep talking to git directly and never contact the server.

## Decisions (brainstorm, approved by maintainer)

| Decision | Choice |
|---|---|
| Package layout | New `internal/server` package; `internal/cli/serve.go` only wires cobra flags |
| Session storage | In-memory map, no persistence; server restart = re-auth |
| Token storage | SHA-256(token) digest in memory; `subtle.ConstantTimeCompare`; no salt — nothing is persisted, so there is nothing to mount a rainbow-table attack on |
| Origin policy | Strict: every mutating request MUST carry a matching `Origin` header; absent → 403 (curl/tests add the header explicitly) |
| UI structure | SPA: static `index.html` + `app.js` + `style.css` behind `go:embed`; zero server-side rendering of secret data |
| Unlock model | Per-session `vault.Vault` instance over ONE shared `GitStore`; password verified by a decrypt probe when the vault is non-empty |
| Concurrency | One server-level mutex serializes every vault/store operation (`Vault` is not goroutine-safe; GitStore's multi-step git sequences assume one logical caller — phase-1 review) |
| Dependencies | None. `net/http` (stdlib, Go 1.22+ mux patterns), `go:embed`, `crypto/subtle`, `crypto/sha256`, vanilla JS |

## 1. Process model and CLI

```
psst serve [--listen 127.0.0.1:7788] [--token <tok>] [--timeout 30m]
```

- Inherits the global flags `--global`, `--env`, `--storage`.
- **Requires git storage.** Storage resolution follows phase 1 (`--storage` flag > config > autodetect). If the resolved storage is SQLite → hard error, exit 1: `psst serve requires git storage; run 'psst migrate storage --to git'`. A missing vault (no repo) exits 3 with the standard "No vault found" message, matching other vault commands.
- **No TTY prompts ever.** `serve` does NOT use `getUnlockedVault` (which unlocks immediately and prompts for the password). It opens the store itself: `OpenVaultStore(envDir, "git", "", false)` + `InitSchema()` (validates pins, TOFU, non-destructiveness — same as any other command) and starts **locked**. Unlocking happens per session through the API.
- Startup output (token printed exactly once, never logged afterwards):

  ```
  psst server:  http://127.0.0.1:7788
  auth token:   <43-char base64url>   (shown once)
  ```

  With `--token` supplied by the user, the token is not echoed (the user already has it); only the URL line prints.
- Token: `--token <tok>` value, the `PSST_SERVE_TOKEN` env var, or 32 bytes from `crypto/rand` encoded as base64url (43 chars). Precedence: flag > env > generated. Only the SHA-256 digest is retained in memory. A token passed via `--token` is visible in `/proc/<pid>/cmdline` to other local users on multi-user hosts — the exact adversary the mandatory token defends against; the README documents this and recommends `PSST_SERVE_TOKEN` or the generated token instead.
- `--listen`: parsed with `net.SplitHostPort`; default `127.0.0.1:7788`. If the host part is not a loopback address (`127.0.0.1`, `localhost`, `::1`) → explicit stderr warning: `warning: listening on a non-loopback interface; expose only via SSH tunnel (ssh -L 7788:127.0.0.1:7788)`. An empty host (`:7788`) means all interfaces → same warning.
- `--timeout`: unlock inactivity timeout; default `30m` (per §2). Minimum accepted value `1m`; smaller values are rejected at startup.
- Graceful shutdown: SIGINT/SIGTERM → `http.Server.Shutdown` with a 5s context, then every session vault is closed (keys zeroed) and the session map cleared.

## 2. Auth — two barriers

### 2.1 Barrier 1: server token

- Mandatory, even on localhost (other local users of a multi-user host can reach `127.0.0.1`).
- `POST /api/login` `{"token": "..."}` → SHA-256 the presented token → `subtle.ConstantTimeCompare` against the stored digest. On success: create a session, `Set-Cookie`. On failure: `401 {"error": "invalid token"}` (generic, constant-time).
- No rate limiting on login: a 256-bit token on a loopback-only listener is not brute-forceable; documented as accepted.
- Session ID: 32 bytes `crypto/rand` → base64url. Cookie:

  ```
  Name:     psst_session
  Value:    <session-id>
  Path:     /
  HttpOnly: true
  SameSite: Strict
  Max-Age:  86400
  ```

  No `Secure` flag: the server is plain HTTP on loopback and must keep working in every browser (Safari does not treat `127.0.0.1` as a secure context). Accepted trade-off: the threat model is localhost traffic + token, not transport eavesdropping; remote access is via SSH tunnel (encrypted transport), documented.
- Session lifetime: 24h absolute from login (no renewal). The 24h timer is the *token barrier* lifetime; the 30-min unlock timer (2.2) is independent.

### 2.2 Barrier 2: vault password unlock

- `POST /api/unlock` `{"password": "..."}` (session required). An empty password → `400` (master spec: empty password is rejected at init and unlock). Under the operation mutex:
  1. **The metadata snapshot is store-global.** The shared GitStore caches `psst.yaml` and carries a single unlocked-fingerprint slot; all live sessions must derive from the same snapshot (the recovery protocol in 3.2 maintains this invariant). A new unlock first re-runs `InitSchema()` on the shared store (idempotent, the same path every CLI command runs): it re-checks the pin — through the per-call `loadPins` wiring of 7.4 — against the current cache, **fail-closes the unlock on any downgrade**, and advances the local pin if the cache was strengthened since the last check. Only then does it read the cached `kdf_*`/`vault_aad` through `GetMeta` and derive the key.
  2. Build a per-session key provider that returns exactly this password (a fixed-value `keyring.KeyProvider` implementation living in `internal/server`; `vault.Unlock()` takes it through the existing `GetRawKey` path — the vault package is not modified for this).
  3. `vault.New(enc, provider, sharedGitStore)` + `Unlock()` → Argon2id key in memory, AAD bound, fingerprint recorded on the store (existing phase-1 logic).
  4. **Verification (decrypt probe).** Argon2id never fails on a wrong password — an unverified key would let a typo'd session encrypt under the wrong key and push undecryptable ciphertext. When the vault has ≥1 secret: pick the first name from `ListSecrets` and `GetSecret` it; decryption failure → close the vault (key zeroed) and return `401 {"error": "wrong password or undecryptable secret <NAME>"}`. When the vault is empty: the key is accepted unverified (`verified: false` in the response; UI shows a notice). This mirrors CLI behavior for empty vaults and is documented as the residual risk.
- Unlock state per session: the `*vault.Vault` + `expiresAt`. **Inactivity timeout 30m, sliding**: every request from the session EXCEPT `GET /api/session` refreshes `expiresAt = now + timeout` (a polling countdown tab must not keep the key alive forever; the UI counts down locally from `unlockExpiresAt` and re-syncs only on real actions). A background sweeper (1 tick/min) closes expired unlocks (keys zeroed) and deletes expired sessions.
- `POST /api/logout`: close the session vault (key zeroed), delete the session, expire the cookie. The token barrier and the unlock die together.
- After unlock expiry the session itself stays valid (token barrier) — writes/reveal return `403 {"error": "vault is locked"}` until re-unlock; the UI re-shows the unlock form.

### 2.3 Middleware (order matters, applied to every request)

1. **Host check** — DNS-rebinding defense. `r.Host` hostname part must be `127.0.0.1`, `localhost`, or `[::1]`; a port, if present, must equal the listener port. Anything else → `403`. Applied to ALL requests including static and login (rebinding must not even reach the login form).
2. **Static assets** — `/`, `/app.js`, `/style.css` served without a session (the SPA must load to show the login form).
3. **Session check on `/api/*`** — everything requires a session except `POST /api/login` and `GET /api/session`; violations → `401`.
4. **Origin check on mutations** (POST/PUT/PATCH/DELETE): `Origin` header is REQUIRED and must be exactly `http://127.0.0.1:<port>`, `http://localhost:<port>`, or `http://[::1]:<port>` (the same hosts the Host check permits). Absent → `403`. Mismatched → `403`. (Maintainer decision: strict; non-browser clients set the header explicitly.)
5. **Unlock check** — mutations and `/value` additionally require a live unlock → else `403 {"error": "vault is locked"}`.

Every `/api/*` response carries `Cache-Control: no-store`. Static responses carry `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-cache`.

## 3. Concurrency and store access

- The `Server` holds one `sync.Mutex` (`opMu`). **Every** handler section that touches the shared GitStore or a session vault holds it — reads, writes, unlock (Argon2id ~0.5s under the lock: acceptable, requests serialize), sweep-driven closes.
- Rationale (phase-1 review finding): `vault.Vault` is not goroutine-safe (plain `key`/`aad` fields, no internal locking), and GitStore's multi-step git sequences assume one logical caller — two concurrent handler goroutines could interleave `ExecTx` nesting and staging state, and would contend on the repo `flock` with wait timeouts against the server's own requests. (The `flock` does serialize same-process callers too — each `LockRepo` opens its own file descriptor — but waiting on ourselves is a failure mode, not a design.) The server is long-lived, so it serializes itself with `opMu`.
- The session registry has its own `sync.RWMutex` (session lookup does not need `opMu`).
- The server is just another client of the clone: a concurrent CLI process on the same machine interleaves through the repo `flock` exactly as in phase 1 (CLI write while serve holds the flock waits; vice versa).

### 3.1 Git-store error mapping

| Store error | HTTP | Effect |
|---|---|---|
| `store.ErrRemoteMetaChanged` | `409 {"error": "vault parameters changed remotely", "reunlock": true}` | Global unlock invalidation — see 3.2; the failing session AND every other session lose their unlock (keys zeroed) |
| `store.ErrConflict` | `409 {"error": "<phase-1 message>"}` (re-set the value or `psst sync --discard-local`) | unchanged |
| `store.ErrPushFailed` (new sentinel, 7.3) | `409 {"error": "<store message: push failed; change is in the local clone, run 'psst sync' later>"}` | unchanged |
| `store.ErrSaltChanged` / `store.ErrKDFWeakened` (pin violation) | `500 {"error": "<phase-1 message>"}`; all session unlocks closed | No auto-recovery — pin violation means tampering; manual rotation procedure required |
| No remote configured (`GitStore.HasRemote() == false`, 7.3) | success + `{"warning": "no remote configured; change is local"}` | unchanged. Known cosmetic gap: a repo with a remote configured but no upstream tracking also stays local without a warning (the warning keys on `remote.origin.url`; the store's push gate keys on upstream tracking) — accepted, a failed push still maps to `ErrPushFailed` |

Stale reads are never silent (§1.3 of the master spec). The store's `ListSecrets`/`GetHistory` discard the divergence flag internally, so the server calls the concrete `SyncPullRead()` on the shared GitStore under `opMu` before answering `GET /api/secrets` and `GET .../history`, and copies a `true` flag into the response's `warning` field (`"local clone has unpushed changes; run psst sync"`). `GET .../value` keeps the store's existing stderr print (visible in the server log) — its schema deliberately has no `warning` field.

### 3.2 Metadata epoch — global unlock invalidation

The unlocked-fingerprint slot is store-global by design (one clone, one key epoch; a per-session slot cannot be expressed through the phase-1 `SecretStore` contract). The server therefore enforces centrally, under `opMu`:

- **On `store.ErrRemoteMetaChanged` from ANY operation** (read or write): close EVERY session vault — a session still holding a key derived from old parameters must never encrypt through a fingerprint slot another unlock refreshed — then `SetUnlockedFingerprint("")` and refresh the metadata snapshot: `SyncPullRead()` (with the slot empty, `reloadMetaAndCheck` accepts the incoming parameters and updates the cache) followed by `InitSchema()` on the shared store. `InitSchema` is the same path every CLI command runs: it re-checks the pin against the refreshed cache and **advances the local pin on KDF strengthening via the existing `SavePins` hook** — without this step the serve host would keep a stale pin, and a later parameter revert would pass `CheckPinned` as `equal`, silently undoing the strengthening (`reloadMetaAndCheck` itself never persists pins). If the refresh cannot complete (repo lock busy, no upstream), the `409` is still returned; the next ordinary read silently refreshes the cache (with the slot empty, no error fires), and the deferred pin advancement lands on the next unlock (2.2 step 1) or the next 3.2 cycle. The failed request returns the 3.1 `409` with `reunlock: true`. Afterwards reads work again and new unlocks derive from the fresh parameters — **no server restart needed**.
- **On `store.ErrSaltChanged` / `store.ErrKDFWeakened`**: close all session vaults, return `500`; recovery is the manual rotation procedure.
- The same close-all applies on graceful shutdown.

## 4. REST API

All requests/responses are JSON (`Content-Type: application/json; charset=utf-8`) except static assets. Request bodies go through `http.MaxBytesReader`: 64 KiB for auth endpoints (`login`, `unlock`, `rollback`), 1 MiB for `POST /api/secrets/{name}`. Malformed JSON → `400`. All timestamps are RFC3339.

| Method + Path | Session | Unlock | Body | Success (`200`) |
|---|---|---|---|---|
| `POST /api/login` | — | — | `{"token": string}` | `{"ok": true}` + cookie |
| `POST /api/logout` | ✔ | — | — | `{"ok": true}` + cookie expired |
| `GET /api/session` | — | — | — | `{"authenticated": bool, "unlocked": bool, "verified": bool, "unlockExpiresAt": string\|null}` |
| `POST /api/unlock` | ✔ | — | `{"password": string}` | `{"ok": true, "verified": bool}` |
| `GET /api/secrets` | ✔ | — | — | `{"secrets": [SecretItem], "warning"?: string}` |
| `POST /api/secrets/{name}` | ✔ | ✔ | `{"value"?: string, "tag"?: string}` | `{"ok": true, "warning"?: string}` |
| `DELETE /api/secrets/{name}` | ✔ | ✔ | — | `{"ok": true}` |
| `GET /api/secrets/{name}/history` | ✔ | — | — | `{"history": [HistoryItem]}` |
| `POST /api/secrets/{name}/rollback` | ✔ | ✔ | `{"version": number}` | `{"ok": true}` |
| `GET /api/secrets/{name}/value` | ✔ | ✔ | — | `{"value": string}` |

`SecretItem` = `{name, tags: [string], createdAt, updatedAt, updatedBy}` — **no value field ever**. `HistoryItem` = `{version, tags, author, archivedAt}` — no value. Routing uses Go 1.22+ `ServeMux` patterns (`"POST /api/secrets/{name}"` + `r.PathValue("name")`); `{name}` is validated against `^[A-Z][A-Z0-9_]*$` (existing `store.ValidSecretName`) → `400` otherwise; tags against `^[a-z][a-z0-9-]*$`.

Semantics:

- `POST /api/secrets/{name}` — create or update. Fields are optional and independently meaningful; the server maps JSON `tag: ""` to an empty/nil tags slice (GitStore rejects a one-element slice containing `""` as `invalid tag ""`):
  - `value` present and non-empty + `tag` absent → `SetSecret(name, value, <current tags>)` (keep the existing tag; looked up via `ListSecrets`).
  - `value` present and non-empty + `tag` present (may be `""` = untag) → `SetSecret(name, value, tags)` with the mapped slice.
  - `value` absent/empty + `tag` present → `RetagSecret(name, tags)` with the mapped slice — tag move **without knowing the value** (ciphertext is relocated; this is the phase-1 `git mv` path).
  - both absent → `400 {"error": "nothing to set"}`.
  - Editing a secret never requires revealing it: the UI value field is empty by default ("leave empty to keep the current value").
- `DELETE /api/secrets/{name}` — `404` if the secret does not exist. Unlock required: every state change sits behind both barriers (an attacker holding only the token must not be able to wipe secrets).
- `GET .../history` — no unlock: names/tags/dates/authors are already public in git (§2); values are not included.
- `POST .../rollback` — unlock required (the target version is decrypted and re-encrypted; the "predates a KDF migration" failure surfaces as `409` with that message).
- `GET .../value` — the **only** endpoint that ever returns a plaintext value. Unlock required. `Cache-Control: no-store`. Not logged (server logs contain names and actions, never values).

Missing secret on read endpoints → `404 {"error": "secret <NAME> not found"}`.

## 5. UI — SPA

Assets in `internal/server/static/`, embedded with `go:embed`, served at `/` (`index.html`), `/app.js`, `/style.css`. No framework, no build step, no inline scripts/styles (CSP forbids them). Secret values are inserted into the DOM exclusively via `textContent` after an explicit reveal action — never `innerHTML`.

Screens (sections toggled by JS; state from `GET /api/session`):

1. **login** — token input (masked field), submit → `/api/login`; wrong token shows the generic error.
2. **list** — tree grouped by tag directory (untagged secrets under a root group); per secret: name, `updatedAt`, `updatedBy` ("changed by machine"); create button; per-secret actions: open, reveal, edit, delete (last three prompt the unlock form when locked).
3. **history** (per secret) — metadata header, history table (`version`, `archivedAt`, `author`, tags) with a rollback button per row, back link.
4. **create/edit form** — name (create only; validated client-side with the same regex), value textarea (empty on edit — never prefilled), tag input (single). Save → POST; errors rendered inline.
5. **unlock form** (modal/section) — password input, submit → `/api/unlock`; empty-vault unlock shows the "password not verified yet" notice; countdown to expiry in the header.
6. Header: vault/env label, unlock state + remaining time, logout.

Behavior: locked sessions see names/tags/dates/authors only (list + history fully usable); create/edit/delete/reveal disabled with an "unlock required" hint. The reveal block has a hide button and a copy button. Sync warnings from `warning` fields render as a banner. A `409` with `reunlock` drops the unlock state and opens the unlock form.

## 6. Error handling and server hygiene

- `http.Server` timeouts: `ReadHeaderTimeout: 5s`, `ReadTimeout: 30s`, `WriteTimeout: 60s`, `IdleTimeout: 120s`.
- Recover middleware: a panicking handler returns `500 {"error": "internal error"}` and logs the panic (message + stack) to stderr — never to the HTTP response.
- Server logging: stderr, one line per request (method, path, status, duration) — values and passwords never logged; reveal requests log the secret NAME and action only.
- Sweeper: one ticker per minute; closes expired unlocks and deletes expired sessions.

## 7. Interface changes (complete list)

1. `store.SecretMeta` and `vault.SecretMeta` gain `UpdatedBy string` — git: author of the latest commit touching the file (folded into the existing `entryTimes` git-log call); SQLite: empty string. Required because §2 puts "commit author as changed-by machine" on the **list** screen, and `ListSecrets` currently returns no author. No `SecretStore` interface signature changes; CLI output is untouched (author remains visible in `psst history`; the CLI list does not print `UpdatedBy`).
2. No changes to `vault.Vault` (unlock-through-provider reuses `GetRawKey`; per-session close reuses `Vault.Close`, which zeroes the key and calls the no-op `GitStore.Close`).
3. Additive `internal/store/git.go` changes (no interface changes, CLI error text unchanged): export `func (g *GitStore) HasRemote() bool` (wraps the existing unexported `hasRemote`) and add `var ErrPushFailed` wrapped into both push error paths (`fmt.Errorf("...: %w", ...)`), so the server can classify push failures with `errors.Is` instead of string matching (the store currently swallows `ErrNoRemote` inside `mutate`/`ExecTx`).
4. `internal/cli/vaultconfig.go`: the `loadPins` closure inside `OpenVaultStore` must re-read `LoadVaultConfig(envDir)` on **every call** (mirroring `savePins`, which already fresh-reads). Today it captures the config struct once at open time — harmless for one-shot CLI commands, but the long-lived server would keep comparing `CheckPinned` against startup parameters forever: after a recovery advances the pin on disk, an in-process revert to the startup params would pass as `equal`, silently downgrading the running server. With the re-read, both the server's own `SavePins` and external processes' advancements are observed.
5. No new dependencies.

## 8. Documentation updates (ship in the same PR)

- `docs/rules/security.md`: §2 of the master spec refinement — Web UI section rewritten from "future phase" to the shipped barrier list (localhost bind, mandatory token, unlock second barrier, Host/Origin checks, SameSite=Strict, reveal as an explicit operator-initiated egress channel alongside `psst get`/`export`).
- `docs/rules/architecture.md`: `server/` layer row; allowed dependencies `cli → server`, `server → {vault, store, crypto, keyring}`; serialization rule for the long-lived server.
- `README.md` (+ `docs/ru` mirror if a serve section exists there): serve flags, token handling, SSH-tunnel remote access recipe.

## 9. Testing

Standard `testing` + `net/http/httptest`, real temporary git repositories (bare remote pattern from phase-1 `git_test.go`), fake values only (`"secret123"`, `"test-password"`), `PSST_NO_KEYCHAIN=1`. Injectable clock for sweeper/timeout tests; injectable stderr writer.

- Token: login success/failure (401, generic body); cookie flags (HttpOnly, SameSite=Strict, Path=/, Max-Age).
- Host middleware: foreign Host → 403; `127.0.0.1:port`, `localhost:port` pass; wrong port → 403.
- Origin: mutation without Origin → 403; wrong Origin → 403; correct Origin passes; GET without Origin passes.
- Static: CSP/nosniff/no-referrer headers; assets served from the embedded FS; traversal/encoded paths (`/../../etc/passwd`, `/%2e%2e/`) resolve inside the embedded FS only → 404, never the host filesystem.
- Locked mode: `GET /api/secrets` and `/history` work without unlock; response bytes must not contain the plaintext of any seeded secret.
- Unlock: wrong password (vault with a seeded secret) → 401 and no unlock; empty password → 400; correct password → reveal works; empty vault → `verified: false`.
- Full API cycle against a real repo with a bare remote: create → list (names, tags, dates, updatedBy) → edit value → retag via tag-only POST → **untag via `{"tag": ""}`** → history grows → rollback → value round-trips → delete → 404.
- Reveal gating: locked → 403; unlocked → 200 with `Cache-Control: no-store`; value absent from every other endpoint's payload.
- Timeout: unlock expiry (injected clock) → reveal 403, session still authenticated; `GET /api/session` polling does NOT refresh the unlock; session expiry (24h) → 401.
- Logout: subsequent reveal 403; cookie expired.
- `ErrRemoteMetaChanged` recovery (3.2): KDF params strengthened behind the server's back via a second store instance → next operation → 409 with `reunlock`, **every** session's unlock dropped; a previously-unlocked stale session cannot push old-key ciphertext afterwards; re-unlock succeeds with the fresh parameters without a server restart.
- `ErrSaltChanged`: salt tampering via a second store instance → 500, all unlocks closed.
- Push failure (non-fast-forward remote) → 409 with the store message; write to a repo without a remote → 200 + `warning`.
- Request body limits: oversized login/rollback (> 64 KiB) and secret value (> 1 MiB) → 413.
- SQLite vault → `serve` startup error mentions `psst migrate storage`.
- Concurrency smoke: parallel list + write + reveal requests under `-race`.

## 10. Non-goals

- No TLS on the server (loopback + SSH-tunnel model).
- No WebSocket/live updates; the UI refreshes on navigation/action.
- No multi-user accounts, no per-secret permissions, no audit log persistence.
- No `PSST_PASSWORD` auto-unlock in serve (barrier 2 is interactive by design).
- No tag management beyond the single tag field (git backend model: one tag = one directory).

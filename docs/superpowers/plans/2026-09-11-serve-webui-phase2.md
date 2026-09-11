# `psst serve` Web UI (Phase 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `psst serve` — a localhost web UI over the existing GitStore: token + unlock two-barrier auth, full secret CRUD/history/rollback/reveal REST API, embedded SPA, zero new dependencies.

**Architecture:** New `internal/server` package (sessions, middleware, handlers, embedded static) driven by a thin `internal/cli/serve.go` cobra wrapper. The server is another client of ONE shared `*store.GitStore`; per-session `vault.Vault` instances hold Argon2id keys; every store/vault operation serializes under one server mutex. Spec: `docs/superpowers/specs/2026-09-11-serve-webui-design.md` (approved after 4 review rounds — read it before starting).

**Tech Stack:** Go 1.26 stdlib only (`net/http` with 1.22+ mux patterns, `go:embed`, `crypto/subtle`, `crypto/sha256`), vanilla JS/CSS (no framework, no build step). Existing deps only.

## Global Constraints

- Tests run ONLY with `PSST_NO_KEYCHAIN=1` (use `make test`; it exports the var). Never run bare `go test` without it — macOS Keychain dialogs hang the run.
- `make test` green before every commit; conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`).
- No new dependencies (`go.mod` untouched). No comments in code (only `//nolint:` directives, matching existing style).
- Error wrapping: `fmt.Errorf("context: %w", err)`. Never log or render secret values; the ONLY endpoint returning a value is `GET /api/secrets/{name}/value` after unlock.
- Test secrets are fakes only (`"secret123"`, `"test-password"`).
- Secret names match `^[A-Z][A-Z0-9_]*$`; tags match `^[a-z][a-z0-9-]*$` (use `store.ValidSecretName`, `store.ValidTag`).
- Module path: `github.com/aatumaykin/psst`. Work in worktree `.worktrees/serve-webui`, branch `feat/serve-webui`.
- `vault.Vault` is not goroutine-safe; the server serializes all vault/store access behind one mutex (spec §3).

---

### Task 1: `UpdatedBy` author through the list stack

Spec §7.1: the list screen shows "changed by machine" — `ListSecrets` must return the git commit author.

**Files:**
- Modify: `internal/store/store.go:14-19` (`SecretMeta`)
- Modify: `internal/vault/types.go:15-20` (`SecretMeta`)
- Modify: `internal/vault/vault.go:265-280` (`ListSecrets` mapping)
- Modify: `internal/store/git.go:515-540` (`entryTimes`), `:753-775` (`ListSecrets`), `:695-724` (`GetSecret`)
- Test: `internal/store/git_test.go`, `internal/vault/vault_test.go`

**Interfaces:**
- Consumes: existing `GitStore.entryTimes`, `GitStore.ListSecrets`.
- Produces: `store.SecretMeta.UpdatedBy string`; `vault.SecretMeta.UpdatedBy string`; `func (g *GitStore) entryTimes(rel string) (created, updated time.Time, author string, err error)` (signature change, unexported).

- [ ] **Step 1: Write failing tests**

Add to `internal/store/git_test.go`:

```go
func TestGitStoreListUpdatedBy(t *testing.T) {
	g, _ := newGitStore(t)
	iv := make([]byte, 12)
	if err := g.SetSecret("KEY", []byte("ct"), iv, nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	metas, err := g.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 {
		t.Fatalf("metas = %d", len(metas))
	}
	if !strings.HasPrefix(metas[0].UpdatedBy, "psst/") {
		t.Fatalf("updatedBy = %q, want psst/<hostname>", metas[0].UpdatedBy)
	}
}
```

Add to `internal/vault/vault_test.go` (uses a git-backed test vault helper; if `newTestGitVault` is absent, add it):

```go
func newTestGitVault(t *testing.T) *Vault {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	s, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("git store: %v", err)
	}
	if err := s.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Setenv("PSST_PASSWORD", "test-password")
	enc := crypto.NewAESGCM()
	return New(enc, keyring.NewPasswordProvider(enc, false), s)
}
```

(`filepath` and the `store`/`keyring` imports may already be present — add only what is missing; `internal/store/git_test.go` needs `strings` added for the first test above.)

```go
func TestVaultListSecretsMapsUpdatedBy(t *testing.T) {
	v := newTestGitVault(t)
	defer v.Close()
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret("KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("set: %v", err)
	}
	metas, err := v.ListSecrets()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(metas) != 1 || metas[0].UpdatedBy == "" {
		t.Fatalf("updatedBy not mapped: %+v", metas)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/store/ ./internal/vault/ -run 'UpdatedBy' -v`
Expected: FAIL — `metas[0].UpdatedBy undefined`.

- [ ] **Step 3: Implement**

`internal/store/store.go` — add to `SecretMeta`:

```go
type SecretMeta struct {
	Name      string
	Tags      []string
	CreatedAt time.Time
	UpdatedAt time.Time
	UpdatedBy string
}
```

`internal/vault/types.go` — same field on `vault.SecretMeta`.

`internal/vault/vault.go` `ListSecrets` mapping — add `UpdatedBy: m.UpdatedBy,`.

`internal/store/git.go` — change `entryTimes` to fold `%an` into the existing newest-commit call:

```go
func (g *GitStore) entryTimes(rel string) (time.Time, time.Time, string, error) {
	out, err := g.git.Run("log", "-1", "--format=%cI%x1f%an", "--", rel)
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	fields := strings.SplitN(strings.TrimSpace(out), "\x1f", 2)
	if len(fields) != 2 {
		return time.Time{}, time.Time{}, "", fmt.Errorf("parse git log output for %s", rel)
	}
	updated, err := time.Parse(time.RFC3339, fields[0])
	if err != nil {
		return time.Time{}, time.Time{}, "", err
	}
	author := fields[1]
	created := updated
	out, err = g.git.Run("log", "--diff-filter=A", "--format=%cI", "--", rel)
	if err == nil {
		first := ""
		for _, line := range strings.Split(out, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				first = line
			}
		}
		if first != "" {
			if ts, terr := time.Parse(time.RFC3339, first); terr == nil {
				created = ts
			}
		}
	}
	return created, updated, author, nil
}
```

Update the two call sites:

- `GetSecret` (around line 716): `created, updated, _, _ = g.entryTimes(rel)`
- `ListSecrets` (around line 767): `created, updated, author, _ := g.entryTimes(rel)` and add `UpdatedBy: author` to the built `SecretMeta`.

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS (all packages).

- [ ] **Step 5: Commit**

```bash
git add internal/store/store.go internal/store/git.go internal/store/git_test.go internal/vault/types.go internal/vault/vault.go internal/vault/vault_test.go
git commit -m "feat: UpdatedBy author in secret list metadata"
```

---

### Task 2: store groundwork — `HasRemote`, `ErrPushFailed`, per-call pins

Spec §7.3/§7.4: the server needs to classify push failures without string matching, detect the no-remote case, and must never compare pins against a startup snapshot.

**Files:**
- Modify: `internal/store/git.go` (add `ErrPushFailed`, `HasRemote`; wrap `push`/`pushAll`)
- Modify: `internal/cli/vaultconfig.go:174-179` (`loadPins` closure)
- Test: `internal/store/git_test.go`, `internal/cli/vaultconfig_test.go`

**Interfaces:**
- Produces: `var ErrPushFailed = errors.New("push failed")` (store); `func (g *GitStore) HasRemote() bool`; `OpenVaultStore`'s `loadPins` re-reads `LoadVaultConfig(envDir)` per call.

- [ ] **Step 1: Write failing tests**

Add to `internal/store/git_test.go`:

```go
func TestGitStoreHasRemote(t *testing.T) {
	g := newClonedStore(t, newBareRemote(t))
	if !g.HasRemote() {
		t.Fatal("cloned store must report remote")
	}
	local, _ := newGitStore(t)
	if local.HasRemote() {
		t.Fatal("local-only store must not report remote")
	}
}

func TestGitStorePushFailedSentinel(t *testing.T) {
	remote := newBareRemote(t)
	g := newClonedStore(t, remote)
	if err := os.Chmod(remote, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(remote, 0o755) })
	iv := make([]byte, 12)
	err := g.SetSecret("KEY", []byte("ct"), iv, nil)
	if err == nil {
		t.Fatal("push to read-only remote must fail")
	}
	if !errors.Is(err, ErrPushFailed) {
		t.Fatalf("err = %v, want ErrPushFailed", err)
	}
	if !strings.Contains(err.Error(), "run `psst sync` later") {
		t.Fatalf("message text changed: %v", err)
	}
}
```

Add to `internal/cli/vaultconfig_test.go`:

```go
func TestOpenVaultStoreLoadPinsFresh(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	repo := filepath.Join(envDir, "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	s, _, err := OpenVaultStore(envDir, "git", "", false)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	cfg, err := LoadVaultConfig(envDir)
	if err != nil {
		t.Fatalf("cfg: %v", err)
	}
	cfg.PinSalt = "AAAAAAAAAAAAAAAAAAAAAA=="
	if err := SaveVaultConfig(envDir, *cfg); err != nil {
		t.Fatalf("save cfg: %v", err)
	}
	err = s.InitSchema()
	if !errors.Is(err, store.ErrSaltChanged) {
		t.Fatalf("InitSchema after pin tamper = %v, want ErrSaltChanged", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/store/ -run 'HasRemote|PushFailed' -v && PSST_NO_KEYCHAIN=1 go test ./internal/cli/ -run LoadPinsFresh -v`
Expected: FAIL — `g.HasRemote undefined`, `ErrPushFailed undefined`; the pins test fails because the closure uses the config captured at open (old pin) → `InitSchema` returns nil.

- [ ] **Step 3: Implement**

`internal/store/git.go` — add to the `var` block at the top:

```go
ErrPushFailed = errors.New("push failed")
```

Add near `hasRemote`:

```go
func (g *GitStore) HasRemote() bool {
	return g.hasRemote()
}
```

Change both push error paths so the message text stays byte-identical for the CLI while carrying the sentinel:

```go
func (g *GitStore) push() error {
	if !g.hasUpstream() {
		return ErrNoRemote
	}
	if _, err := g.git.Run("push"); err != nil {
		return fmt.Errorf("%w; change is in the local clone, run `psst sync` later: %w", ErrPushFailed, err)
	}
	return nil
}

func (g *GitStore) pushAll() error {
	if !g.hasRemote() {
		return ErrNoRemote
	}
	if _, err := g.git.Run("push", "-u", "origin", "HEAD"); err != nil {
		return fmt.Errorf("%w; change is in the local clone, run `psst sync` later: %w", ErrPushFailed, err)
	}
	return nil
}
```

`internal/cli/vaultconfig.go` — replace the `loadPins` closure inside `OpenVaultStore`:

```go
loadPins := func() *store.Pin {
	cur, err := LoadVaultConfig(envDir)
	if err != nil || cur.PinSalt == "" {
		return nil
	}
	return &store.Pin{SaltB64: cur.PinSalt, Params: cur.PinKDF}
}
```

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/git.go internal/store/git_test.go internal/cli/vaultconfig.go internal/cli/vaultconfig_test.go
git commit -m "feat: HasRemote, ErrPushFailed and per-call pin loading"
```

---

### Task 3: server package — sessions, token auth, login/logout/session

**Files:**
- Create: `internal/server/server.go` (Config, Server, New, Handler, Close)
- Create: `internal/server/session.go` (session struct, registry)
- Create: `internal/server/json.go` (writeJSON/writeErr/readBody helpers)
- Create: `internal/server/server_test.go` (shared helpers + auth tests)

**Interfaces:**
- Consumes: `store.GitStore`, `crypto.NewAESGCM()`.
- Produces:

```go
type Config struct {
	Store         *store.GitStore
	Enc           crypto.Encryptor
	Host          string
	Port          string
	TokenDigest   [32]byte
	UnlockTimeout time.Duration
	SessionTTL    time.Duration
	Now           func() time.Time
	Log           *log.Logger
}
func New(cfg Config) *Server
func (s *Server) Handler() http.Handler
func (s *Server) Close()
```

- `session` struct with `id`, `createdAt`, `expiresAt`, `vault *vault.Vault`, `verified bool`, `unlockExpiresAt time.Time`; registry guarded by `sync.RWMutex`; cookie name `psst_session`.

- [ ] **Step 1: Write failing tests**

Create `internal/server/server_test.go` with shared helpers and auth tests:

```go
package server

import (
	"crypto/sha256"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
)

const testToken = "test-token-0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) (*Server, *store.GitStore) {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatalf("git store: %v", err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	digest := sha256.Sum256([]byte(testToken))
	s := New(Config{
		Store: gs, Enc: crypto.NewAESGCM(),
		Host: "127.0.0.1", Port: "7788",
		TokenDigest: digest,
		UnlockTimeout: 30 * time.Minute,
		SessionTTL:    24 * time.Hour,
		Now:           time.Now,
		Log:           log.New(io.Discard, "", 0),
	})
	t.Cleanup(s.Close)
	return s, gs
}

func do(t *testing.T, h http.Handler, method, path, body, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:7788"
	if method != http.MethodGet && method != http.MethodHead {
		req.Header.Set("Origin", "http://127.0.0.1:7788")
	}
	if cookie != "" {
		req.Header.Set("Cookie", "psst_session="+cookie)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loginOK(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/api/login", `{"token":"`+testToken+`"}`, "")
	if rec.Code != 200 {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == "psst_session" {
			return c.Value
		}
	}
	t.Fatal("no session cookie")
	return ""
}

func TestLoginConstantTime(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	rec := do(t, h, http.MethodPost, "/api/login", `{"token":"`+testToken+`"}`, "")
	if rec.Code != 200 {
		t.Fatalf("good token = %d", rec.Code)
	}
	ck := rec.Result().Cookies()[0]
	if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatalf("cookie flags wrong: %+v", ck)
	}
	//nolint:mnd // cookie max-age seconds
	if ck.MaxAge != 24*60*60 {
		t.Fatalf("max-age = %d", ck.MaxAge)
	}
	rec = do(t, h, http.MethodPost, "/api/login", `{"token":"wrong-token"}`, "")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "invalid token") {
		t.Fatalf("bad token = %d %s", rec.Code, rec.Body.String())
	}
}

func TestSessionEndpoints(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	rec := do(t, h, http.MethodGet, "/api/session", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authenticated":false`) {
		t.Fatalf("anon session = %d %s", rec.Code, rec.Body.String())
	}
	ck := loginOK(t, h)
	rec = do(t, h, http.MethodGet, "/api/session", "", ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authenticated":true`) {
		t.Fatalf("auth session = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/secrets", "", "")
	if rec.Code != 401 {
		t.Fatalf("unauth list = %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/logout", "", ck)
	if rec.Code != 200 {
		t.Fatalf("logout = %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/session", "", ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authenticated":false`) {
		t.Fatalf("session after logout = %d %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: FAIL — package does not compile (`New undefined`).

- [ ] **Step 3: Implement**

`internal/server/json.go`:

```go
package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return nil, false
		}
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	return b, true
}
```

`internal/server/session.go`:

```go
package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/aatumaykin/psst/internal/vault"
)

const sessionCookie = "psst_session"

type session struct {
	id              string
	createdAt       time.Time
	expiresAt       time.Time
	vault           *vault.Vault
	verified        bool
	unlockExpiresAt time.Time
}

func newSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sessionCookieHeader(id string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: maxAge,
	}
}
```

`internal/server/server.go` (auth part; middleware and remaining handlers are added in later tasks — this task compiles with login/logout/session only):

```go
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/store"
)

type Config struct {
	Store         *store.GitStore
	Enc           crypto.Encryptor
	Host          string
	Port          string
	TokenDigest   [sha256.Size]byte
	UnlockTimeout time.Duration
	SessionTTL    time.Duration
	Now           func() time.Time
	Log           *log.Logger
}

type Server struct {
	cfg      Config
	sessMu   sync.RWMutex
	sessions map[string]*session
	opMu     sync.Mutex
}

func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = log.New(os.Stderr, "", log.LstdFlags)
	}
	return &Server{cfg: cfg, sessions: make(map[string]*session)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	return mux
}

func (s *Server) Close() {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, sess := range s.sessions {
		s.closeVaultLocked(sess)
	}
	s.sessions = make(map[string]*session)
}

func (s *Server) closeVaultLocked(sess *session) {
	if sess.vault != nil {
		_ = sess.vault.Close()
		sess.vault = nil
	}
	sess.verified = false
	sess.unlockExpiresAt = time.Time{}
}

func (s *Server) sessionFromRequest(r *http.Request) *session {
	ck, err := r.Cookie(sessionCookie)
	if err != nil || ck.Value == "" {
		return nil
	}
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	sess := s.sessions[ck.Value]
	if sess == nil || !sess.expiresAt.After(s.cfg.Now()) {
		return nil
	}
	return sess
}

type loginRequest struct {
	Token string `json:"token"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 64*1024)
	if !ok {
		return
	}
	var req loginRequest
	if err := jsonUnmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	digest := sha256.Sum256([]byte(req.Token))
	if subtle.ConstantTimeCompare(digest[:], s.cfg.TokenDigest[:]) != 1 {
		writeErr(w, http.StatusUnauthorized, "invalid token")
		return
	}
	now := s.cfg.Now()
	sess := &session{
		id:        newSessionID(),
		createdAt: now,
		expiresAt: now.Add(s.cfg.SessionTTL),
	}
	s.sessMu.Lock()
	s.sessions[sess.id] = sess
	s.sessMu.Unlock()
	http.SetCookie(w, sessionCookieHeader(sess.id, int(s.cfg.SessionTTL.Seconds())))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	resp := map[string]any{"authenticated": false, "unlocked": false, "verified": false, "unlockExpiresAt": nil}
	if sess != nil {
		s.serveSessionState(w, sess, resp)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
```

Add the state builder and logout in `session.go`:

```go
func (s *Server) serveSessionState(w http.ResponseWriter, sess *session, resp map[string]any) {
	now := s.cfg.Now()
	s.sessMu.RLock()
	unlocked := sess.vault != nil && sess.unlockExpiresAt.After(now)
	verified := sess.verified && unlocked
	expires := sess.unlockExpiresAt
	s.sessMu.RUnlock()
	resp["authenticated"] = true
	resp["unlocked"] = unlocked
	resp["verified"] = verified
	if unlocked {
		resp["unlockExpiresAt"] = expires.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := s.sessionFromRequest(r)
	if sess == nil {
		writeErr(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	s.opMu.Lock()
	s.sessMu.Lock()
	s.closeVaultLocked(sess)
	delete(s.sessions, sess.id)
	s.sessMu.Unlock()
	s.opMu.Unlock()
	http.SetCookie(w, sessionCookieHeader("", -1))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
```

Add `jsonUnmarshal` to `json.go`:

```go
func jsonUnmarshal(body []byte, v any) error {
	return json.Unmarshal(body, v)
}
```

Add the missing `crypto` import to `server.go` (`github.com/aatumaykin/psst/internal/crypto`).

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: server session registry and token auth"
```

---

### Task 4: host and origin middleware

Spec §2.3: Host allowlist on every request (DNS-rebinding), strict Origin on mutations; recover + request logging; API no-store is already in writeJSON.

**Files:**
- Modify: `internal/server/server.go` (middleware chain in `Handler()`)
- Create: `internal/server/middleware.go`
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Produces: `func (s *Server) hostAllowed(host string) bool`; middleware wiring order `recover → log → host → origin → mux`.

- [ ] **Step 1: Write failing tests**

Add to `internal/server/server_test.go`:

```go
func TestHostMiddleware(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	rec := do(t, h, http.MethodGet, "/api/session", "", "")
	if rec.Code != 200 {
		t.Fatalf("loopback host = %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Host = "evil.example.com:7788"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 403 {
		t.Fatalf("foreign host = %d", rec2.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Host = "127.0.0.1:9999"
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req)
	if rec3.Code != 403 {
		t.Fatalf("wrong port = %d", rec3.Code)
	}
	req = httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Host = "localhost:7788"
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req)
	if rec4.Code != 200 {
		t.Fatalf("localhost host = %d", rec4.Code)
	}
}

func TestOriginMiddleware(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := do(t, h, http.MethodPost, "/api/logout", "", ck)
	if rec.Code != 200 {
		t.Fatalf("mutation with origin = %d", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"token":"x"}`))
	req.Host = "127.0.0.1:7788"
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != 403 {
		t.Fatalf("mutation without origin = %d", rec2.Code)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"token":"x"}`))
	req.Host = "127.0.0.1:7788"
	req.Header.Set("Origin", "https://evil.example.com")
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req)
	if rec3.Code != 403 {
		t.Fatalf("foreign origin = %d", rec3.Code)
	}
}
```

Note: after the first logout the cookie is dead — the second and third requests hit `/api/login` (no session needed) so ordering stays valid.

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run 'HostMiddleware|OriginMiddleware' -v`
Expected: FAIL — foreign host returns 200 (no middleware yet).

- [ ] **Step 3: Implement**

Create `internal/server/middleware.go`:

```go
package server

import (
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Log.Printf("panic %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		s.cfg.Log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) hostAllowed(host string) bool {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h, port = host, s.cfg.Port
	}
	if port != s.cfg.Port {
		return false
	}
	switch h {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func (s *Server) hostMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	switch origin {
	case fmt.Sprintf("http://127.0.0.1:%s", s.cfg.Port),
		fmt.Sprintf("http://localhost:%s", s.cfg.Port),
		fmt.Sprintf("http://[::1]:%s", s.cfg.Port):
		return true
	}
	return false
}

func (s *Server) isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func (s *Server) originMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isMutation(r.Method) {
			origin := r.Header.Get("Origin")
			if origin == "" || !s.originAllowed(origin) {
				writeErr(w, http.StatusForbidden, "origin not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
```

Wire the chain in `Handler()` (`server.go`):

```go
	return s.recoverMW(s.logMW(s.hostMW(s.originMW(mux))))
```

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS (all previous tests still green — `do()` already sends the correct Origin).

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: serve host and origin middleware"
```

---

### Task 5: unlock endpoint with decrypt probe

Spec §2.2: `POST /api/unlock` under `opMu` — `InitSchema` (pin re-check, per-call `loadPins`), fixed-value provider, `vault.Unlock`, decrypt probe on the first listed secret; empty password 400; wrong password 401; empty vault `verified:false`; sliding 30-min expiry (refreshed everywhere except `GET /api/session`); `Sweep()` closes expired unlocks and sessions.

**Files:**
- Create: `internal/server/unlock.go`
- Create: `internal/server/api.go` (store-error mapping + recovery helpers only — read/write handlers come in Tasks 6-7)
- Modify: `internal/server/server.go` (route + session touch wiring)
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Consumes: `keyring.KeyProvider` (4-method interface), `vault.New/Unlock/Close`, Task 2 `InitSchema` pins.
- Produces:
  - `type fixedPasswordProvider struct{ password string }` implementing `keyring.KeyProvider`
  - `func (s *Server) Sweep()`
  - `func (s *Server) apiHandler(unlockRequired bool, h func(w http.ResponseWriter, r *http.Request, sess *session)) http.HandlerFunc`
  - `func (s *Server) touch(sess *session)`
  - `func (s *Server) writeStoreError(w http.ResponseWriter, err error)` — full §3.1 mapping incl. `recoverMetaChanged`/`invalidateUnlocks`

- [ ] **Step 1: Write failing tests**

Add to `internal/server/server_test.go`:

```go
func seedGitSecret(t *testing.T, gs *store.GitStore) {
	t.Helper()
	v := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, gs)
	if err := v.Unlock(); err != nil {
		t.Fatalf("seed unlock: %v", err)
	}
	if err := v.SetSecret("API_KEY", []byte("secret123"), []string{"prod"}); err != nil {
		t.Fatalf("seed set: %v", err)
	}
}

func unlockVault(t *testing.T, h http.Handler, ck, password string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, h, http.MethodPost, "/api/unlock", `{"password":"`+password+`"}`, ck)
}

func TestUnlockFlow(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := unlockVault(t, h, ck, "wrong-password")
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), "wrong password") {
		t.Fatalf("wrong password = %d %s", rec.Code, rec.Body.String())
	}
	rec = unlockVault(t, h, ck, "")
	if rec.Code != 400 {
		t.Fatalf("empty password = %d", rec.Code)
	}
	rec = unlockVault(t, h, ck, "test-password")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"verified":true`) {
		t.Fatalf("unlock = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/session", "", ck)
	if !strings.Contains(rec.Body.String(), `"unlocked":true`) {
		t.Fatalf("session state: %s", rec.Body.String())
	}
}

func TestUnlockEmptyVaultUnverified(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := unlockVault(t, h, ck, "test-password")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"verified":false`) {
		t.Fatalf("empty vault unlock = %d %s", rec.Code, rec.Body.String())
	}
}

func TestUnlockExpirySweep(t *testing.T) {
	now := time.Now()
	s, _ := newTestServer(t)
	s.cfg.Now = func() time.Time { return now }
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	s.cfg.Now = func() time.Time { return now.Add(31 * time.Minute) }
	s.Sweep()
	rec := do(t, h, http.MethodGet, "/api/session", "", ck)
	if !strings.Contains(rec.Body.String(), `"unlocked":false`) {
		t.Fatalf("after sweep: %s", rec.Body.String())
	}
}

func TestTouchSemantics(t *testing.T) {
	now := time.Now()
	s, _ := newTestServer(t)
	s.cfg.Now = func() time.Time { return now }
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	s.cfg.Now = func() time.Time { return now.Add(29 * time.Minute) }
	for i := 0; i < 3; i++ {
		if rec := do(t, h, http.MethodGet, "/api/session", "", ck); rec.Code != 200 {
			t.Fatalf("session poll: %d", rec.Code)
		}
	}
	s.cfg.Now = func() time.Time { return now.Add(31 * time.Minute) }
	s.Sweep()
	if rec := do(t, h, http.MethodGet, "/api/session", "", ck); !strings.Contains(rec.Body.String(), `"unlocked":false`) {
		t.Fatal("GET /api/session polling must not refresh the unlock timer")
	}
	s.cfg.Now = func() time.Time { return now }
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("re-unlock: %d", rec.Code)
	}
	s.cfg.Now = func() time.Time { return now.Add(29 * time.Minute) }
	if rec := do(t, h, http.MethodGet, "/api/secrets", "", ck); rec.Code != 200 {
		t.Fatalf("real request: %d", rec.Code)
	}
	s.cfg.Now = func() time.Time { return now.Add(31 * time.Minute) }
	s.Sweep()
	if rec := do(t, h, http.MethodGet, "/api/session", "", ck); !strings.Contains(rec.Body.String(), `"unlocked":true`) {
		t.Fatal("a real request must refresh the unlock timer")
	}
}

func TestSessionExpiry(t *testing.T) {
	now := time.Now()
	s, _ := newTestServer(t)
	s.cfg.Now = func() time.Time { return now }
	h := s.Handler()
	ck := loginOK(t, h)
	s.cfg.Now = func() time.Time { return now.Add(25 * time.Hour) }
	if rec := do(t, h, http.MethodGet, "/api/secrets", "", ck); rec.Code != 401 {
		t.Fatalf("expired session = %d", rec.Code)
	}
}

func TestWriteStoreErrorMapping(t *testing.T) {
	s, _ := newTestServer(t)
	w := httptest.NewRecorder()
	s.writeStoreError(w, fmt.Errorf("%w; change is in the local clone: %w", store.ErrPushFailed, errors.New("boom")))
	if w.Code != 409 || !strings.Contains(w.Body.String(), "psst sync") {
		t.Fatalf("push = %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.writeStoreError(w, fmt.Errorf("meta: %w", store.ErrSaltChanged))
	if w.Code != 500 {
		t.Fatalf("salt = %d", w.Code)
	}
}

func TestBodyLimit413(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	big := `{"token":"` + strings.Repeat("x", 100*1024) + `"}`
	rec := do(t, h, http.MethodPost, "/api/login", big, "")
	if rec.Code != 413 {
		t.Fatalf("oversized login = %d", rec.Code)
	}
}
```

Add the `vault` import (`github.com/aatumaykin/psst/internal/vault`) to the test file imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run 'Unlock' -v`
Expected: FAIL — `fixedPasswordProvider undefined`, 404 on `/api/unlock`.

- [ ] **Step 3: Implement**

Create `internal/server/unlock.go`:

```go
package server

import (
	"errors"
	"net/http"

	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/vault"
)

type fixedPasswordProvider struct {
	password string
}

func (p *fixedPasswordProvider) GetRawKey(_, _ string) (string, error) {
	return p.password, nil
}

func (p *fixedPasswordProvider) SetKey(_, _ string, _ []byte) error {
	return errors.New("fixed provider is read-only")
}

func (p *fixedPasswordProvider) IsAvailable() bool {
	return true
}

func (p *fixedPasswordProvider) GenerateKey() ([]byte, error) {
	return nil, errors.New("fixed provider cannot generate keys")
}

type unlockRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request, sess *session) {
	body, ok := readBody(w, r, 64*1024)
	if !ok {
		return
	}
	var req unlockRequest
	if err := jsonUnmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Password == "" {
		writeErr(w, http.StatusBadRequest, "empty password")
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if err := s.cfg.Store.InitSchema(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	v := vault.New(s.cfg.Enc, &fixedPasswordProvider{password: req.Password}, s.cfg.Store)
	if err := v.Unlock(); err != nil {
		writeErr(w, http.StatusInternalServerError, "unlock failed")
		return
	}
	verified := false
	metas, err := v.ListSecrets()
	if err != nil {
		_ = v.Close()
		s.writeStoreError(w, err)
		return
	}
	if len(metas) > 0 {
		if _, err := v.GetSecret(metas[0].Name); err != nil {
			_ = v.Close()
			writeErr(w, http.StatusUnauthorized, "wrong password or undecryptable secret "+metas[0].Name)
			return
		}
		verified = true
	}
	now := s.cfg.Now()
	s.sessMu.Lock()
	s.closeVaultLocked(sess)
	sess.vault = v
	sess.verified = verified
	sess.unlockExpiresAt = now.Add(s.cfg.UnlockTimeout)
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "verified": verified})
}

func (s *Server) touch(sess *session) {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	if sess.vault != nil && sess.unlockExpiresAt.After(s.cfg.Now()) {
		sess.unlockExpiresAt = s.cfg.Now().Add(s.cfg.UnlockTimeout)
	}
}

func (s *Server) Sweep() {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	now := s.cfg.Now()
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for id, sess := range s.sessions {
		if !sess.expiresAt.After(now) {
			s.closeVaultLocked(sess)
			delete(s.sessions, id)
			continue
		}
		if sess.vault != nil && !sess.unlockExpiresAt.After(now) {
			s.closeVaultLocked(sess)
		}
	}
}
```

Extend `Handler()` in `server.go` with the api wrapper and route:

```go
	mux.HandleFunc("POST /api/unlock", s.apiHandler(false, s.handleUnlock))
```

Add the wrapper to `session.go`:

```go
func (s *Server) apiHandler(unlockRequired bool, h func(w http.ResponseWriter, r *http.Request, sess *session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFromRequest(r)
		if sess == nil {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		if !(r.Method == http.MethodGet && r.URL.Path == "/api/session") {
			s.touch(sess)
		}
		if unlockRequired {
			s.sessMu.RLock()
			unlocked := sess.vault != nil && sess.unlockExpiresAt.After(s.cfg.Now())
			s.sessMu.RUnlock()
			if !unlocked {
				writeErr(w, http.StatusForbidden, "vault is locked")
				return
			}
		}
		h(w, r, sess)
	}
}
```

Create `internal/server/api.go` with the store-error mapping (spec §3.1/§3.2). `invalidateUnlocks` and `recoverMetaChanged` are called only from `writeStoreError`, which is only invoked by handlers holding `opMu`; they take `sessMu` internally so the sessions map is never accessed unsafely:

```go
package server

import (
	"errors"
	"net/http"

	"github.com/aatumaykin/psst/internal/store"
)

func (s *Server) writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrRemoteMetaChanged):
		s.recoverMetaChanged()
		writeJSON(w, http.StatusConflict, map[string]any{"error": "vault parameters changed remotely", "reunlock": true})
	case errors.Is(err, store.ErrSaltChanged), errors.Is(err, store.ErrKDFWeakened):
		s.invalidateUnlocks()
		writeErr(w, http.StatusInternalServerError, err.Error())
	case errors.Is(err, store.ErrConflict), errors.Is(err, store.ErrPushFailed):
		writeErr(w, http.StatusConflict, err.Error())
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

func (s *Server) invalidateUnlocks() {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	for _, sess := range s.sessions {
		s.closeVaultLocked(sess)
	}
}

func (s *Server) recoverMetaChanged() {
	s.invalidateUnlocks()
	s.cfg.Store.SetUnlockedFingerprint("")
	_, _ = s.cfg.Store.SyncPullRead()
	_ = s.cfg.Store.InitSchema()
}
```

Add imports to the test file: `fmt`, `errors`, and `github.com/aatumaykin/psst/internal/store` (if not already present).

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS (unlock tests take ~2-4s each — Argon2id).

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: vault unlock endpoint with decrypt probe"
```

---

### Task 6: list and history endpoints (locked mode)

Spec §4: `GET /api/secrets` and `GET .../history` need no unlock; the server calls `SyncPullRead()` itself and surfaces the divergence warning; names/tags/dates/authors only — never values.

**Files:**
- Modify: `internal/server/api.go` (add DTOs + read handlers; error mapping already exists from Task 5)
- Modify: `internal/server/server.go` (routes)
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Produces:
  - `func (s *Server) handleList(w, r, sess)`, `func (s *Server) handleHistory(w, r, sess)`
  - `type secretItem`, `type historyItem`, `func formatTime`, `func validNameOr400`
  - `func (s *Server) secretExists(name string) bool`

- [ ] **Step 1: Write failing tests**

Add to `internal/server/server_test.go`:

```go
func TestListLockedNoValues(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := do(t, h, http.MethodGet, "/api/secrets", "", ck)
	if rec.Code != 200 {
		t.Fatalf("list = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret123") {
		t.Fatal("plaintext leaked into list response")
	}
	if !strings.Contains(rec.Body.String(), `"name":"API_KEY"`) || !strings.Contains(rec.Body.String(), `"updatedBy"`) {
		t.Fatalf("list payload: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tag":"prod"`) && !strings.Contains(rec.Body.String(), `"tags":["prod"]`) {
		t.Fatalf("tags missing: %s", rec.Body.String())
	}
}

func TestHistoryLockedNoValues(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	v := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, gs)
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret("API_KEY", []byte("secret456"), []string{"prod"}); err != nil {
		t.Fatalf("set2: %v", err)
	}
	h := s.Handler()
	ck := loginOK(t, h)
	rec := do(t, h, http.MethodGet, "/api/secrets/API_KEY/history", "", ck)
	if rec.Code != 200 {
		t.Fatalf("history = %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret123") || strings.Contains(rec.Body.String(), "secret456") {
		t.Fatal("plaintext leaked into history response")
	}
	if !strings.Contains(rec.Body.String(), `"version"`) || !strings.Contains(rec.Body.String(), `"author"`) {
		t.Fatalf("history payload: %s", rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/NOPE/history", "", ck)
	if rec.Code != 404 {
		t.Fatalf("missing history = %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/bad_name/history", "", ck)
	if rec.Code != 400 {
		t.Fatalf("invalid name = %d", rec.Code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run 'ListLocked|HistoryLocked' -v`
Expected: FAIL — 404 (routes not registered).

- [ ] **Step 3: Implement**

Add to `internal/server/api.go` (keep the Task 5 content; add the `time` import):

```go
type secretItem struct {
	Name      string   `json:"name"`
	Tags      []string `json:"tags"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
	UpdatedBy string   `json:"updatedBy"`
}

type historyItem struct {
	Version    int      `json:"version"`
	Tags       []string `json:"tags"`
	Author     string   `json:"author"`
	ArchivedAt string   `json:"archivedAt"`
}

func formatTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339)
}

func validNameOr400(w http.ResponseWriter, name string) bool {
	if !store.ValidSecretName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid secret name")
		return false
	}
	return true
}

func (s *Server) secretExists(name string) bool {
	sec, err := s.cfg.Store.GetSecret(name)
	return err == nil && sec != nil
}

func (s *Server) handleList(w http.ResponseWriter, _ *http.Request, _ *session) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	resp := map[string]any{"secrets": []secretItem{}}
	diverged, err := s.cfg.Store.SyncPullRead()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	metas, err := s.cfg.Store.ListSecrets()
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	items := make([]secretItem, 0, len(metas))
	for _, m := range metas {
		items = append(items, secretItem{
			Name: m.Name, Tags: m.Tags,
			CreatedAt: formatTime(m.CreatedAt), UpdatedAt: formatTime(m.UpdatedAt), UpdatedBy: m.UpdatedBy,
		})
	}
	resp["secrets"] = items
	if diverged {
		resp["warning"] = "local clone has unpushed changes; run psst sync"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, _ *session) {
	name := r.PathValue("name")
	if !validNameOr400(w, name) {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	resp := map[string]any{"history": []historyItem{}}
	if _, err := s.cfg.Store.SyncPullRead(); err != nil {
		s.writeStoreError(w, err)
		return
	}
	if !s.secretExists(name) {
		writeErr(w, http.StatusNotFound, "secret "+name+" not found")
		return
	}
	entries, err := s.cfg.Store.GetHistory(name)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	items := make([]historyItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, historyItem{
			Version: e.Version, Tags: e.Tags, Author: e.Author, ArchivedAt: formatTime(e.ArchivedAt),
		})
	}
	resp["history"] = items
	writeJSON(w, http.StatusOK, resp)
}
```

Register routes in `Handler()`:

```go
	mux.HandleFunc("GET /api/secrets", s.apiHandler(false, s.handleList))
	mux.HandleFunc("GET /api/secrets/{name}/history", s.apiHandler(false, s.handleHistory))
```

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: serve secrets list and history endpoints"
```

---

### Task 7: write endpoints + global recovery protocol

Spec §4 semantics + §3.1/§3.2: POST (value/tag matrix, `tag:""` → nil slice), DELETE, rollback; error mapping incl. `ErrRemoteMetaChanged` global recovery (verified end-to-end here), push-failure 409, no-remote warning.

**Files:**
- Modify: `internal/server/api.go` (add handlers)
- Modify: `internal/server/server.go` (routes)
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Consumes: `vault.SetSecret/RetagSecret/DeleteSecret/Rollback`, Task 2 `HasRemote`.
- Produces: `handleSet`, `handleDelete`, `handleRollback` (all `apiHandler(true, ...)`).

- [ ] **Step 1: Write failing tests**

Add to `internal/server/server_test.go`:

```go
func TestWriteCycle(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"new-secret123","tag":"prod"}`, ck)
	if rec.Code != 200 {
		t.Fatalf("create = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"v2-secret123","tag":"stage"}`, ck)
	if rec.Code != 200 {
		t.Fatalf("edit+retag = %d %s", rec.Code, rec.Body.String())
	}
	metas, _ := gs.ListSecrets()
	for _, m := range metas {
		if m.Name == "NEW_KEY" && (len(m.Tags) != 1 || m.Tags[0] != "stage") {
			t.Fatalf("retag = %+v", m.Tags)
		}
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"tag":"prod2"}`, ck)
	if rec.Code != 200 {
		t.Fatalf("tag-only move = %d %s", rec.Code, rec.Body.String())
	}
	metas, _ = gs.ListSecrets()
	for _, m := range metas {
		if m.Name == "NEW_KEY" && (len(m.Tags) != 1 || m.Tags[0] != "prod2") {
			t.Fatalf("tag-only = %+v", m.Tags)
		}
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"tag":""}`, ck)
	if rec.Code != 200 {
		t.Fatalf("untag = %d %s", rec.Code, rec.Body.String())
	}
	metas, _ = gs.ListSecrets()
	for _, m := range metas {
		if m.Name == "NEW_KEY" && len(m.Tags) != 0 {
			t.Fatalf("untag left tags: %+v", m)
		}
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{}`, ck)
	if rec.Code != 400 {
		t.Fatalf("empty body = %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/bad_name", `{"value":"x"}`, ck)
	if rec.Code != 400 {
		t.Fatalf("bad name = %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x","tag":"Bad"}`, ck)
	if rec.Code != 400 {
		t.Fatalf("bad tag = %d", rec.Code)
	}
	rec = do(t, h, http.MethodDelete, "/api/secrets/API_KEY", "", ck)
	if rec.Code != 200 {
		t.Fatalf("delete = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodDelete, "/api/secrets/API_KEY", "", ck)
	if rec.Code != 404 {
		t.Fatalf("delete missing = %d", rec.Code)
	}
}

func TestRollbackEndpoint(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	v := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, gs)
	if err := v.Unlock(); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if err := v.SetSecret("API_KEY", []byte("secret456"), nil); err != nil {
		t.Fatalf("set2: %v", err)
	}
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/secrets/API_KEY/rollback", `{"version":1}`, ck)
	if rec.Code != 200 {
		t.Fatalf("rollback = %d %s", rec.Code, rec.Body.String())
	}
	got, err := v.GetSecret("API_KEY")
	if err != nil || string(got.Value) != "secret123" {
		t.Fatalf("rollback value = %q %v", got.Value, err)
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/API_KEY/rollback", `{"version":99}`, ck)
	if rec.Code != 404 {
		t.Fatalf("rollback missing version = %d", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NOPE/rollback", `{"version":1}`, ck)
	if rec.Code != 404 {
		t.Fatalf("rollback missing secret = %d", rec.Code)
	}
}

func TestWriteRequiresUnlock(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck)
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), "locked") {
		t.Fatalf("locked write = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodDelete, "/api/secrets/API_KEY", "", ck)
	if rec.Code != 403 {
		t.Fatalf("locked delete = %d", rec.Code)
	}
}

Add a `newBareRemote` helper (copy from `internal/store/git_test.go`; add `os/exec` to the test imports):

```go
func newBareRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}
```

The recovery test performs a REAL strengthening migration through exported APIs only: decrypt with a vault holding the OLD key, bump params via `SetMeta`, re-encrypt+push through a vault unlocked under the NEW params (what `psst migrate kdf` does). Without the re-encryption the post-recovery unlock probe could not decrypt and the test would be wrong.

```go
func TestRemoteMetaChangedRecovery(t *testing.T) {
	remote := newBareRemote(t)
	repo := filepath.Join(t.TempDir(), "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatalf("init: %v", err)
	}
	seed := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, gs)
	if err := seed.Unlock(); err != nil {
		t.Fatalf("seed unlock: %v", err)
	}
	if err := seed.SetSecret("API_KEY", []byte("secret123"), nil); err != nil {
		t.Fatalf("seed set (pushes): %v", err)
	}

	digest := sha256.Sum256([]byte(testToken))
	s := New(Config{
		Store: gs, Enc: crypto.NewAESGCM(),
		Host: "127.0.0.1", Port: "7788", TokenDigest: digest,
		UnlockTimeout: 30 * time.Minute, SessionTTL: 24 * time.Hour,
		Now: time.Now, Log: log.New(io.Discard, "", 0),
	})
	t.Cleanup(s.Close)
	h := s.Handler()
	ck1 := loginOK(t, h)
	if rec := unlockVault(t, h, ck1, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock1: %d", rec.Code)
	}
	ck2 := loginOK(t, h)
	if rec := unlockVault(t, h, ck2, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock2: %d", rec.Code)
	}

	other, err := store.NewGitStore(filepath.Join(t.TempDir(), "repo2"), store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("other: %v", err)
	}
	if err := other.Sync(); err != nil {
		t.Fatalf("other sync: %v", err)
	}
	oldV := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, other)
	if err := oldV.Unlock(); err != nil {
		t.Fatalf("old unlock: %v", err)
	}
	got, err := oldV.GetSecret("API_KEY")
	if err != nil {
		t.Fatalf("old-key decrypt: %v", err)
	}
	if err := other.SetMeta("kdf_time", "4"); err != nil {
		t.Fatalf("strengthen: %v", err)
	}
	mig := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, other)
	if err := mig.Unlock(); err != nil {
		t.Fatalf("mig unlock: %v", err)
	}
	if err := mig.SetSecret("API_KEY", got.Value, got.Tags); err != nil {
		t.Fatalf("mig re-encrypt+push: %v", err)
	}

	rec := do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck1)
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "reunlock") {
		t.Fatalf("stale write = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/session", "", ck1)
	if strings.Contains(rec.Body.String(), `"unlocked":true`) {
		t.Fatal("requesting session must lose its unlock")
	}
	rec = do(t, h, http.MethodGet, "/api/session", "", ck2)
	if strings.Contains(rec.Body.String(), `"unlocked":true`) {
		t.Fatal("EVERY session must lose its unlock after recovery")
	}
	rec = unlockVault(t, h, ck1, "test-password")
	if rec.Code != 200 {
		t.Fatalf("re-unlock after recovery = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck1)
	if rec.Code != 200 {
		t.Fatalf("write after re-unlock = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/API_KEY/value", "", ck1)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "secret123") {
		t.Fatalf("reveal after recovery = %d %s", rec.Code, rec.Body.String())
	}
}

```go
func TestNoRemoteWarning(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	rec := do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "no remote configured") {
		t.Fatalf("no-remote write = %d %s", rec.Code, rec.Body.String())
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run 'WriteCycle|RollbackEndpoint|WriteRequiresUnlock|RemoteMetaChanged|NoRemoteWarning' -v`
Expected: FAIL — routes not registered (404/405).

- [ ] **Step 3: Implement**

Add to `internal/server/api.go`:

```go
type setRequest struct {
	Value *string `json:"value"`
	Tag   *string `json:"tag"`
}

type rollbackRequest struct {
	Version int `json:"version"`
}

func validTagOr400(w http.ResponseWriter, tag string) bool {
	if tag != "" && !store.ValidTag.MatchString(tag) {
		writeErr(w, http.StatusBadRequest, "invalid tag")
		return false
	}
	return true
}

func tagsFrom(tag *string) []string {
	if tag == nil || *tag == "" {
		return nil
	}
	return []string{*tag}
}

func (s *Server) handleSet(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !validNameOr400(w, name) {
		return
	}
	body, ok := readBody(w, r, 1024*1024)
	if !ok {
		return
	}
	var req setRequest
	if err := jsonUnmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Tag != nil && !validTagOr400(w, *req.Tag) {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	v := sess.vault
	var err error
	switch {
	case req.Value != nil && *req.Value != "":
		tags := tagsFrom(req.Tag)
		if req.Tag == nil {
			tags = s.currentTagsLocked(name)
		}
		err = v.SetSecret(name, []byte(*req.Value), tags)
	case req.Tag != nil:
		if !s.secretExists(name) {
			writeErr(w, http.StatusNotFound, "secret "+name+" not found")
			return
		}
		err = v.RetagSecret(name, tagsFrom(req.Tag))
	default:
		writeErr(w, http.StatusBadRequest, "nothing to set")
		return
	}
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	resp := map[string]any{"ok": true}
	if !s.cfg.Store.HasRemote() {
		resp["warning"] = "no remote configured; change is local"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) currentTagsLocked(name string) []string {
	metas, err := s.cfg.Store.ListSecrets()
	if err != nil {
		return nil
	}
	for _, m := range metas {
		if m.Name == name {
			return m.Tags
		}
	}
	return nil
}

func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !validNameOr400(w, name) {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.secretExists(name) {
		writeErr(w, http.StatusNotFound, "secret "+name+" not found")
		return
	}
	if err := sess.vault.DeleteSecret(name); err != nil {
		s.writeStoreError(w, err)
		return
	}
	resp := map[string]any{"ok": true}
	if !s.cfg.Store.HasRemote() {
		resp["warning"] = "no remote configured; change is local"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !validNameOr400(w, name) {
		return
	}
	body, ok := readBody(w, r, 64*1024)
	if !ok {
		return
	}
	var req rollbackRequest
	if err := jsonUnmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.secretExists(name) {
		writeErr(w, http.StatusNotFound, "secret "+name+" not found")
		return
	}
	if err := sess.vault.Rollback(name, req.Version); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "predates a KDF migration") {
			writeErr(w, http.StatusConflict, msg)
			return
		}
		if strings.Contains(msg, "not found") {
			writeErr(w, http.StatusNotFound, msg)
			return
		}
		s.writeStoreError(w, err)
		return
	}
	resp := map[string]any{"ok": true}
	if !s.cfg.Store.HasRemote() {
		resp["warning"] = "no remote configured; change is local"
	}
	writeJSON(w, http.StatusOK, resp)
}
```

Add `strings` to `api.go` imports. Register routes in `Handler()`:

```go
	mux.HandleFunc("POST /api/secrets/{name}", s.apiHandler(true, s.handleSet))
	mux.HandleFunc("DELETE /api/secrets/{name}", s.apiHandler(true, s.handleDelete))
	mux.HandleFunc("POST /api/secrets/{name}/rollback", s.apiHandler(true, s.handleRollback))
```

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS (the recovery test exercises a real bare remote; ~10-15s with Argon2).

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: serve write endpoints with recovery protocol"
```

---

### Task 8: reveal endpoint

Spec §4: `GET /api/secrets/{name}/value` — unlock required, `Cache-Control: no-store` (already on every writeJSON), the only endpoint returning a value; logging records name + action only.

**Files:**
- Modify: `internal/server/api.go`
- Modify: `internal/server/server.go` (route)
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Produces: `func (s *Server) handleValue(w, r, sess)` via `apiHandler(true, ...)`.

- [ ] **Step 1: Write failing tests**

```go
func TestReveal(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	rec := do(t, h, http.MethodGet, "/api/secrets/API_KEY/value", "", ck)
	if rec.Code != 403 {
		t.Fatalf("locked reveal = %d", rec.Code)
	}
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/API_KEY/value", "", ck)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "secret123") {
		t.Fatalf("reveal = %d %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("cache-control = %q", cc)
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/NOPE/value", "", ck)
	if rec.Code != 404 {
		t.Fatalf("missing reveal = %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/secrets/API_KEY/history", "", ck)
	if strings.Contains(rec.Body.String(), "secret123") {
		t.Fatal("history must not contain values")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run TestReveal -v`
Expected: FAIL — 404 (route missing).

- [ ] **Step 3: Implement**

Add to `internal/server/api.go`:

```go
func (s *Server) handleValue(w http.ResponseWriter, r *http.Request, sess *session) {
	name := r.PathValue("name")
	if !validNameOr400(w, name) {
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if !s.secretExists(name) {
		writeErr(w, http.StatusNotFound, "secret "+name+" not found")
		return
	}
	sec, err := sess.vault.GetSecret(name)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	s.cfg.Log.Printf("reveal %s", name)
	writeJSON(w, http.StatusOK, map[string]string{"value": string(sec.Value)})
}
```

Register: `mux.HandleFunc("GET /api/secrets/{name}/value", s.apiHandler(true, s.handleValue))`.

- [ ] **Step 4: Run tests**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: serve reveal endpoint"
```

---

### Task 9: static SPA assets

Spec §5: `go:embed` `index.html`/`app.js`/`style.css`, served at `/`, `/app.js`, `/style.css` with CSP/nosniff/no-referrer/no-cache headers; exact-path serving only (no traversal); vanilla JS inserting values only via `textContent`.

**Files:**
- Create: `internal/server/static/index.html`
- Create: `internal/server/static/app.js`
- Create: `internal/server/static/style.css`
- Create: `internal/server/static.go`
- Test: `internal/server/server_test.go` (extend)

**Interfaces:**
- Produces: `func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request)`; `//go:embed static` FS.

- [ ] **Step 1: Write failing tests**

```go
func TestStaticAssets(t *testing.T) {
	s, _ := newTestServer(t)
	h := s.Handler()
	for path, want := range map[string]string{
		"/":          "text/html",
		"/app.js":    "text/javascript",
		"/style.css": "text/css",
	} {
		rec := do(t, h, http.MethodGet, path, "", "")
		if rec.Code != 200 {
			t.Fatalf("%s = %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, want) {
			t.Fatalf("%s content-type = %q", path, ct)
		}
		csp := rec.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "object-src 'none'") {
			t.Fatalf("csp = %q", csp)
		}
		if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("nosniff missing for %s", path)
		}
	}
	for _, path := range []string{"/../etc/passwd", "/%2e%2e/etc/passwd", "/nope.js"} {
		rec := do(t, h, http.MethodGet, path, "", "")
		if rec.Code == 200 {
			t.Fatalf("%s must not serve", path)
		}
	}
}

func TestConcurrentSmoke(t *testing.T) {
	s, gs := newTestServer(t)
	seedGitSecret(t, gs)
	h := s.Handler()
	ck := loginOK(t, h)
	if rec := unlockVault(t, h, ck, "test-password"); rec.Code != 200 {
		t.Fatalf("unlock: %d", rec.Code)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := do(t, h, http.MethodGet, "/api/secrets", "", ck)
			if rec.Code != 200 {
				errs <- fmt.Errorf("list = %d", rec.Code)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			rec := do(t, h, http.MethodGet, fmt.Sprintf("/api/secrets/API_KEY/value"), "", ck)
			if rec.Code != 200 {
				errs <- fmt.Errorf("reveal = %d", rec.Code)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
```

Add `sync` to the test imports. Run the package with `-race` in addition to the normal run (Step 4).

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -run TestStaticAssets -v`
Expected: FAIL — `/` returns 404.

- [ ] **Step 3: Implement**

Create `internal/server/static.go`:

```go
package server

import (
	"embed"
	"net/http"
)

//go:embed static
var staticFS embed.FS

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path
	switch name {
	case "/":
		name = "index.html"
	case "/app.js", "/style.css":
	default:
		http.NotFound(w, r)
		return
	}
	data, err := staticFS.ReadFile("static" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-cache")
	switch {
	case name == "index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case name == "app.js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	_, _ = w.Write(data)
}
```

Register in `Handler()`: `mux.HandleFunc("GET /{$}", s.handleStatic)` plus `mux.HandleFunc("GET /app.js", s.handleStatic)` and `mux.HandleFunc("GET /style.css", s.handleStatic)` (keep the exact-path switch as the guard).

Create `internal/server/static/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>psst</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header id="top">
  <span id="vault-label">psst</span>
  <span id="unlock-state"></span>
  <button id="btn-logout" class="ghost" hidden>logout</button>
</header>

<main>
  <section id="view-login" hidden>
    <h1>psst server</h1>
    <p>Enter the auth token printed by <code>psst serve</code>.</p>
    <form id="form-login">
      <input type="password" id="login-token" placeholder="auth token" autocomplete="off" required>
      <button type="submit">sign in</button>
      <p id="login-error" class="error" role="alert"></p>
    </form>
  </section>

  <section id="view-list" hidden>
    <div class="toolbar">
      <button id="btn-create">new secret</button>
      <button id="btn-unlock">unlock</button>
    </div>
    <p id="sync-warning" class="warning" role="alert" hidden></p>
    <div id="secret-tree"></div>
  </section>

  <section id="view-history" hidden>
    <button id="btn-back" class="ghost">&larr; back</button>
    <h2 id="history-title"></h2>
    <div class="toolbar">
      <button id="btn-reveal">reveal value</button>
      <button id="btn-edit">edit</button>
      <button id="btn-delete" class="danger">delete</button>
    </div>
    <pre id="reveal-box" hidden></pre>
    <p id="reveal-note" class="notice" hidden></p>
    <table id="history-table">
      <thead><tr><th>version</th><th>archived</th><th>by</th><th>tag</th><th></th></tr></thead>
      <tbody id="history-body"></tbody>
    </table>
  </section>

  <section id="view-form" hidden>
    <button id="btn-back2" class="ghost">&larr; back</button>
    <h2 id="form-title">new secret</h2>
    <form id="form-secret">
      <label>name <input id="f-name" pattern="[A-Z][A-Z0-9_]*" required></label>
      <label>value <textarea id="f-value" placeholder="leave empty to keep the current value"></textarea></label>
      <label>tag <input id="f-tag" pattern="[a-z][a-z0-9-]*" placeholder="optional"></label>
      <button type="submit" id="btn-save">save</button>
      <p id="form-error" class="error" role="alert"></p>
    </form>
  </section>
</main>

<div id="modal-unlock" hidden>
  <div class="modal-card">
    <h2>unlock vault</h2>
    <p class="notice" id="unlock-note" hidden></p>
    <form id="form-unlock">
      <input type="password" id="unlock-password" placeholder="vault password" autocomplete="off" required>
      <button type="submit">unlock</button>
      <button type="button" id="btn-cancel-unlock" class="ghost">cancel</button>
      <p id="unlock-error" class="error" role="alert"></p>
    </form>
  </div>
</div>

<script src="/app.js"></script>
</body>
</html>
```

Create `internal/server/static/style.css`:

```css
:root { --fg:#1c2333; --bg:#f6f7f9; --card:#fff; --line:#d9dee7; --accent:#2453ff; --danger:#c0392b; }
* { box-sizing: border-box; }
body { margin:0; font:15px/1.5 system-ui, sans-serif; color:var(--fg); background:var(--bg); }
header#top { display:flex; gap:1rem; align-items:center; padding:.7rem 1.2rem; background:var(--card); border-bottom:1px solid var(--line); }
#vault-label { font-weight:700; letter-spacing:.06em; }
#unlock-state { color:#667; font-size:.85rem; }
main { max-width:880px; margin:0 auto; padding:1.2rem; }
button { border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; padding:.42rem .9rem; font:inherit; cursor:pointer; }
button.ghost { background:transparent; color:var(--fg); border-color:var(--line); }
button.danger { background:var(--danger); border-color:var(--danger); }
button:hover { filter:brightness(1.06); }
.toolbar { display:flex; gap:.6rem; margin:.6rem 0 1rem; }
input, textarea { font:inherit; padding:.45rem .6rem; border:1px solid var(--line); border-radius:6px; width:100%; }
form label { display:block; margin:.7rem 0; }
form button { margin-top:.6rem; }
.error { color:var(--danger); min-height:1.2em; }
.warning { background:#fff6e5; border:1px solid #eedc9a; padding:.5rem .7rem; border-radius:6px; }
.notice { color:#667; font-size:.85rem; }
.group { margin-bottom:1rem; }
.group h3 { margin:.2rem 0 .4rem; font-size:.8rem; text-transform:uppercase; letter-spacing:.08em; color:#667; }
.secret-row { display:flex; gap:.8rem; align-items:center; background:var(--card); border:1px solid var(--line); border-radius:6px; padding:.45rem .7rem; margin-bottom:.35rem; }
.secret-row .name { font-family:ui-monospace, monospace; font-weight:600; cursor:pointer; flex:1; }
.secret-row .meta { color:#667; font-size:.8rem; }
table { border-collapse:collapse; width:100%; background:var(--card); border:1px solid var(--line); border-radius:6px; }
th, td { text-align:left; padding:.45rem .7rem; border-bottom:1px solid var(--line); font-size:.9rem; }
#reveal-box { background:#101623; color:#d7e3ff; padding:.7rem; border-radius:6px; overflow:auto; font-family:ui-monospace, monospace; }
#modal-unlock { position:fixed; inset:0; background:rgba(12,18,30,.55); display:flex; align-items:center; justify-content:center; }
.modal-card { background:var(--card); border-radius:10px; padding:1.2rem 1.4rem; width:min(420px, 90vw); }
[hidden] { display:none !important; }
```

Create `internal/server/static/app.js`:

```js
"use strict";

const $ = (id) => document.getElementById(id);
let currentSecret = null;
let editing = false;

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) {}
  if (res.status === 401) { showView("login"); throw new Error(data.error || "not authenticated"); }
  if (!res.ok) {
    if (data.reunlock) { state.unlocked = false; openUnlock(); }
    throw new Error(data.error || ("HTTP " + res.status));
  }
  return data;
}

const state = { authenticated: false, unlocked: false, verified: false, unlockExpiresAt: null };

function showView(name) {
  for (const v of ["login", "list", "history", "form"]) $("view-" + v).hidden = v !== name;
}

function fmtDate(iso) {
  if (!iso) return "";
  return new Date(iso).toLocaleString();
}

function renderUnlockState() {
  const el = $("unlock-state");
  $("btn-unlock").hidden = state.unlocked;
  if (state.unlocked) {
    const left = Math.max(0, Math.floor((new Date(state.unlockExpiresAt) - Date.now()) / 60000));
    el.textContent = state.verified ? "unlocked (" + left + " min left)" : "unlocked (unverified — vault is empty)";
  } else {
    el.textContent = state.authenticated ? "locked" : "";
  }
  $("btn-logout").hidden = !state.authenticated;
}

function openUnlock(note) {
  $("unlock-note").hidden = !note;
  if (note) $("unlock-note").textContent = note;
  $("modal-unlock").hidden = false;
  $("unlock-password").value = "";
  $("unlock-password").focus();
}

async function refreshSession() {
  const s = await api("GET", "/api/session");
  state.authenticated = s.authenticated;
  state.unlocked = s.unlocked;
  state.verified = s.verified;
  state.unlockExpiresAt = s.unlockExpiresAt;
  showView(s.authenticated ? "list" : "login");
  renderUnlockState();
  if (s.authenticated) await loadList();
}

async function loadList() {
  const data = await api("GET", "/api/secrets");
  $("sync-warning").hidden = !data.warning;
  if (data.warning) $("sync-warning").textContent = data.warning;
  const tree = $("secret-tree");
  tree.textContent = "";
  const groups = new Map();
  for (const sec of data.secrets) {
    const tag = sec.tags && sec.tags.length ? sec.tags[0] : "untagged";
    if (!groups.has(tag)) groups.set(tag, []);
    groups.get(tag).push(sec);
  }
  const sorted = [...groups.keys()].sort();
  for (const tag of sorted) {
    const g = document.createElement("div");
    g.className = "group";
    const h = document.createElement("h3");
    h.textContent = tag;
    g.appendChild(h);
    for (const sec of groups.get(tag)) {
      const row = document.createElement("div");
      row.className = "secret-row";
      const name = document.createElement("span");
      name.className = "name";
      name.textContent = sec.name;
      name.addEventListener("click", () => openHistory(sec.name));
      const meta = document.createElement("span");
      meta.className = "meta";
      meta.textContent = fmtDate(sec.updatedAt) + (sec.updatedBy ? " · " + sec.updatedBy : "");
      row.appendChild(name);
      row.appendChild(meta);
      g.appendChild(row);
    }
    tree.appendChild(g);
  }
}

async function openHistory(name) {
  currentSecret = name;
  $("reveal-box").hidden = true;
  $("reveal-note").hidden = true;
  const data = await api("GET", "/api/secrets/" + name + "/history");
  $("history-title").textContent = name;
  const body = $("history-body");
  body.textContent = "";
  for (const h of data.history) {
    const tr = document.createElement("tr");
    for (const val of [String(h.version), fmtDate(h.archivedAt), h.author, (h.tags && h.tags[0]) || ""]) {
      const td = document.createElement("td");
      td.textContent = val;
      tr.appendChild(td);
    }
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "ghost";
    btn.textContent = "rollback";
    btn.disabled = !state.unlocked;
    btn.addEventListener("click", async () => {
      try {
        await api("POST", "/api/secrets/" + name + "/rollback", { version: h.version });
        await openHistory(name);
      } catch (e) { alert(e.message); }
    });
    act.appendChild(btn);
    tr.appendChild(act);
    body.appendChild(tr);
  }
  $("btn-reveal").disabled = !state.unlocked;
  $("btn-delete").disabled = !state.unlocked;
  showView("history");
}

async function reveal(name) {
  const data = await api("GET", "/api/secrets/" + name + "/value");
  const box = $("reveal-box");
  box.textContent = data.value;
  box.hidden = false;
  $("reveal-note").hidden = false;
}

function openForm(isEdit) {
  editing = isEdit;
  $("form-title").textContent = isEdit ? "edit " + currentSecret : "new secret";
  $("f-name").value = isEdit ? currentSecret : "";
  $("f-name").disabled = isEdit;
  $("f-value").value = "";
  $("f-tag").value = "";
  $("form-error").textContent = "";
  showView("form");
}

$("form-login").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-error").textContent = "";
  try {
    await api("POST", "/api/login", { token: $("login-token").value });
    await refreshSession();
  } catch (e) { $("login-error").textContent = e.message; }
});

$("form-unlock").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("unlock-error").textContent = "";
  try {
    const res = await api("POST", "/api/unlock", { password: $("unlock-password").value });
    $("modal-unlock").hidden = true;
    state.unlocked = true;
    state.verified = res.verified;
    await refreshSession();
  } catch (e) { $("unlock-error").textContent = e.message; }
});

$("btn-cancel-unlock").addEventListener("click", () => { $("modal-unlock").hidden = true; });
$("btn-unlock").addEventListener("click", () => openUnlock(!state.verified && state.authenticated ? "" : undefined));

$("btn-logout").addEventListener("click", async () => {
  try { await api("POST", "/api/logout"); } catch (_) {}
  state.authenticated = false;
  state.unlocked = false;
  showView("login");
});

$("btn-create").addEventListener("click", () => {
  if (!state.unlocked) { openUnlock("unlock required to create secrets"); return; }
  openForm(false);
});

$("btn-back").addEventListener("click", () => showView("list"));
$("btn-back2").addEventListener("click", () => showView(currentSecret ? "history" : "list"));

$("btn-reveal").addEventListener("click", async () => {
  try { await reveal(currentSecret); } catch (e) { alert(e.message); }
});

$("btn-edit").addEventListener("click", () => {
  if (!state.unlocked) { openUnlock("unlock required to edit"); return; }
  openForm(true);
});

$("btn-delete").addEventListener("click", async () => {
  if (!confirm("delete " + currentSecret + "?")) return;
  try {
    await api("DELETE", "/api/secrets/" + currentSecret);
    currentSecret = null;
    await loadList();
    showView("list");
  } catch (e) { alert(e.message); }
});

$("form-secret").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("form-error").textContent = "";
  const name = $("f-name").value.trim();
  const body = {};
  const value = $("f-value").value;
  const tag = $("f-tag").value.trim();
  if (value !== "") body.value = value;
  if (tag !== "" || editing) body.tag = tag;
  try {
    await api("POST", "/api/secrets/" + name, body);
    await loadList();
    showView("list");
  } catch (e) { $("form-error").textContent = e.message; }
});

setInterval(renderUnlockState, 30000);
refreshSession().catch(() => showView("login"));
```

- [ ] **Step 4: Run tests + manual smoke**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/server/ -v && PSST_NO_KEYCHAIN=1 go test ./internal/server/ -race -count=1`
Expected: PASS (including the race run).

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: serve web UI static assets"
```

---

### Task 10: `psst serve` CLI command

Spec §1: flags, storage gate (SQLite → migrate hint, missing vault → exit 3), token precedence (flag > `PSST_SERVE_TOKEN` > generated, printed only when generated), listen parsing + non-loopback warning, timeout (min 1m), startup print, `http.Server` timeouts, SIGINT/SIGTERM graceful shutdown + `srv.Close()`, sweeper ticker.

**Files:**
- Create: `internal/cli/serve.go`
- Test: `internal/cli/serve_test.go`

**Interfaces:**
- Consumes: `server.New/Handler/Close/Sweep`, `OpenVaultStore`, `ResolveStorage`.
- Produces: `func isLoopbackHost(host string) bool`; `func resolveServeToken(flagVal string) (token string, generated bool)`; cobra command `serve`.

- [ ] **Step 1: Write failing tests**

Create `internal/cli/serve_test.go`:

```go
package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aatumaykin/psst/internal/store"
)

func TestIsLoopbackHost(t *testing.T) {
	for h, want := range map[string]bool{
		"127.0.0.1": true, "localhost": true, "::1": true, "[::1]": true,
		"0.0.0.0": false, "example.com": false, "192.168.1.5": false, "": false,
	} {
		if got := isLoopbackHost(h); got != want {
			t.Fatalf("isLoopbackHost(%q) = %v", h, got)
		}
	}
}

func TestResolveServeToken(t *testing.T) {
	t.Setenv("PSST_SERVE_TOKEN", "")
	tok, generated := resolveServeToken("flag-token")
	if tok != "flag-token" || generated {
		t.Fatalf("flag precedence: %q %v", tok, generated)
	}
	t.Setenv("PSST_SERVE_TOKEN", "env-token")
	tok, generated = resolveServeToken("")
	if tok != "env-token" || generated {
		t.Fatalf("env precedence: %q %v", tok, generated)
	}
	t.Setenv("PSST_SERVE_TOKEN", "")
	tok, generated = resolveServeToken("")
	if len(tok) != 43 || !generated {
		t.Fatalf("generated: len=%d generated=%v", len(tok), generated)
	}
	tok2, _ := resolveServeToken("")
	if tok == tok2 {
		t.Fatal("tokens must be random")
	}
}

func TestServeRequiresGitStorage(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	if err := os.MkdirAll(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(envDir, "vault.db")
	if err := os.WriteFile(dbPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := serveStorageGate(envDir, "")
	if err == nil {
		t.Fatal("sqlite vault must be rejected")
	}
	if !strings.Contains(err.Error(), "migrate storage") {
		t.Fatalf("message = %v", err)
	}
}

func TestServeMissingVault(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	err := serveStorageGate(envDir, "")
	if err != errNoVault {
		t.Fatalf("missing vault = %v", err)
	}
}

func TestServeGitVaultPassesGate(t *testing.T) {
	envDir := filepath.Join(t.TempDir(), "env")
	repo := filepath.Join(envDir, "repo")
	gs, err := store.NewGitStore(repo, store.GitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gs.InitSchema(); err != nil {
		t.Fatal(err)
	}
	if err := serveStorageGate(envDir, ""); err != nil {
		t.Fatalf("git vault rejected: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PSST_NO_KEYCHAIN=1 go test ./internal/cli/ -run 'IsLoopback|ResolveServeToken|ServeRequires|ServeMissing|ServeGitVault' -v`
Expected: FAIL — symbols undefined.

- [ ] **Step 3: Implement**

Create `internal/cli/serve.go`:

```go
package cli

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/server"
	"github.com/aatumaykin/psst/internal/vault"
)

var errNoVault = errors.New("no vault found")

const (
	defaultListen       = "127.0.0.1:7788"
	defaultServeTimeout = 30 * time.Minute
	minServeTimeout     = time.Minute
	sessionTTL          = 24 * time.Hour
)

func isLoopbackHost(host string) bool {
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func resolveServeToken(flagVal string) (string, bool) {
	if flagVal != "" {
		return flagVal, false
	}
	if env := os.Getenv("PSST_SERVE_TOKEN"); env != "" {
		return env, false
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		exitWithError(fmt.Sprintf("generate token: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(b), true
}

func serveStorageGate(envDir, storageFlag string) error {
	storage, err := ResolveStorage(storageFlag, envDir)
	if err != nil {
		return err
	}
	repoExists := statExists(filepath.Join(envDir, "repo", ".git")) ||
		statExists(filepath.Join(envDir, "repo", "psst.yaml"))
	if storage == "git" {
		if !repoExists {
			return errNoVault
		}
		return nil
	}
	dbExists := statExists(vault.SQLitePath(envDir))
	if dbExists || repoExists {
		return errors.New("psst serve requires git storage; run 'psst migrate storage --to git'")
	}
	return errNoVault
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the web UI server (git storage only)",
	Run: func(cmd *cobra.Command, _ []string) {
		_, _, global, env, _ := getGlobalFlags(cmd)
		listen, _ := cmd.Flags().GetString("listen")
		tokenFlag, _ := cmd.Flags().GetString("token")
		timeoutStr, _ := cmd.Flags().GetString("timeout")
		if listen == "" {
			listen = defaultListen
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			exitWithError(fmt.Sprintf("invalid --timeout: %v", err))
		}
		//nolint:mnd // spec minimum
		if timeout < minServeTimeout {
			exitWithError("--timeout must be at least 1m")
		}
		envDir, err := vault.FindVaultDir(global, env)
		if err != nil {
			exitWithError(err.Error())
		}
		if err := serveStorageGate(envDir, getStorageFlag(cmd)); err != nil {
			if errors.Is(err, errNoVault) {
				printNoVault(false, false)
				//nolint:mnd // exit code for missing vault
				os.Exit(3)
			}
			exitWithError(err.Error())
		}
		s, gs, err := OpenVaultStore(envDir, "git", "", false)
		if err != nil {
			exitWithError(fmt.Sprintf("open vault: %v", err))
		}
		if err := s.InitSchema(); err != nil {
			exitWithError(fmt.Sprintf("init vault: %v", err))
		}
		host, port, err := net.SplitHostPort(listen)
		if err != nil {
			exitWithError(fmt.Sprintf("invalid --listen %q: %v", listen, err))
		}
		if !isLoopbackHost(host) {
			fmt.Fprintln(os.Stderr, "warning: listening on a non-loopback interface; expose only via SSH tunnel (ssh -L 7788:127.0.0.1:7788)")
		}
		token, generated := resolveServeToken(tokenFlag)
		digest := sha256.Sum256([]byte(token))
		srv := server.New(server.Config{
			Store: gs, Enc: crypto.NewAESGCM(),
			Host: host, Port: port,
			TokenDigest: digest,
			UnlockTimeout: timeout,
			SessionTTL:    sessionTTL,
		})
		httpSrv := &http.Server{
			Addr:    listen,
			Handler: srv.Handler(),
			//nolint:mnd // server timeouts per spec
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			t := time.NewTicker(time.Minute)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					srv.Sweep()
				}
			}
		}()
		errCh := make(chan error, 1)
		go func() { errCh <- httpSrv.ListenAndServe() }()
		fmt.Printf("psst server:  http://%s\n", listen)
		if generated {
			fmt.Printf("auth token:   %s   (shown once)\n", token)
		}
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				exitWithError(fmt.Sprintf("serve: %v", err))
			}
		case <-ctx.Done():
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		srv.Close()
	},
}

//nolint:gochecknoinits // cobra command registration
func init() {
	serveCmd.Flags().String("listen", defaultListen, "Listen address")
	serveCmd.Flags().String("token", "", "Auth token (reads PSST_SERVE_TOKEN env; generated when empty)")
	serveCmd.Flags().String("timeout", "30m", "Unlock inactivity timeout (minimum 1m)")
	rootCmd.AddCommand(serveCmd)
}
```

Register the command via the existing `init()` pattern shown at the bottom of the code block.

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS (whole repo).

- [ ] **Step 5: Commit**

```bash
git add internal/cli/serve.go internal/cli/serve_test.go
git commit -m "feat: psst serve command"
```

---

### Task 11: documentation

Spec §8: security.md web UI section (present tense barrier list), architecture.md server layer, README serve section.

**Files:**
- Modify: `docs/rules/security.md` (line 69 area + Git Storage section)
- Modify: `docs/rules/architecture.md` (layers diagram, dependency rules)
- Modify: `README.md` (serve section)

**Interfaces:**
- Produces: documentation only; no code.

- [ ] **Step 1: Update `docs/rules/security.md`**

In "What NOT To Do", replace the sentence `The web UI (future phase) binds to localhost with a mandatory token.` with:

```
The web UI (`psst serve`) binds to localhost by default and requires a mandatory
token plus a second vault-password unlock barrier; Host and Origin checks defend
against DNS rebinding/CSRF; values are revealed only through the dedicated
`/api/secrets/{name}/value` endpoint after unlock. Remote UI access only via SSH tunnel.
```

Append a new section before "Vulnerability Response":

```markdown
## Web UI (`psst serve`)

- Default bind `127.0.0.1`; non-loopback `--listen` prints an explicit tunnel warning.
- Two barriers: server token (SHA-256 digest in memory, constant-time compare,
  printed once) and per-session vault unlock (Argon2id key in memory, 30-minute
  inactivity timeout, zeroed on logout/expiry/shutdown).
- Host allowlist (`127.0.0.1`/`localhost`/`[::1]` + listener port) on every request;
  `Origin` required and matching on every mutating request; cookie is `HttpOnly`,
  `SameSite=Strict`.
- Without unlock the UI serves only names/tags/dates/authors — never values.
- All vault/store access in the server serializes behind one mutex; the server is
  another client of the git clone (repo `flock` still guards cross-process).
```

- [ ] **Step 2: Update `docs/rules/architecture.md`**

In the Layers diagram add between `cli/` and `vault/`:

```
├─────────────────────────────────┤
│  server/                        │  Web UI — HTTP handlers, sessions, embedded SPA
├─────────────────────────────────┤
```

In Dependency Rules append:

```
6. **Allowed:** `cli → server`, `server → vault`, `server → store`, `server → crypto`, `server → keyring`. The web UI server is a presentation layer beside `cli/`; it never imports `cli`, `output`, or `runner`.
7. The long-lived server serializes all vault/store access behind a single mutex (`server.opMu`); `vault.Vault` is not goroutine-safe.
```

- [ ] **Step 3: Update `README.md`**

After the `psst sync` section (or the git storage section), add:

```markdown
### Web UI

```bash
psst serve [--listen 127.0.0.1:7788] [--token <tok>] [--timeout 30m]
# psst server:  http://127.0.0.1:7788
# auth token:   <generated>   (shown once)
```

Requires git storage (`psst migrate storage --to git`). The token is generated at
startup and printed once; pass one via `--token` (visible in `ps` output on
multi-user hosts) or `PSST_SERVE_TOKEN`. The vault password is entered in the UI
(unlock, 30-minute inactivity timeout). Secret values are shown only through the
explicit reveal action.

Remote access: `ssh -L 7788:127.0.0.1:7788 <host>`, then open
`http://127.0.0.1:7788` locally.
```

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: PASS (docs only — sanity check).

- [ ] **Step 5: Commit**

```bash
git add docs/rules/security.md docs/rules/architecture.md README.md
git commit -m "docs: serve web UI documentation"
```

---

## Final verification (after all tasks)

- [ ] `make test` green; `make lint` clean if golangci-lint is available.
- [ ] `go vet ./...` clean.
- [ ] Manual end-to-end in the worktree: init git vault → seed secret → `psst serve` → browser: login (token), locked list, unlock, create/edit/retag/untag, reveal, history+rollback, delete, logout; Ctrl-C shuts down cleanly.
- [ ] Re-verify the spec's §9 test list is fully covered by the test files (each bullet maps to at least one test added in Tasks 3-10).
- [ ] Final diff review by a fresh subagent (per project process), then `git merge --no-ff feat/serve-webui` into `main`.

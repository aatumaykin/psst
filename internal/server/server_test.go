package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
	"github.com/aatumaykin/psst/internal/store"
	"github.com/aatumaykin/psst/internal/vault"
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
		TokenDigest:   digest,
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
	rec = do(t, h, http.MethodPost, "/api/logout", "", "")
	if rec.Code != 401 {
		t.Fatalf("unauth logout = %d", rec.Code)
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
	s.writeStoreError(w, fmt.Errorf("%w; change is in the local clone, run `psst sync` later: %w", store.ErrPushFailed, errors.New("boom")))
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
	if err := v.SetSecret("API_KEY", []byte("secret456"), []string{"prod"}); err != nil {
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

func newBareRemote(t *testing.T) string {
	t.Helper()
	remote := filepath.Join(t.TempDir(), "remote.git")
	if out, err := exec.Command("git", "init", "--bare", remote).CombinedOutput(); err != nil {
		t.Fatalf("git init --bare: %v\n%s", err, out)
	}
	return remote
}

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

	repo2 := filepath.Join(t.TempDir(), "repo2")
	other, err := store.CloneGitVault(remote, repo2, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("other: %v", err)
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
	fresh, err := store.NewGitStore(repo2, store.GitOptions{Remote: remote})
	if err != nil {
		t.Fatalf("fresh: %v", err)
	}
	mig := vault.New(crypto.NewAESGCM(), &fixedPasswordProvider{password: "test-password"}, fresh)
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
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"verified":true`) {
		t.Fatalf("re-unlock after recovery = %d %s", rec.Code, rec.Body.String())
	}
	rec = do(t, h, http.MethodPost, "/api/secrets/NEW_KEY", `{"value":"x"}`, ck1)
	if rec.Code != 200 {
		t.Fatalf("write after re-unlock = %d %s", rec.Code, rec.Body.String())
	}
}

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

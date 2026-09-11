package server

import (
	"crypto/sha256"
	"errors"
	"fmt"
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

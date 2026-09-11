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

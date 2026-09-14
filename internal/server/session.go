package server

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"time"

	"github.com/aatumaykin/psst/internal/vault"
)

const (
	sessionCookie = "psst_session"
	sessionIDSize = 32
)

type session struct {
	id              string
	createdAt       time.Time
	expiresAt       time.Time
	vault           *vault.Vault
	verified        bool
	unlockExpiresAt time.Time
}

func newSessionID() string {
	b := make([]byte, sessionIDSize)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sessionCookieHeader(id string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}
}

func (s *Server) apiHandler(
	unlockRequired bool, h func(w http.ResponseWriter, r *http.Request, sess *session),
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.sessionFromRequest(r)
		if sess == nil {
			writeErr(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		if (r.Method != http.MethodGet || r.URL.Path != "/api/session") && r.Header.Get("X-Psst-Auto") != "1" {
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

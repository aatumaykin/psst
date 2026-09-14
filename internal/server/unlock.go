package server

import (
	"net/http"

	"github.com/aatumaykin/psst/internal/keyring"
	"github.com/aatumaykin/psst/internal/vault"
)

type unlockRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request, sess *session) {
	body, ok := readBody(w, r, bodyLimit64KiB)
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
	v := vault.New(s.cfg.Enc, keyring.NewFixedProvider(req.Password), s.cfg.Store)
	if err := v.Unlock(r.Context()); err != nil {
		writeErr(w, http.StatusInternalServerError, "unlock failed")
		return
	}
	verified := false
	metas, err := v.ListSecrets(r.Context())
	if err != nil {
		_ = v.Close()
		s.writeStoreError(w, err)
		return
	}
	if len(metas) > 0 {
		if _, err = v.GetSecret(r.Context(), metas[0].Name); err != nil {
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

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

var _ keyring.KeyProvider = (*fixedPasswordProvider)(nil)

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

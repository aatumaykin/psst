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

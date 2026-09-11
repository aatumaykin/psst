package server

import (
	"errors"
	"net/http"
	"time"

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

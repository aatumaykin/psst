package server

import (
	"errors"
	"net/http"
	"strings"
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

package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/aatumaykin/psst/internal/crypto"
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
	mux.HandleFunc("POST /api/unlock", s.apiHandler(false, s.handleUnlock))
	mux.HandleFunc("GET /api/secrets", s.apiHandler(false, s.handleList))
	mux.HandleFunc("GET /api/secrets/{name}/history", s.apiHandler(false, s.handleHistory))
	return s.recoverMW(s.logMW(s.hostMW(s.originMW(mux))))
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

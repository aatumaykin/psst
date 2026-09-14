package server

import (
	"fmt"
	"net"
	"net/http"
	"runtime/debug"
	"time"
)

func (s *Server) recoverMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.cfg.Log.Printf("panic %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				writeErr(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.cfg.Log.Printf("%s %s %d %s", r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}

type statusRecorder struct {
	http.ResponseWriter

	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) hostAllowed(host string) bool {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		h, port = host, s.cfg.Port
	}
	if port != s.cfg.Port {
		return false
	}
	switch h {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		return true
	}
	return false
}

func (s *Server) hostMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r.Host) {
			writeErr(w, http.StatusForbidden, "host not allowed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) originAllowed(origin string) bool {
	switch origin {
	case fmt.Sprintf("http://127.0.0.1:%s", s.cfg.Port),
		fmt.Sprintf("http://localhost:%s", s.cfg.Port),
		fmt.Sprintf("http://[::1]:%s", s.cfg.Port):
		return true
	}
	return false
}

func (s *Server) isMutation(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func (s *Server) originMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.isMutation(r.Method) {
			origin := r.Header.Get("Origin")
			if origin == "" || !s.originAllowed(origin) {
				writeErr(w, http.StatusForbidden, "origin not allowed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

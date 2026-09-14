package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

const (
	bodyLimit64KiB = 64 * 1024
	bodyLimit1MiB  = 1024 * 1024
)

func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	b, err := io.ReadAll(r.Body)
	if err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
			return nil, false
		}
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return nil, false
	}
	return b, true
}

func jsonUnmarshal(body []byte, v any) error {
	return json.Unmarshal(body, v)
}

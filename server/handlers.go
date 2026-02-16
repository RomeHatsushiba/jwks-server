package server

import (
	"encoding/json"
	"net/http"
	"time"
)

type Server struct {
	ks  *KeyStore
	mux *http.ServeMux
}

func NewServer(ks *KeyStore) *Server {
	s := &Server{
		ks:  ks,
		mux: http.NewServeMux(),
	}
	s.routes()
	return s
}

func (s *Server) Router() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)
	s.mux.HandleFunc("/auth", s.handleAuth)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	keys := s.ks.Unexpired(now)

	jwks := JWKS{Keys: make([]JWK, 0, len(keys))}
	for _, kp := range keys {
		jwks.Keys = append(jwks.Keys, toJWK(kp.Kid, kp.Public))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now().UTC()
	expiredMode := r.URL.Query().Get("expired") != ""

	var kp KeyPair
	var ok bool

	if expiredMode {
		kp, ok = s.ks.ExpiredKey(now)
		if !ok {
			http.Error(w, "no expired key available", http.StatusInternalServerError)
			return
		}

		token, err := SignJWT_RS256(kp.Kid, kp.Private, "fake-user", now, now.Add(-5*time.Minute))
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(token))
		return
	}

	kp, ok = s.ks.ActiveKey(now)
	if !ok {
		http.Error(w, "no active key available", http.StatusInternalServerError)
		return
	}

	token, err := SignJWT_RS256(kp.Kid, kp.Private, "fake-user", now, now.Add(5*time.Minute))
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(token))
}

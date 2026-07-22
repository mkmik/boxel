package idp

// Stateless dynamic client registration (RFC 7591): the client_id *is* the
// registration — a compact JSON payload plus an HMAC computed from the signing
// key. No storage means registrations survive restarts for free (as long as
// the signing key is persistent), which matters because MCP connectors
// register once and keep the client_id indefinitely.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// clientReg is the registration embedded in a client_id. Field names are
// single letters to keep the client_id (which travels in authorize URLs)
// short.
type clientReg struct {
	RedirectURIs []string `json:"r"`
	Name         string   `json:"n,omitempty"`
	IssuedAt     int64    `json:"t"`
}

func (s *Server) encodeClientID(c clientReg) (string, error) {
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(payload)
	return b64u(payload) + "." + b64u(mac.Sum(nil)[:16]), nil
}

func (s *Server) decodeClientID(id string) (clientReg, error) {
	var c clientReg
	p, sig, ok := strings.Cut(id, ".")
	if !ok {
		return c, fmt.Errorf("malformed client_id")
	}
	payload, err := b64uDecode(p)
	if err != nil {
		return c, fmt.Errorf("malformed client_id")
	}
	got, err := b64uDecode(sig)
	if err != nil {
		return c, fmt.Errorf("malformed client_id")
	}
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write(payload)
	if !hmac.Equal(got, mac.Sum(nil)[:16]) {
		return c, fmt.Errorf("unknown client_id")
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("malformed client_id")
	}
	return c, nil
}

// validRedirectURI accepts absolute https URLs, plus http on loopback hosts
// (native/dev clients per RFC 8252 §7.3).
func validRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	return false
}

// handleRegister implements RFC 7591 dynamic registration for public clients.
// It is deliberately unauthenticated (like the rest of the token machinery):
// possessing a client_id grants nothing — every authorization still passes
// through the exe.dev-authenticated, allowlisted /authorize consent step.
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "malformed registration request")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 8 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "between 1 and 8 redirect_uris required")
		return
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", fmt.Sprintf("invalid redirect_uri %q (https required, http only on loopback)", u))
			return
		}
	}
	name := req.ClientName
	if len(name) > 128 {
		name = name[:128]
	}
	now := time.Now()
	id, err := s.encodeClientID(clientReg{RedirectURIs: req.RedirectURIs, Name: name, IssuedAt: now.Unix()})
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "registration failed")
		return
	}
	s.cfg.Logf("idp: registered client %q (%d redirect_uris)", name, len(req.RedirectURIs))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        now.Unix(),
		"client_name":                name,
		"redirect_uris":              req.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
	})
}

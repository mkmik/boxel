// Package idp implements the built-in OIDC identity provider: a minimal
// OAuth 2.1 / OIDC authorization server whose source of user truth is the
// exe.dev edge proxy. It never sees a password — /authorize trusts the
// edge-injected X-ExeDev-Email header (bouncing anonymous browsers through
// the platform's /__exe.dev/login), gates on an email allowlist, and shows a
// consent page; every other endpoint (/token, /register, metadata, JWKS) is
// deliberately public so that server-side OAuth clients — like the backend of
// Claude's MCP connector — can drive the code+PKCE flow without an exe.dev
// session. That is also why the VM hosting the IDP must be `share set-public`:
// a fully private VM would make the edge swallow those programmatic requests
// with a login redirect.
//
// Everything the IDP issues (authorization codes, access/refresh/ID tokens,
// client registrations) is stateless: ES256 JWTs or HMAC-sealed blobs bound to
// one persistent signing key. The only server state is a small replay cache
// for authorization codes.
package idp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// HeaderExeEmail is injected by the exe.dev edge proxy on requests from
// authenticated users (and stripped from unauthenticated ones).
const HeaderExeEmail = "X-ExeDev-Email"

// exeLoginPath is the platform login bounce available on every exe.dev VM
// domain; redirect={path} returns the browser to us with identity attached.
const exeLoginPath = "/__exe.dev/login"

// Endpoint paths, relative to the issuer origin.
const (
	AuthorizePath = "/idp/authorize"
	TokenPath     = "/idp/token"
	RegisterPath  = "/idp/register"
	JWKSPath      = "/idp/jwks"
	UserinfoPath  = "/idp/userinfo"
)

// Config configures the IDP.
type Config struct {
	// Issuer is the external base URL clients see (e.g. https://myvm.exe.xyz),
	// scheme+host only. It appears as `iss` in every token.
	Issuer string
	// Users is the email allowlist: only these identities can complete
	// /authorize. Never empty — an IDP that signs tokens for arbitrary
	// exe.dev users in front of an RCE endpoint is a bug, not a feature.
	Users []string
	// Key signs everything. Persist it (LoadOrCreateKey) or every client
	// registration and refresh token dies with the process.
	Key *ecdsa.PrivateKey
	// AccessTTL / RefreshTTL / CodeTTL default to 1h / 30d / 5m.
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration
	// Logf is the logging sink. Default log.Printf.
	Logf func(format string, args ...any)
}

// Server is the IDP: a set of http handlers around one signing key.
type Server struct {
	cfg     Config
	kid     string
	hmacKey []byte

	mu        sync.Mutex
	usedCodes map[string]time.Time // code jti -> expiry, for single-use enforcement
}

// New builds a Server.
func New(cfg Config) (*Server, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("idp: issuer is required")
	}
	u, err := url.Parse(cfg.Issuer)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("idp: issuer must be an absolute URL with no path, got %q", cfg.Issuer)
	}
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("idp: at least one allowed user is required")
	}
	for i, e := range cfg.Users {
		cfg.Users[i] = strings.ToLower(strings.TrimSpace(e))
	}
	if cfg.Key == nil {
		return nil, fmt.Errorf("idp: signing key is required")
	}
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = time.Hour
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 30 * 24 * time.Hour
	}
	if cfg.CodeTTL <= 0 {
		cfg.CodeTTL = 5 * time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	// The client-registry HMAC key is derived from the signing key so the
	// whole IDP state lives in one file.
	d := sha256.Sum256(append([]byte("boxel-idp-client-registry/"), cfg.Key.D.Bytes()...))
	return &Server{
		cfg:       cfg,
		kid:       keyID(&cfg.Key.PublicKey),
		hmacKey:   d[:],
		usedCodes: map[string]time.Time{},
	}, nil
}

// Issuer returns the configured issuer URL.
func (s *Server) Issuer() string { return s.cfg.Issuer }

// Verifier returns the resource-side verifier bound to this IDP's key: the
// same process serves both the IDP and the protected /mcp endpoint.
func (s *Server) Verifier() *Verifier {
	return &Verifier{issuer: s.cfg.Issuer, pub: &s.cfg.Key.PublicKey, kid: s.kid}
}

// AttachRoutes registers the IDP endpoints on mux. All of them are public by
// design; do not wrap them in the resource auth guard.
//
// The CORS-wrapped routes are registered without a method in the pattern so
// that preflight OPTIONS requests reach the wrapper instead of the mux's 405.
func (s *Server) AttachRoutes(mux *http.ServeMux) {
	mux.Handle("/.well-known/openid-configuration", cors(http.MethodGet, http.HandlerFunc(s.handleMetadata)))
	mux.Handle("/.well-known/oauth-authorization-server", cors(http.MethodGet, http.HandlerFunc(s.handleMetadata)))
	mux.Handle(JWKSPath, cors(http.MethodGet, http.HandlerFunc(s.handleJWKS)))
	mux.Handle(RegisterPath, cors(http.MethodPost, http.HandlerFunc(s.handleRegister)))
	mux.Handle("GET "+AuthorizePath, http.HandlerFunc(s.handleAuthorizeGet))
	mux.Handle("POST "+AuthorizePath, http.HandlerFunc(s.handleAuthorizePost))
	mux.Handle(TokenPath, cors(http.MethodPost, http.HandlerFunc(s.handleToken)))
	mux.Handle(UserinfoPath, cors(http.MethodGet, http.HandlerFunc(s.handleUserinfo)))
}

// cors allows browser-based OAuth clients (e.g. MCP inspector) to reach the
// public endpoints: it answers preflight OPTIONS and enforces the expected
// method itself. Safe: nothing here relies on cookies or ambient identity —
// /authorize, the only endpoint that does, is deliberately not wrapped.
func cors(method string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", method+", OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != method && !(method == http.MethodGet && r.Method == http.MethodHead) {
			w.Header().Set("Allow", method+", OPTIONS")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) allowed(email string) bool {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return false
	}
	for _, u := range s.cfg.Users {
		if subtle.ConstantTimeCompare([]byte(u), []byte(email)) == 1 {
			return true
		}
	}
	return false
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func (s *Server) handleMetadata(w http.ResponseWriter, r *http.Request) {
	iss := s.cfg.Issuer
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + AuthorizePath,
		"token_endpoint":                        iss + TokenPath,
		"registration_endpoint":                 iss + RegisterPath,
		"jwks_uri":                              iss + JWKSPath,
		"userinfo_endpoint":                     iss + UserinfoPath,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported":                      []string{"openid", "email"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
	})
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwkSet{Keys: []jwk{ecJWK(&s.cfg.Key.PublicKey, s.kid)}})
}

const consentTemplate = `<!doctype html>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>boxel — authorize access</title>
<style>
body{font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;color:#222}
.card{border:1px solid #ddd;border-radius:8px;padding:1.5rem}
code{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px;word-break:break-all}
button{font-size:1rem;padding:.5rem 1.5rem;border-radius:6px;border:1px solid #888;cursor:pointer}
button[value=approve]{background:#1a7f37;color:#fff;border-color:#1a7f37}
form{display:inline-block;margin-right:.75rem;margin-top:1rem}
</style>
<div class="card">
<h1>Authorize access?</h1>
<p><strong>{{.ClientName}}</strong> is asking to act as <strong>{{.Email}}</strong> on this boxel deployment.</p>
<p>It will be redirected to <code>{{.RedirectURI}}</code> with an authorization code.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="req" value="{{.Req}}">
<button name="decision" value="approve">Approve</button>
</form>
<form method="post" action="{{.Action}}">
<input type="hidden" name="req" value="{{.Req}}">
<button name="decision" value="deny">Deny</button>
</form>
</div>
`

var consentTmpl = template.Must(template.New("consent").Parse(consentTemplate))

// handleAuthorizeGet validates the authorization request, establishes the
// user's identity from the exe.dev edge header (bouncing to the platform
// login when absent), and renders the consent form.
func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client, err := s.decodeClientID(q.Get("client_id"))
	if err != nil {
		http.Error(w, "invalid client_id (register at "+RegisterPath+")", http.StatusBadRequest)
		return
	}
	redirectURI := q.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		// Never redirect to an unregistered URI — render the error instead.
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	fail := func(code, desc string) { redirectError(w, r, redirectURI, q.Get("state"), code, desc) }
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		fail("invalid_request", "PKCE with code_challenge_method=S256 is required")
		return
	}

	email := strings.TrimSpace(r.Header.Get(HeaderExeEmail))
	if email == "" {
		// Anonymous browser: bounce through the exe.dev platform login, which
		// returns to this same URL with the identity header injected.
		http.Redirect(w, r, exeLoginPath+"?redirect="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	if !s.allowed(email) {
		s.cfg.Logf("idp: authorize denied for %s (not in allowlist)", email)
		fail("access_denied", "this exe.dev user is not authorized for this IDP")
		return
	}

	req, err := signJWT(s.cfg.Key, s.kid, claims{
		"iss": s.cfg.Issuer, "typ": "authzreq", "jti": randID(),
		"email": strings.ToLower(email), "cid": q.Get("client_id"),
		"ruri": redirectURI, "cc": q.Get("code_challenge"),
		"state": q.Get("state"), "nonce": q.Get("nonce"),
		"scope": q.Get("scope"), "resource": q.Get("resource"),
		"iat": time.Now().Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	name := client.Name
	if name == "" {
		name = "An OAuth client"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(w, map[string]string{
		"ClientName":  name,
		"Email":       email,
		"RedirectURI": redirectURI,
		"Action":      AuthorizePath,
		"Req":         req,
	})
}

// handleAuthorizePost consumes an approved consent form and redirects back to
// the client with an authorization code. The signed req blob makes the round
// trip stateless; binding it to the *current* edge identity blocks any
// cross-user replay of a leaked form.
func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "malformed form", http.StatusBadRequest)
		return
	}
	c, err := s.verifyOwn(r.PostFormValue("req"), "authzreq")
	if err != nil {
		http.Error(w, "invalid or expired consent form; restart the authorization", http.StatusBadRequest)
		return
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderExeEmail)))
	if email == "" || email != c.str("email") || !s.allowed(email) {
		http.Error(w, "identity changed during consent; restart the authorization", http.StatusForbidden)
		return
	}
	if r.PostFormValue("decision") != "approve" {
		redirectError(w, r, c.str("ruri"), c.str("state"), "access_denied", "the user denied the request")
		return
	}
	now := time.Now()
	code, err := signJWT(s.cfg.Key, s.kid, claims{
		"iss": s.cfg.Issuer, "typ": "code", "jti": randID(),
		"sub": email, "email": email, "cid": c.str("cid"),
		"ruri": c.str("ruri"), "cc": c.str("cc"), "nonce": c.str("nonce"),
		"scope": c.str("scope"), "resource": c.str("resource"),
		"iat": now.Unix(), "exp": now.Add(s.cfg.CodeTTL).Unix(),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.cfg.Logf("idp: issued code for %s", email)
	u, _ := url.Parse(c.str("ruri"))
	qq := u.Query()
	qq.Set("code", code)
	if st := c.str("state"); st != "" {
		qq.Set("state", st)
	}
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form")
		return
	}
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.tokenFromCode(w, r)
	case "refresh_token":
		s.tokenFromRefresh(w, r)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
	}
}

func (s *Server) tokenFromCode(w http.ResponseWriter, r *http.Request) {
	c, err := s.verifyOwn(r.PostFormValue("code"), "code")
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired code")
		return
	}
	if !s.markCodeUsed(c.str("jti"), time.Unix(c.num("exp"), 0)) {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "code already redeemed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("client_id")), []byte(c.str("cid"))) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	// redirect_uri is optional under OAuth 2.1 (PKCE binds the code), but if
	// the client sends it, it must match.
	if ru := r.PostFormValue("redirect_uri"); ru != "" && ru != c.str("ruri") {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	verifier := r.PostFormValue("code_verifier")
	if verifier == "" {
		oauthError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required")
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	if subtle.ConstantTimeCompare([]byte(b64u(sum[:])), []byte(c.str("cc"))) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	s.issueTokens(w, c.str("email"), c.str("cid"), c.str("scope"), c.str("resource"), c.str("nonce"), true)
}

func (s *Server) tokenFromRefresh(w http.ResponseWriter, r *http.Request) {
	c, err := s.verifyOwn(r.PostFormValue("refresh_token"), "refresh")
	if err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "invalid or expired refresh token")
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("client_id")), []byte(c.str("cid"))) != 1 {
		oauthError(w, http.StatusBadRequest, "invalid_grant", "client_id mismatch")
		return
	}
	email := c.str("email")
	if !s.allowed(email) { // allowlist changes take effect at refresh time
		oauthError(w, http.StatusBadRequest, "invalid_grant", "user no longer authorized")
		return
	}
	s.issueTokens(w, email, c.str("cid"), c.str("scope"), c.str("resource"), "", false)
}

// issueTokens writes the token response. withRefresh also mints a refresh
// token (code redemption); refresh-grant responses omit it, meaning the client
// keeps using the one it has until it expires.
func (s *Server) issueTokens(w http.ResponseWriter, email, clientID, scope, resource, nonce string, withRefresh bool) {
	now := time.Now()
	access := claims{
		"iss": s.cfg.Issuer, "typ": "access", "jti": randID(),
		"sub": email, "email": email, "client_id": clientID,
		"iat": now.Unix(), "exp": now.Add(s.cfg.AccessTTL).Unix(),
	}
	if scope != "" {
		access["scope"] = scope
	}
	if resource != "" {
		access["aud"] = resource
	}
	accessTok, err := signJWT(s.cfg.Key, s.kid, access)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
		return
	}
	resp := map[string]any{
		"access_token": accessTok,
		"token_type":   "Bearer",
		"expires_in":   int(s.cfg.AccessTTL.Seconds()),
	}
	if scope != "" {
		resp["scope"] = scope
	}
	if withRefresh {
		refreshTok, err := signJWT(s.cfg.Key, s.kid, claims{
			"iss": s.cfg.Issuer, "typ": "refresh", "jti": randID(),
			"email": email, "cid": clientID, "scope": scope, "resource": resource,
			"iat": now.Unix(), "exp": now.Add(s.cfg.RefreshTTL).Unix(),
		})
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
			return
		}
		resp["refresh_token"] = refreshTok
	}
	if strings.Contains(" "+scope+" ", " openid ") {
		idc := claims{
			"iss": s.cfg.Issuer, "aud": clientID,
			"sub": email, "email": email,
			"iat": now.Unix(), "exp": now.Add(s.cfg.AccessTTL).Unix(),
		}
		if nonce != "" {
			idc["nonce"] = nonce
		}
		idTok, err := signJWT(s.cfg.Key, s.kid, idc)
		if err != nil {
			oauthError(w, http.StatusInternalServerError, "server_error", "signing failed")
			return
		}
		resp["id_token"] = idTok
	}
	s.cfg.Logf("idp: issued tokens for %s", email)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="boxel-idp"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "bearer access token required")
		return
	}
	c, err := s.verifyOwn(strings.TrimPrefix(auth, prefix), "access")
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="boxel-idp", error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired access token")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"sub": c.str("sub"), "email": c.str("email")})
}

// verifyOwn checks a JWT this IDP issued: our signature, our issuer, and the
// expected token type.
func (s *Server) verifyOwn(token, typ string) (claims, error) {
	c, err := verifyJWT(token, func(kid string) (*ecdsa.PublicKey, error) {
		if kid != s.kid {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return &s.cfg.Key.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	if c.str("iss") != s.cfg.Issuer || c.str("typ") != typ {
		return nil, fmt.Errorf("wrong issuer or token type")
	}
	return c, nil
}

// markCodeUsed records a code redemption, reporting false on replay. Expired
// entries are pruned opportunistically; the map stays tiny because codes live
// for CodeTTL only.
func (s *Server) markCodeUsed(jti string, exp time.Time) bool {
	if jti == "" {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.usedCodes {
		if now.After(e.Add(clockSkew)) {
			delete(s.usedCodes, k)
		}
	}
	if _, used := s.usedCodes[jti]; used {
		return false
	}
	s.usedCodes[jti] = exp
	return true
}

// redirectError sends an OAuth error back to the client's redirect_uri (which
// the caller has already validated against the registration).
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// randID returns a fresh unguessable identifier (for jti claims).
func randID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return b64u(b)
}

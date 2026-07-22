package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/mkmik/boxel/internal/idp"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
}

func do(t *testing.T, h http.Handler, headers map[string]string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// Regression test: the SDK's localhost DNS-rebinding protection must not 403
// requests that arrive on a loopback listener with the public Host header a
// fronting proxy (exe.dev, cloudflared) forwards.
func TestStreamableHandlerAcceptsForwardedPublicHost(t *testing.T) {
	h := newStreamableHandler(mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil))
	ts := httptest.NewServer(h) // binds 127.0.0.1
	defer ts.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`
	req, err := http.NewRequest(http.MethodPost, ts.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "boxel.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize with public Host: code %d, body %q", resp.StatusCode, b)
	}
}

func TestAuthMiddlewareRefusesUnauthenticated(t *testing.T) {
	if _, _, _, err := authLayers("", "", nil); err == nil {
		t.Fatal("expected error when no auth is configured")
	}
}

func TestAuthMiddlewareBearerOnly(t *testing.T) {
	wrap, ok, desc, err := authLayers("sekret", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := wrap(okHandler())
	if desc != "bearer" {
		t.Errorf("desc = %q, want bearer", desc)
	}
	if code := do(t, h, map[string]string{"Authorization": "Bearer sekret"}); code != http.StatusOK {
		t.Errorf("valid bearer: code %d", code)
	}
	if code := do(t, h, map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Errorf("bad bearer: code %d, want 401", code)
	}
	if code := do(t, h, nil); code != http.StatusUnauthorized {
		t.Errorf("no bearer: code %d, want 401", code)
	}
	// The predicate mirrors the middleware.
	req := httptest.NewRequest(http.MethodGet, "/install-agent", nil)
	if ok(req) {
		t.Error("predicate passed an unauthenticated request")
	}
	req.Header.Set("Authorization", "Bearer sekret")
	if !ok(req) {
		t.Error("predicate rejected a valid bearer")
	}
}

func TestAuthMiddlewareExeIdentityOnly(t *testing.T) {
	wrap, _, desc, err := authLayers("", "owner@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := wrap(okHandler())
	if desc != "exe-identity(owner@example.com)" {
		t.Errorf("desc = %q", desc)
	}
	// Correct owner (case/space-insensitive) passes.
	if code := do(t, h, map[string]string{exeEmailHeader: "  Owner@Example.com "}); code != http.StatusOK {
		t.Errorf("owner: code %d, want 200", code)
	}
	// Missing header → 401 (request did not traverse the authenticating edge).
	if code := do(t, h, nil); code != http.StatusUnauthorized {
		t.Errorf("missing header: code %d, want 401", code)
	}
	// Different authenticated user → 403.
	if code := do(t, h, map[string]string{exeEmailHeader: "intruder@example.com"}); code != http.StatusForbidden {
		t.Errorf("non-owner: code %d, want 403", code)
	}
}

// newTestVerifier returns a Verifier plus a mint function producing access
// tokens signed by the matching key.
func newTestVerifier(t *testing.T, issuer string) (*idp.Verifier, func(email string) string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := idp.New(idp.Config{
		Issuer: issuer,
		Users:  []string{"owner@example.com"},
		Key:    key,
		Logf:   t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.AttachRoutes(mux)
	return s.Verifier(), func(email string) string { return mintAccessToken(t, mux, email) }
}

// mintAccessToken runs the full register→authorize→token flow against the
// IDP handlers in-process and returns the access token.
func mintAccessToken(t *testing.T, mux *http.ServeMux, email string) string {
	t.Helper()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	// The issuer in s doesn't match ts.URL, but nothing in this flow
	// validates the request Host against the issuer, so the handlers work.
	regBody := `{"client_name":"t","redirect_uris":["https://client.example/cb"]}`
	res, err := http.Post(ts.URL+idp.RegisterPath, "application/json", strings.NewReader(regBody))
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()

	verifier := "0123456789abcdef0123456789abcdef0123456789abcdef"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	q := url.Values{
		"response_type": {"code"}, "client_id": {reg.ClientID},
		"redirect_uri":   {"https://client.example/cb"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	noRedir := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	greq, _ := http.NewRequest(http.MethodGet, ts.URL+idp.AuthorizePath+"?"+q.Encode(), nil)
	greq.Header.Set(idp.HeaderExeEmail, email)
	gres, err := noRedir.Do(greq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(gres.Body)
	gres.Body.Close()
	m := regexp.MustCompile(`name="req" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("no consent blob: %d %s", gres.StatusCode, body)
	}
	form := url.Values{"req": {string(m[1])}, "decision": {"approve"}}
	preq, _ := http.NewRequest(http.MethodPost, ts.URL+idp.AuthorizePath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set(idp.HeaderExeEmail, email)
	pres, err := noRedir.Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	pres.Body.Close()
	loc, _ := url.Parse(pres.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code: %s", pres.Header.Get("Location"))
	}
	tres, err := http.PostForm(ts.URL+idp.TokenPath, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"code_verifier": {verifier}, "client_id": {reg.ClientID},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tres.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tres.Body).Decode(&tok); err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken == "" {
		t.Fatal("no access token")
	}
	return tok.AccessToken
}

func TestAuthMiddlewareOAuth(t *testing.T) {
	v, mint := newTestVerifier(t, "https://idp.example")
	wrap, ok, desc, err := authLayers("", "", v)
	if err != nil {
		t.Fatal(err)
	}
	h := wrap(okHandler())
	if desc != "oauth(https://idp.example)" {
		t.Errorf("desc = %q", desc)
	}
	access := mint("owner@example.com")
	if code := do(t, h, map[string]string{"Authorization": "Bearer " + access}); code != http.StatusOK {
		t.Errorf("valid oauth token: code %d, want 200", code)
	}
	// Unauthenticated → 401 with an RFC 9728 resource_metadata challenge.
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: code %d, want 401", rec.Code)
	}
	if www := rec.Header().Get("WWW-Authenticate"); !strings.Contains(www, "resource_metadata=") {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata challenge", www)
	}
	if ok(req) {
		t.Error("predicate passed an unauthenticated request")
	}
	// Garbage tokens fail.
	if code := do(t, h, map[string]string{"Authorization": "Bearer garbage"}); code != http.StatusUnauthorized {
		t.Errorf("garbage token: code %d, want 401", code)
	}
}

func TestAuthMiddlewareOAuthOrStatic(t *testing.T) {
	v, mint := newTestVerifier(t, "https://idp.example")
	wrap, _, desc, err := authLayers("sekret", "", v)
	if err != nil {
		t.Fatal(err)
	}
	h := wrap(okHandler())
	if desc != "bearer or oauth(https://idp.example)" {
		t.Errorf("desc = %q", desc)
	}
	// Either method alone satisfies the guard.
	if code := do(t, h, map[string]string{"Authorization": "Bearer sekret"}); code != http.StatusOK {
		t.Errorf("static bearer: code %d, want 200", code)
	}
	if code := do(t, h, map[string]string{"Authorization": "Bearer " + mint("owner@example.com")}); code != http.StatusOK {
		t.Errorf("oauth token: code %d, want 200", code)
	}
	if code := do(t, h, nil); code != http.StatusUnauthorized {
		t.Errorf("neither: code %d, want 401", code)
	}
}

// The server-level guard is default-deny: every route — the hub dashboard,
// /mcp, unknown paths, anything added in the future — requires auth unless it
// is on the explicit OAuth-spec/self-authenticating public allowlist.
func TestWithGuardDefaultDeny(t *testing.T) {
	wrap, _, _, err := authLayers("sekret", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, p := range []string{"GET /{$}", "/mcp", "/agents", "/vm/somevm/", "/healthz", "/idp/jwks", "/.well-known/oauth-authorization-server", "/hub/connect", "/install-agent"} {
		mux.Handle(p, okHandler())
	}
	h := withGuard(wrap, mux)

	get := func(path, token string) int {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Guarded by default, including the dashboard and unregistered paths.
	for _, p := range []string{"/", "/mcp", "/agents", "/vm/somevm/mcp", "/no-such-route"} {
		if code := get(p, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s unauthenticated: code %d, want 401", p, code)
		}
	}
	if code := get("/", "sekret"); code != http.StatusOK {
		t.Errorf("dashboard with auth: code %d, want 200", code)
	}
	// The closed public allowlist stays reachable without credentials.
	for _, p := range []string{"/healthz", "/idp/jwks", "/.well-known/oauth-authorization-server", "/hub/connect", "/install-agent"} {
		if code := get(p, ""); code != http.StatusOK {
			t.Errorf("GET %s (public): code %d, want 200", p, code)
		}
	}
}

func TestDefaultIDPIssuer(t *testing.T) {
	issuer := defaultIDPIssuer()
	if issuer == "" {
		t.Skip("no hostname available")
	}
	if !strings.HasPrefix(issuer, "https://") || !strings.HasSuffix(issuer, ".exe.xyz") {
		t.Errorf("defaultIDPIssuer() = %q, want https://<short-hostname>.exe.xyz", issuer)
	}
	if strings.Contains(strings.TrimSuffix(strings.TrimPrefix(issuer, "https://"), ".exe.xyz"), ".") {
		t.Errorf("defaultIDPIssuer() = %q, hostname not shortened", issuer)
	}
}

func TestResourceMetadataEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	attachResourceMetadata(mux, "https://idp.example")
	for path, wantResource := range map[string]string{
		"/.well-known/oauth-protected-resource":          "https://vm.exe.xyz/mcp",
		"/.well-known/oauth-protected-resource/mcp":      "https://vm.exe.xyz/mcp",
		"/.well-known/oauth-protected-resource/vm/a/mcp": "https://vm.exe.xyz/vm/a/mcp",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Host = "vm.exe.xyz"
		req.Header.Set("X-Forwarded-Proto", "https")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: code %d", path, rec.Code)
		}
		var meta struct {
			Resource             string   `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
			t.Fatal(err)
		}
		if meta.Resource != wantResource {
			t.Errorf("%s: resource = %q, want %q", path, meta.Resource, wantResource)
		}
		if len(meta.AuthorizationServers) != 1 || meta.AuthorizationServers[0] != "https://idp.example" {
			t.Errorf("%s: authorization_servers = %v", path, meta.AuthorizationServers)
		}
	}
}

func TestAuthMiddlewareBothLayers(t *testing.T) {
	wrap, _, desc, err := authLayers("sekret", "owner@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := wrap(okHandler())
	if desc != "bearer+exe-identity(owner@example.com)" {
		t.Errorf("desc = %q", desc)
	}
	// Both satisfied → OK.
	if code := do(t, h, map[string]string{
		"Authorization": "Bearer sekret",
		exeEmailHeader:  "owner@example.com",
	}); code != http.StatusOK {
		t.Errorf("both: code %d, want 200", code)
	}
	// Valid bearer but wrong owner → 403 (bearer layer passes, identity fails).
	if code := do(t, h, map[string]string{
		"Authorization": "Bearer sekret",
		exeEmailHeader:  "intruder@example.com",
	}); code != http.StatusForbidden {
		t.Errorf("wrong owner: code %d, want 403", code)
	}
	// Right owner but no bearer → 401 (bearer layer is outermost).
	if code := do(t, h, map[string]string{exeEmailHeader: "owner@example.com"}); code != http.StatusUnauthorized {
		t.Errorf("no bearer: code %d, want 401", code)
	}
}

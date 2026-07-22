package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// newTestIDP starts an IDP whose issuer is the httptest server's own URL.
func newTestIDP(t *testing.T, users ...string) (*Server, *httptest.Server) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	if len(users) == 0 {
		users = []string{"owner@example.com"}
	}
	s, err := New(Config{
		Issuer: ts.URL,
		Users:  users,
		Key:    key,
		Logf:   t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.AttachRoutes(mux)
	return s, ts
}

// noRedirect returns a client that surfaces 3xx responses instead of
// following them.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func registerClient(t *testing.T, ts *httptest.Server, redirectURI string) string {
	t.Helper()
	body := `{"client_name":"Test Client","redirect_uris":["` + redirectURI + `"]}`
	res, err := http.Post(ts.URL+RegisterPath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("register: %d %s", res.StatusCode, b)
	}
	var reg struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(res.Body).Decode(&reg); err != nil {
		t.Fatal(err)
	}
	if reg.ClientID == "" {
		t.Fatal("register returned empty client_id")
	}
	return reg.ClientID
}

const (
	testRedirect = "https://client.example/cb"
	testVerifier = "0123456789abcdef0123456789abcdef0123456789abcdef"
)

func testChallenge() string {
	sum := sha256.Sum256([]byte(testVerifier))
	return b64u(sum[:])
}

func authorizeURL(ts *httptest.Server, clientID string, extra url.Values) string {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"code_challenge":        {testChallenge()},
		"code_challenge_method": {"S256"},
		"state":                 {"st4te"},
	}
	for k, vs := range extra {
		q[k] = vs
	}
	return ts.URL + AuthorizePath + "?" + q.Encode()
}

var reqBlobRE = regexp.MustCompile(`name="req" value="([^"]+)"`)

// authorize runs the GET (consent form) + POST (approval) round trip as
// email and returns the authorization code.
func authorizeAs(t *testing.T, ts *httptest.Server, clientID, email string, extra url.Values) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, authorizeURL(ts, clientID, extra), nil)
	req.Header.Set(HeaderExeEmail, email)
	res, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("authorize GET: %d %s", res.StatusCode, body)
	}
	m := reqBlobRE.FindSubmatch(body)
	if m == nil {
		t.Fatalf("consent form has no req blob: %s", body)
	}
	form := url.Values{"req": {string(m[1])}, "decision": {"approve"}}
	preq, _ := http.NewRequest(http.MethodPost, ts.URL+AuthorizePath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set(HeaderExeEmail, email)
	pres, err := noRedirect().Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(pres.Body)
		t.Fatalf("authorize POST: %d %s", pres.StatusCode, b)
	}
	loc, err := url.Parse(pres.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc.String(), testRedirect) {
		t.Fatalf("redirected to %s, want %s", loc, testRedirect)
	}
	if got := loc.Query().Get("state"); got != "st4te" {
		t.Fatalf("state = %q, want st4te", got)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}
	return code
}

func redeemCode(t *testing.T, ts *httptest.Server, clientID, code, verifier string) (*http.Response, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"redirect_uri":  {testRedirect},
	}
	res, err := http.PostForm(ts.URL+TokenPath, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res, out
}

func TestMetadata(t *testing.T) {
	_, ts := newTestIDP(t)
	for _, wk := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		res, err := http.Get(ts.URL + wk)
		if err != nil {
			t.Fatal(err)
		}
		var meta map[string]any
		if err := json.NewDecoder(res.Body).Decode(&meta); err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if meta["issuer"] != ts.URL {
			t.Errorf("%s: issuer = %v, want %s", wk, meta["issuer"], ts.URL)
		}
		for _, k := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri"} {
			if meta[k] == nil {
				t.Errorf("%s: missing %s", wk, k)
			}
		}
	}
}

func TestAuthorizeBouncesAnonymousToExeLogin(t *testing.T) {
	_, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)
	res, err := noRedirect().Get(authorizeURL(ts, clientID, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("code %d, want 302", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, exeLoginPath+"?redirect=") {
		t.Fatalf("Location = %q, want %s bounce", loc, exeLoginPath)
	}
	// The bounce must round-trip back to the same authorize request.
	back, err := url.QueryUnescape(strings.TrimPrefix(loc, exeLoginPath+"?redirect="))
	if err != nil || !strings.HasPrefix(back, AuthorizePath+"?") {
		t.Fatalf("redirect param %q does not return to authorize", back)
	}
}

func TestAuthorizeRejectsNonAllowlistedUser(t *testing.T) {
	_, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)
	req, _ := http.NewRequest(http.MethodGet, authorizeURL(ts, clientID, nil), nil)
	req.Header.Set(HeaderExeEmail, "intruder@example.com")
	res, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("code %d, want 302 error redirect", res.StatusCode)
	}
	loc, _ := url.Parse(res.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("error = %q, want access_denied", got)
	}
}

func TestAuthorizeRejectsUnregisteredRedirectURI(t *testing.T) {
	_, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)
	u := authorizeURL(ts, clientID, url.Values{"redirect_uri": {"https://evil.example/cb"}})
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set(HeaderExeEmail, "owner@example.com")
	res, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("code %d, want 400 (never redirect to unregistered URIs)", res.StatusCode)
	}
}

func TestFullCodeFlow(t *testing.T) {
	s, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)
	code := authorizeAs(t, ts, clientID, "Owner@Example.com", url.Values{
		"scope":    {"openid email"},
		"nonce":    {"n0nce"},
		"resource": {"https://res.example/mcp"},
	})

	res, tok := redeemCode(t, ts, clientID, code, testVerifier)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("token: %d %v", res.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	idTok, _ := tok["id_token"].(string)
	if access == "" || refresh == "" {
		t.Fatalf("missing tokens: %v", tok)
	}
	if idTok == "" {
		t.Fatal("scope openid requested but no id_token issued")
	}

	// The co-located verifier accepts the access token for the right host...
	v := s.Verifier()
	req := httptest.NewRequest(http.MethodPost, "https://res.example/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	email, err := v.VerifyRequest(req)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if email != "owner@example.com" {
		t.Fatalf("email = %q", email)
	}
	// ...but rejects it for a different host (audience restriction)...
	wrongHost := httptest.NewRequest(http.MethodPost, "https://other.example/mcp", nil)
	wrongHost.Header.Set("Authorization", "Bearer "+access)
	if _, err := v.VerifyRequest(wrongHost); err == nil {
		t.Fatal("token with foreign audience accepted")
	}
	// ...and rejects refresh and ID tokens presented as access tokens.
	for name, tk := range map[string]string{"refresh": refresh, "id": idTok} {
		r := httptest.NewRequest(http.MethodPost, "https://res.example/mcp", nil)
		r.Header.Set("Authorization", "Bearer "+tk)
		if _, err := v.VerifyRequest(r); err == nil {
			t.Fatalf("%s token accepted as access token", name)
		}
	}

	// Codes are single-use.
	if res, _ := redeemCode(t, ts, clientID, code, testVerifier); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed code: %d, want 400", res.StatusCode)
	}

	// The refresh grant issues a fresh access token.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}
	rres, err := http.PostForm(ts.URL+TokenPath, form)
	if err != nil {
		t.Fatal(err)
	}
	defer rres.Body.Close()
	var rtok map[string]any
	_ = json.NewDecoder(rres.Body).Decode(&rtok)
	if rres.StatusCode != http.StatusOK {
		t.Fatalf("refresh: %d %v", rres.StatusCode, rtok)
	}
	access2, _ := rtok["access_token"].(string)
	if access2 == "" {
		t.Fatalf("refresh returned no access token: %v", rtok)
	}
	req2 := httptest.NewRequest(http.MethodPost, "https://res.example/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+access2)
	if _, err := v.VerifyRequest(req2); err != nil {
		t.Fatalf("verify refreshed token: %v", err)
	}

	// Userinfo works with the access token.
	ureq, _ := http.NewRequest(http.MethodGet, ts.URL+UserinfoPath, nil)
	ureq.Header.Set("Authorization", "Bearer "+access)
	ures, err := http.DefaultClient.Do(ureq)
	if err != nil {
		t.Fatal(err)
	}
	defer ures.Body.Close()
	var ui map[string]string
	_ = json.NewDecoder(ures.Body).Decode(&ui)
	if ures.StatusCode != http.StatusOK || ui["email"] != "owner@example.com" {
		t.Fatalf("userinfo: %d %v", ures.StatusCode, ui)
	}
}

func TestTokenRejectsBadPKCEAndWrongClient(t *testing.T) {
	_, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)

	code := authorizeAs(t, ts, clientID, "owner@example.com", nil)
	if res, tok := redeemCode(t, ts, clientID, code, "wrong-verifier-wrong-verifier-wrong-verifier"); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad PKCE: %d %v", res.StatusCode, tok)
	}

	code2 := authorizeAs(t, ts, clientID, "owner@example.com", nil)
	otherClient := registerClient(t, ts, "https://other.example/cb")
	if res, tok := redeemCode(t, ts, otherClient, code2, testVerifier); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("wrong client: %d %v", res.StatusCode, tok)
	}
}

func TestConsentPostRejectsIdentityMismatch(t *testing.T) {
	_, ts := newTestIDP(t, "owner@example.com", "second@example.com")
	clientID := registerClient(t, ts, testRedirect)
	req, _ := http.NewRequest(http.MethodGet, authorizeURL(ts, clientID, nil), nil)
	req.Header.Set(HeaderExeEmail, "owner@example.com")
	res, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := reqBlobRE.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no req blob: %s", body)
	}
	// A different (even allowlisted) user must not be able to submit the form.
	form := url.Values{"req": {string(m[1])}, "decision": {"approve"}}
	preq, _ := http.NewRequest(http.MethodPost, ts.URL+AuthorizePath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set(HeaderExeEmail, "second@example.com")
	pres, err := noRedirect().Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	if pres.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-user consent: %d, want 403", pres.StatusCode)
	}
}

func TestConsentDenyRedirectsWithError(t *testing.T) {
	_, ts := newTestIDP(t)
	clientID := registerClient(t, ts, testRedirect)
	req, _ := http.NewRequest(http.MethodGet, authorizeURL(ts, clientID, nil), nil)
	req.Header.Set(HeaderExeEmail, "owner@example.com")
	res, err := noRedirect().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	m := reqBlobRE.FindSubmatch(body)
	form := url.Values{"req": {string(m[1])}, "decision": {"deny"}}
	preq, _ := http.NewRequest(http.MethodPost, ts.URL+AuthorizePath, strings.NewReader(form.Encode()))
	preq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	preq.Header.Set(HeaderExeEmail, "owner@example.com")
	pres, err := noRedirect().Do(preq)
	if err != nil {
		t.Fatal(err)
	}
	defer pres.Body.Close()
	loc, _ := url.Parse(pres.Header.Get("Location"))
	if got := loc.Query().Get("error"); got != "access_denied" {
		t.Fatalf("deny: error = %q, want access_denied", got)
	}
}

func TestVerifierRejectsForeignKey(t *testing.T) {
	s, ts := newTestIDP(t)
	v := s.Verifier()

	// A well-formed access token signed by a *different* key must be
	// rejected — even if it reuses the IDP's kid.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, kid := range []string{keyID(&otherKey.PublicKey), keyID(&s.cfg.Key.PublicKey)} {
		forged, err := signJWT(otherKey, kid, claims{
			"iss": ts.URL, "typ": "access", "sub": "owner@example.com", "email": "owner@example.com",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		freq := httptest.NewRequest(http.MethodPost, "https://res.example/mcp", nil)
		freq.Header.Set("Authorization", "Bearer "+forged)
		if _, err := v.VerifyRequest(freq); err == nil {
			t.Fatalf("forged token (kid %s) accepted", kid)
		}
	}
}

func TestJWTTamperRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kid := keyID(&key.PublicKey)
	tok, err := signJWT(key, kid, claims{"sub": "a", "exp": time.Now().Add(time.Hour).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	verify := func(s string) error {
		_, err := verifyJWT(s, func(kid string) (*ecdsa.PublicKey, error) { return &key.PublicKey, nil })
		return err
	}
	if err := verify(tok); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	parts := strings.Split(tok, ".")
	tampered := parts[0] + "." + b64u([]byte(`{"sub":"b","exp":9999999999}`)) + "." + parts[2]
	if err := verify(tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
	// alg=none style header swap must fail.
	noneHeader := b64u([]byte(`{"alg":"none"}`))
	if err := verify(noneHeader + "." + parts[1] + "."); err == nil {
		t.Fatal("alg=none accepted")
	}
}

func TestExpiredCodeRejected(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	defer ts.Close()
	s, err := New(Config{
		Issuer: ts.URL,
		Users:  []string{"owner@example.com"},
		Key:    key,
		Logf:   func(string, ...any) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := signJWT(key, keyID(&key.PublicKey), claims{
		"iss": ts.URL, "typ": "code", "jti": randID(),
		"sub": "owner@example.com", "email": "owner@example.com",
		"cid": "x", "ruri": testRedirect, "cc": testChallenge(),
		"iat": time.Now().Add(-time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.verifyOwn(expired, "code"); err == nil {
		t.Fatal("expired code accepted")
	}
}

func TestRegisterRejectsBadRedirects(t *testing.T) {
	_, ts := newTestIDP(t)
	for _, body := range []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["http://evil.example/cb"]}`,
		`{"redirect_uris":["not a url"]}`,
		`{"redirect_uris":["https://ok.example/cb#frag"]}`,
	} {
		res, err := http.Post(ts.URL+RegisterPath, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Errorf("register %s: %d, want 400", body, res.StatusCode)
		}
	}
	// Loopback http is fine for dev tools.
	res, err := http.Post(ts.URL+RegisterPath, "application/json",
		strings.NewReader(`{"redirect_uris":["http://localhost:6274/oauth/callback"]}`))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Errorf("loopback redirect: %d, want 201", res.StatusCode)
	}
}

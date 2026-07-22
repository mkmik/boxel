package idp

// Verifier is the resource-server side: it authenticates an incoming HTTP
// request by validating its Bearer JWT against the IDP's signing key — either
// a local key (co-located IDP) or the issuer's published JWKS (remote IDP).

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Verifier validates access tokens from one issuer.
type Verifier struct {
	issuer string

	// local, when set, verifies against this key without any fetching.
	local    *ecdsa.PublicKey
	localKid string

	// Remote JWKS cache.
	client    *http.Client
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// jwksMaxAge is how long a fetched JWKS is trusted before an unknown kid
// triggers a refetch; jwksMinFetchInterval rate-limits refetches so a flood of
// bogus tokens cannot hammer the issuer.
const (
	jwksMaxAge           = time.Hour
	jwksMinFetchInterval = time.Minute
)

// NewLocalVerifier verifies tokens against an in-process signing key.
func NewLocalVerifier(issuer string, pub *ecdsa.PublicKey, kid string) *Verifier {
	return &Verifier{issuer: strings.TrimSuffix(issuer, "/"), local: pub, localKid: kid}
}

// NewRemoteVerifier verifies tokens against the JWKS discovered from the
// issuer's metadata.
func NewRemoteVerifier(issuer string) *Verifier {
	return &Verifier{
		issuer: strings.TrimSuffix(issuer, "/"),
		client: &http.Client{Timeout: 10 * time.Second},
		keys:   map[string]crypto.PublicKey{},
	}
}

// Issuer returns the issuer URL this verifier trusts.
func (v *Verifier) Issuer() string { return v.issuer }

// VerifyRequest authenticates r's Bearer token: signature, issuer, token
// type, expiry, and — when the token carries an audience — that the audience
// matches the host the request arrived on. It returns the authenticated email.
func (v *Verifier) VerifyRequest(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return "", fmt.Errorf("no bearer token")
	}
	c, err := verifyJWT(strings.TrimPrefix(auth, prefix), v.keyFor)
	if err != nil {
		return "", err
	}
	if c.str("iss") != v.issuer {
		return "", fmt.Errorf("token issuer %q is not %q", c.str("iss"), v.issuer)
	}
	if c.str("typ") != "access" {
		return "", fmt.Errorf("not an access token")
	}
	email := strings.ToLower(c.str("email"))
	if email == "" {
		email = strings.ToLower(c.str("sub"))
	}
	if email == "" {
		return "", fmt.Errorf("token has no subject")
	}
	// RFC 8707 audience restriction: a token minted for another resource must
	// not work here. The audience is the resource URL the client asked for;
	// compare hosts (the path may be /mcp, /vm/<name>/mcp, ...).
	if aud := c.aud(); len(aud) > 0 {
		if !audMatchesRequest(aud, r) {
			return "", fmt.Errorf("token audience %v does not match this host", aud)
		}
	}
	return email, nil
}

// audMatchesRequest reports whether any audience entry names the host this
// request arrived on (Host, or X-Forwarded-Host behind the edge proxy).
func audMatchesRequest(aud []string, r *http.Request) bool {
	hosts := []string{normalizeHost(r.Host)}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" {
		hosts = append(hosts, normalizeHost(fh))
	}
	for _, a := range aud {
		u, err := url.Parse(a)
		if err != nil || u.Host == "" {
			continue
		}
		ah := normalizeHost(u.Host)
		for _, h := range hosts {
			if h != "" && h == ah {
				return true
			}
		}
	}
	return false
}

// normalizeHost lowercases and strips default ports.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ":443")
	h = strings.TrimSuffix(h, ":80")
	return h
}

func (v *Verifier) keyFor(kid, alg string) (crypto.PublicKey, error) {
	if v.local != nil {
		if kid != v.localKid || alg != "ES256" {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return v.local, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if key, ok := v.keys[kid]; ok && time.Since(v.fetchedAt) < jwksMaxAge {
		return key, nil
	}
	// Unknown kid or stale cache: refetch, rate-limited.
	if time.Since(v.fetchedAt) >= jwksMinFetchInterval {
		keys, err := v.fetchJWKS()
		if err != nil {
			if key, ok := v.keys[kid]; ok {
				return key, nil // fetch failed; fall back to the stale cache
			}
			return nil, fmt.Errorf("fetch issuer keys: %w", err)
		}
		v.keys, v.fetchedAt = keys, time.Now()
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown key %q", kid)
}

// fetchJWKS discovers jwks_uri from the issuer's metadata (RFC 8414 with an
// OIDC-discovery fallback) and fetches the key set. Called with v.mu held.
func (v *Verifier) fetchJWKS() (map[string]crypto.PublicKey, error) {
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	var lastErr error
	for _, wk := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		if lastErr = v.getJSON(v.issuer+wk, &meta); lastErr == nil && meta.JWKSURI != "" {
			break
		}
	}
	if meta.JWKSURI == "" {
		return nil, fmt.Errorf("issuer metadata has no jwks_uri (last error: %v)", lastErr)
	}
	var set jwkSet
	if err := v.getJSON(meta.JWKSURI, &set); err != nil {
		return nil, err
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		pub, err := k.publicKey()
		if err != nil {
			continue // skip key types we don't support
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("issuer JWKS contains no usable keys")
	}
	return keys, nil
}

func (v *Verifier) getJSON(u string, out any) error {
	res, err := v.client.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(out)
}

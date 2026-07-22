package idp

// Verifier is the resource-server side: it authenticates an incoming HTTP
// request by validating its Bearer JWT against the co-located IDP's signing
// key.

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Verifier validates access tokens issued by the in-process IDP.
type Verifier struct {
	issuer string
	pub    *ecdsa.PublicKey
	kid    string
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
	c, err := verifyJWT(strings.TrimPrefix(auth, prefix), func(kid string) (*ecdsa.PublicKey, error) {
		if kid != v.kid {
			return nil, fmt.Errorf("unknown key %q", kid)
		}
		return v.pub, nil
	})
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

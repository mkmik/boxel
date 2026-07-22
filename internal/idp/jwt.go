package idp

// Minimal JWS/JWT support: ES256 issuing and verification (the built-in IDP
// signs everything with one P-256 key) plus RS256 verification (so the
// resource-side Verifier can also point at a third-party issuer). Deliberately
// dependency-free, like the rest of the module.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// clockSkew is the leeway applied to exp/nbf checks.
const clockSkew = 60 * time.Second

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64uDecode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// claims is a JWT claim set. Values follow encoding/json conventions
// (numbers are float64 after a round trip).
type claims map[string]any

func (c claims) str(k string) string {
	s, _ := c[k].(string)
	return s
}

func (c claims) num(k string) int64 {
	switch v := c[k].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

// aud returns the aud claim normalized to a slice (it may be a string or an
// array of strings on the wire).
func (c claims) aud() []string {
	switch v := c["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// jwk is a JSON Web Key, covering the EC and RSA fields this package uses.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Kid string `json:"kid,omitempty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// publicKey converts a JWK into a crypto.PublicKey.
func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("unsupported EC curve %q", k.Crv)
		}
		xb, err := b64uDecode(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk x: %w", err)
		}
		yb, err := b64uDecode(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(xb),
			Y:     new(big.Int).SetBytes(yb),
		}, nil
	case "RSA":
		nb, err := b64uDecode(k.N)
		if err != nil {
			return nil, fmt.Errorf("jwk n: %w", err)
		}
		eb, err := b64uDecode(k.E)
		if err != nil {
			return nil, fmt.Errorf("jwk e: %w", err)
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > 1<<31 {
			return nil, fmt.Errorf("jwk: invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
	}
	return nil, fmt.Errorf("unsupported jwk kty %q", k.Kty)
}

// ecJWK renders the public half of an ES256 signing key as a JWK.
func ecJWK(pub *ecdsa.PublicKey, kid string) jwk {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	return jwk{Kty: "EC", Crv: "P-256", X: b64u(x), Y: b64u(y), Kid: kid, Alg: "ES256", Use: "sig"}
}

// keyID derives a stable key identifier from the public key.
func keyID(pub *ecdsa.PublicKey) string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	pub.X.FillBytes(x)
	pub.Y.FillBytes(y)
	sum := sha256.Sum256(append(x, y...))
	return b64u(sum[:8])
}

// signJWT issues an ES256-signed JWT with the given claims.
func signJWT(key *ecdsa.PrivateKey, kid string, c claims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := b64u(header) + "." + b64u(payload)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64u(sig), nil
}

// verifyJWT checks the signature and time validity of token. keyFor resolves
// the verification key from the header's kid and alg; the alg is restricted to
// ES256/RS256 (asymmetric only — "none" and HMAC are rejected by construction).
func verifyJWT(token string, keyFor func(kid, alg string) (crypto.PublicKey, error)) (claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: malformed token")
	}
	hb, err := b64uDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &header); err != nil {
		return nil, fmt.Errorf("jwt: header: %w", err)
	}
	if header.Alg != "ES256" && header.Alg != "RS256" {
		return nil, fmt.Errorf("jwt: unsupported alg %q", header.Alg)
	}
	key, err := keyFor(header.Kid, header.Alg)
	if err != nil {
		return nil, err
	}
	sig, err := b64uDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: signature: %w", err)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		if header.Alg != "ES256" || len(sig) != 64 {
			return nil, fmt.Errorf("jwt: alg/key mismatch")
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, sum[:], r, s) {
			return nil, fmt.Errorf("jwt: invalid signature")
		}
	case *rsa.PublicKey:
		if header.Alg != "RS256" {
			return nil, fmt.Errorf("jwt: alg/key mismatch")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig); err != nil {
			return nil, fmt.Errorf("jwt: invalid signature")
		}
	default:
		return nil, fmt.Errorf("jwt: unsupported key type %T", key)
	}
	pb, err := b64uDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: payload: %w", err)
	}
	var c claims
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, fmt.Errorf("jwt: payload: %w", err)
	}
	now := time.Now()
	exp := c.num("exp")
	if exp == 0 {
		return nil, fmt.Errorf("jwt: missing exp")
	}
	if now.After(time.Unix(exp, 0).Add(clockSkew)) {
		return nil, fmt.Errorf("jwt: expired")
	}
	if nbf := c.num("nbf"); nbf != 0 && now.Add(clockSkew).Before(time.Unix(nbf, 0)) {
		return nil, fmt.Errorf("jwt: not yet valid")
	}
	return c, nil
}

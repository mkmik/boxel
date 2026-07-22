package idp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// LoadOrCreateKey returns the IDP's P-256 signing key. When path exists it is
// read (PEM "EC PRIVATE KEY"); when it does not, a fresh key is generated and
// written there with 0600 permissions. An empty path generates an ephemeral
// key — every token, code, and registered client is invalidated on restart, so
// it is only suitable for testing.
func LoadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if path == "" {
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "EC PRIVATE KEY" {
			return nil, fmt.Errorf("idp key %s: expected a PEM EC PRIVATE KEY block", path)
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("idp key %s: %w", path, err)
		}
		if key.Curve != elliptic.P256() {
			return nil, fmt.Errorf("idp key %s: not a P-256 key", path)
		}
		return key, nil
	case errors.Is(err, fs.ErrNotExist):
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		b := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, fmt.Errorf("write idp key: %w", err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("read idp key: %w", err)
	}
}

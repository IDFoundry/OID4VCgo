// Package devjwk parses the public JWKs the mobile package hands a
// WalletProvider, for the test services and the test build: a real
// Wallet Provider parses them with its own JOSE library.
package devjwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ParseP256 parses a P-256 public JWK.
func ParseP256(raw []byte) (*ecdsa.PublicKey, error) {
	var jwk struct{ Kty, Crv, X, Y string }
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, err
	}
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("devjwk: not a P-256 JWK: %s", raw)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}
	if len(x) != 32 || len(y) != 32 {
		return nil, errors.New("devjwk: malformed P-256 coordinates")
	}
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
}

// ParseP256Set parses a JSON array of P-256 public JWKs.
func ParseP256Set(raw []byte) ([]*ecdsa.PublicKey, error) {
	var set []json.RawMessage
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, err
	}
	keys := make([]*ecdsa.PublicKey, 0, len(set))
	for _, r := range set {
		k, err := ParseP256(r)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

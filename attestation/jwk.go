package attestation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var b64 = base64.RawURLEncoding

// jwk is the minimal JWK (RFC 7517) shape this package needs to
// marshal an attested public key and compare it against another —
// P-256 EC keys and Ed25519 OKP keys, the two algorithms
// internal/jose supports. Extend alongside internal/jose if a real
// need for another key type arises; this is deliberately not a
// general-purpose JWK codec.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// marshalJWK encodes pub as a JWK.
func marshalJWK(pub crypto.PublicKey) (json.RawMessage, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("attestation: unsupported EC curve (only P-256 is supported)")
		}
		// SEC1 uncompressed point: 0x04 || X || Y, each 32 bytes for
		// P-256 — avoids the deprecated PublicKey.X/Y field access (see
		// crypto/ecdsa's own doc comment as of Go 1.26).
		raw, err := k.Bytes()
		if err != nil {
			return nil, fmt.Errorf("attestation: encode public key: %w", err)
		}
		size := (len(raw) - 1) / 2
		return json.Marshal(jwk{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1 : 1+size]), Y: b64.EncodeToString(raw[1+size:])})
	case ed25519.PublicKey:
		return json.Marshal(jwk{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(k)})
	default:
		return nil, fmt.Errorf("attestation: unsupported public key type %T", pub)
	}
}

// matchesPublicKey reports whether attestedKeyJSON — one element of a
// Key Attestation's attested_keys array — encodes the same public key
// as pub.
func matchesPublicKey(attestedKeyJSON []byte, pub crypto.PublicKey) (bool, error) {
	candidate, err := marshalJWK(pub)
	if err != nil {
		return false, err
	}
	var want, got jwk
	if err := json.Unmarshal(attestedKeyJSON, &want); err != nil {
		return false, fmt.Errorf("attestation: parse attested key: %w", err)
	}
	if err := json.Unmarshal(candidate, &got); err != nil {
		return false, err
	}
	return want == got, nil
}

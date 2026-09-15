package jwk

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

// JWK is the minimal JWK (RFC 7517) shape this package supports: P-256
// EC keys ("kty":"EC") and Ed25519 OKP keys ("kty":"OKP").
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// Marshal encodes pub as a JWK.
func Marshal(pub crypto.PublicKey) (JWK, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return JWK{}, fmt.Errorf("jwk: unsupported EC curve (only P-256 is supported)")
		}
		// SEC1 uncompressed point: 0x04 || X || Y, each 32 bytes for
		// P-256 — avoids the deprecated PublicKey.X/Y field access (see
		// crypto/ecdsa's own doc comment as of Go 1.26).
		raw, err := k.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("jwk: encode public key: %w", err)
		}
		size := (len(raw) - 1) / 2
		return JWK{Kty: "EC", Crv: "P-256", X: b64.EncodeToString(raw[1 : 1+size]), Y: b64.EncodeToString(raw[1+size:])}, nil
	case ed25519.PublicKey:
		return JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(k)}, nil
	default:
		return JWK{}, fmt.Errorf("jwk: unsupported public key type %T", pub)
	}
}

// PublicKey decodes k into a crypto.PublicKey.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("jwk: unsupported EC curve %q (only P-256 is supported)", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk: decode x: %w", err)
		}
		y, err := b64.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("jwk: decode y: %w", err)
		}
		curve := elliptic.P256()
		size := (curve.Params().BitSize + 7) / 8
		if len(x) != size || len(y) != size {
			return nil, fmt.Errorf("jwk: EC coordinate has unexpected length")
		}
		uncompressed := make([]byte, 0, 1+2*size)
		uncompressed = append(uncompressed, 0x04)
		uncompressed = append(uncompressed, x...)
		uncompressed = append(uncompressed, y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
		if err != nil {
			return nil, fmt.Errorf("jwk: decode EC public key: %w", err)
		}
		return pub, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("jwk: unsupported OKP curve %q (only Ed25519 is supported)", k.Crv)
		}
		x, err := b64.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("jwk: decode x: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("jwk: Ed25519 key has unexpected length %d", len(x))
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("jwk: unsupported key type %q", k.Kty)
	}
}

// ParsePublicKey decodes raw (a JSON-encoded JWK) into a crypto.PublicKey.
func ParsePublicKey(raw []byte) (crypto.PublicKey, error) {
	var k JWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("jwk: unmarshal: %w", err)
	}
	return k.PublicKey()
}

// Matches reports whether raw (a JSON-encoded JWK) encodes the same
// public key as pub.
func Matches(raw []byte, pub crypto.PublicKey) (bool, error) {
	candidate, err := Marshal(pub)
	if err != nil {
		return false, err
	}
	var want JWK
	if err := json.Unmarshal(raw, &want); err != nil {
		return false, fmt.Errorf("jwk: unmarshal: %w", err)
	}
	return want == candidate, nil
}

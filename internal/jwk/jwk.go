package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

var b64 = base64.RawURLEncoding

// JWK is the minimal JWK (RFC 7517) shape this package supports: P-256
// EC keys ("kty":"EC") and Ed25519 OKP keys ("kty":"OKP"). D is only
// ever populated by MarshalPrivate (Marshal never sets it) — kept on
// this same type, not a separate one, so PublicKey/Thumbprint/Matches
// all keep working unchanged on a JWK that happens to carry a private
// half too, the same way a real JWK Set entry can.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// D is the private key (RFC 7518 §6.2.2.1 "d" for EC, RFC 8037 §2
	// "d" for OKP) — the 32-byte private scalar/seed, base64url
	// (no padding) encoded. Empty for a public-only JWK.
	D string `json:"d,omitempty"`
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

// MarshalPrivate encodes priv (its public half via Marshal, plus its
// own private scalar/seed as "d") as a JWK — the counterpart to
// Marshal for a caller that genuinely needs to hand a private key to
// something else as a JWK, e.g. embedding it in a JWK Set another
// party will use to sign with (this repo's own conformance harness
// does this to hand a throwaway private key to the OIDF suite, which
// plays a simulated Wallet/Attester that needs to actually sign with
// it). Ordinary key-holding code should keep using a crypto.Signer
// directly and never call this at all — a JWK's own "d" member is
// nothing more than a wire encoding of a value that should otherwise
// never leave the process holding it.
func MarshalPrivate(priv crypto.PrivateKey) (JWK, error) {
	switch k := priv.(type) {
	case *ecdsa.PrivateKey:
		j, err := Marshal(&k.PublicKey)
		if err != nil {
			return JWK{}, err
		}
		d, err := k.Bytes()
		if err != nil {
			return JWK{}, fmt.Errorf("jwk: encode private key: %w", err)
		}
		j.D = b64.EncodeToString(d)
		return j, nil
	case ed25519.PrivateKey:
		j, err := Marshal(k.Public())
		if err != nil {
			return JWK{}, err
		}
		j.D = b64.EncodeToString(k.Seed())
		return j, nil
	default:
		return JWK{}, fmt.Errorf("jwk: unsupported private key type %T", priv)
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

// Thumbprint computes the RFC 7638 JWK thumbprint: the base64url (no
// padding) encoding of the SHA-256 digest of the key's required
// members, serialized with no whitespace and in the lexicographic
// member-name order (§3.1) RFC 7638 §3.2/RFC 8037 §2 define per key
// type — "crv","kty","x","y" for EC, "crv","kty","x" for OKP, already
// alphabetical. k's own X/Y/Crv fields are already the exact base64url
// values a canonical JWK's own members would carry, so this builds the
// canonical form directly from them rather than re-deriving coordinates
// from a parsed crypto.PublicKey.
func (k JWK) Thumbprint() (string, error) {
	var canonical string
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return "", fmt.Errorf("jwk: thumbprint: unsupported EC curve %q (only P-256 is supported)", k.Crv)
		}
		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, k.X, k.Y)
	case "OKP":
		if k.Crv != "Ed25519" {
			return "", fmt.Errorf("jwk: thumbprint: unsupported OKP curve %q (only Ed25519 is supported)", k.Crv)
		}
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`, k.X)
	default:
		return "", fmt.Errorf("jwk: thumbprint: unsupported kty %q", k.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}

// Thumbprint computes pub's own RFC 7638 SHA-256 JWK thumbprint as raw
// bytes — Marshal + JWK.Thumbprint + base64url-decode in one step,
// since every caller needing a public key's own thumbprint as bytes
// (rather than the base64url string RFC 7638 itself specifies) needs
// all three regardless of which package it's in; this repo's own
// mdoc SessionTranscript construction (Appendix B.2.6.1/B.2.6.2's own
// "jwkThumbprint" input) is one such caller, on both the presenting
// (wallet) and verifying (verifier) side.
func Thumbprint(pub crypto.PublicKey) ([]byte, error) {
	j, err := Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("jwk: thumbprint: marshal public key: %w", err)
	}
	thumbprint, err := j.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("jwk: thumbprint: %w", err)
	}
	raw, err := b64.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("jwk: thumbprint: decode: %w", err)
	}
	return raw, nil
}

// SetEntry is a JWK plus the set-membership metadata RFC 7517 §5
// permits on an individual JWK Set entry ("kid"/"use"/"alg"/"x5c") —
// meaningful only in that context, not to JWK's own
// Marshal/PublicKey/Thumbprint/Matches round trip, so it lives here as
// a separate, composed type rather than on JWK itself. Embeds JWK, so
// a SetEntry marshals as one flat JSON object with the key-material
// fields alongside these — the exact shape a Credential
// Issuer/Verifier's own "client_metadata.jwks"/"jwks_uri" document,
// or a Wallet/Attester's own signing-key JWK Set, needs.
type SetEntry struct {
	JWK
	Kid string   `json:"kid,omitempty"`
	Use string   `json:"use,omitempty"`
	Alg string   `json:"alg,omitempty"`
	X5C []string `json:"x5c,omitempty"`
}

// Set is a JWK Set (RFC 7517 §5): {"keys": [...]}.
type Set struct {
	Keys []SetEntry `json:"keys"`
}

package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
)

// COSE key type and curve identifiers (RFC 9053 §7) this package
// supports — P-256 for ES256 and Ed25519 for EdDSA, matching
// internal/cose's curated algorithm set.
const (
	coseKtyOKP = 1
	coseKtyEC2 = 2

	coseCrvP256    = 1
	coseCrvEd25519 = 6
)

// CoseKey is an untagged COSE_Key (RFC 9052 §7), used for
// DeviceKeyInfo.DeviceKey (§12.3.4) — the mdoc holder authentication
// public key, the analog of SD-JWT VC's cnf.jwk. Field order matches
// RFC 9053's own EC2/OKP examples; Y is absent for an OKP key.
type CoseKey struct {
	Kty int64  `cbor:"1,keyasint"`
	Crv int64  `cbor:"-1,keyasint"`
	X   []byte `cbor:"-2,keyasint"`
	Y   []byte `cbor:"-3,keyasint,omitempty"`
}

// NewCoseKey builds a CoseKey from pub. pub must be a P-256
// *ecdsa.PublicKey or an ed25519.PublicKey.
func NewCoseKey(pub crypto.PublicKey) (CoseKey, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() {
			return CoseKey{}, fmt.Errorf("mdoc: unsupported EC curve %s", p.Curve.Params().Name)
		}
		// Bytes returns the uncompressed SEC1 point (0x04 || X || Y);
		// splitting it avoids touching PublicKey.X/Y directly, which
		// Go 1.26 deprecates in favor of this and ParseUncompressedPublicKey.
		uncompressed, err := p.Bytes()
		if err != nil {
			return CoseKey{}, fmt.Errorf("mdoc: encode EC public key: %w", err)
		}
		size := (len(uncompressed) - 1) / 2
		return CoseKey{
			Kty: coseKtyEC2, Crv: coseCrvP256,
			X: uncompressed[1 : 1+size],
			Y: uncompressed[1+size:],
		}, nil
	case ed25519.PublicKey:
		return CoseKey{Kty: coseKtyOKP, Crv: coseCrvEd25519, X: []byte(p)}, nil
	default:
		return CoseKey{}, fmt.Errorf("mdoc: unsupported public key type %T", pub)
	}
}

// PublicKey reconstructs the crypto.PublicKey k encodes.
func (k CoseKey) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case coseKtyEC2:
		if k.Crv != coseCrvP256 {
			return nil, fmt.Errorf("mdoc: unsupported EC2 curve %d", k.Crv)
		}
		curve := elliptic.P256()
		size := (curve.Params().BitSize + 7) / 8
		if len(k.X) != size || len(k.Y) != size {
			return nil, fmt.Errorf("mdoc: EC2 coordinate has unexpected length")
		}
		uncompressed := make([]byte, 0, 1+2*size)
		uncompressed = append(uncompressed, 0x04)
		uncompressed = append(uncompressed, k.X...)
		uncompressed = append(uncompressed, k.Y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressed)
		if err != nil {
			return nil, fmt.Errorf("mdoc: decode EC2 public key: %w", err)
		}
		return pub, nil
	case coseKtyOKP:
		if k.Crv != coseCrvEd25519 {
			return nil, fmt.Errorf("mdoc: unsupported OKP curve %d", k.Crv)
		}
		if len(k.X) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("mdoc: Ed25519 key has unexpected length %d", len(k.X))
		}
		return ed25519.PublicKey(k.X), nil
	default:
		return nil, fmt.Errorf("mdoc: unsupported COSE key type %d", k.Kty)
	}
}

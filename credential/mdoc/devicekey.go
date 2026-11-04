package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// COSE key type and curve identifiers (RFC 9053 §7) this package
// supports — P-256, P-384 and P-521 for ES256, ES384 and ES512, and
// Ed25519 for EdDSA, matching internal/cose's algorithm set.
const (
	coseKtyOKP = 1
	coseKtyEC2 = 2

	coseCrvP256    = 1
	coseCrvP384    = 2
	coseCrvP521    = 3
	coseCrvEd25519 = 6
)

// ecCurves are the EC2 curves this package supports, by COSE curve
// identifier. ISO/IEC 18013-5's brainpool curves (§9.1.5.2) aren't in
// Go's standard library, and aren't among them.
var ecCurves = map[int64]elliptic.Curve{
	coseCrvP256: elliptic.P256(),
	coseCrvP384: elliptic.P384(),
	coseCrvP521: elliptic.P521(),
}

// ecCurve is the curve a COSE EC2 curve identifier names (RFC 9053
// §7.1), if this package supports it: P-256 (1), P-384 (2) or P-521
// (3).
func ecCurve(crv int64) (elliptic.Curve, bool) {
	c, ok := ecCurves[crv]
	return c, ok
}

// coseCurveID is curve's COSE curve identifier, if this package
// supports it.
func coseCurveID(curve elliptic.Curve) (int64, bool) {
	for id, c := range ecCurves {
		if c == curve {
			return id, true
		}
	}
	return 0, false
}

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

// NewCoseKey builds a CoseKey from pub. pub must be a P-256, P-384 or
// P-521 *ecdsa.PublicKey or an ed25519.PublicKey.
func NewCoseKey(pub crypto.PublicKey) (CoseKey, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		crv, ok := coseCurveID(p.Curve)
		if !ok {
			return CoseKey{}, fmt.Errorf("mdoc: unsupported EC curve %s", curveName(p.Curve))
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
			Kty: coseKtyEC2, Crv: crv,
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
		curve, ok := ecCurve(k.Crv)
		if !ok {
			return nil, fmt.Errorf("mdoc: unsupported EC2 curve %d", k.Crv)
		}
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
		if jwk.IsSmallOrderEd25519(k.X) {
			return nil, fmt.Errorf("mdoc: Ed25519 key is a point of small order")
		}
		return ed25519.PublicKey(k.X), nil
	default:
		return nil, fmt.Errorf("mdoc: unsupported COSE key type %d", k.Kty)
	}
}

// curveName is c's name, for an error: a key built by hand may have
// no curve at all.
func curveName(c elliptic.Curve) string {
	if c == nil || c.Params() == nil {
		return "(none)"
	}
	return c.Params().Name
}

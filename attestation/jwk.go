package attestation

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// b64 is used directly by this package's own tests to build raw
// key-coordinate fixtures.
var b64 = base64.RawURLEncoding

// marshalJWK encodes pub as a JWK (RFC 7517) — P-256 EC and Ed25519
// OKP, the two key types internal/jose supports. The actual encoding
// lives in internal/jwk, shared with issuer's own need to parse a
// Wallet-supplied JWK.
func marshalJWK(pub crypto.PublicKey) (json.RawMessage, error) {
	k, err := jwk.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("attestation: %w", err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return nil, fmt.Errorf("attestation: marshal jwk: %w", err)
	}
	return raw, nil
}

// matchesPublicKey reports whether attestedKeyJSON — one element of a
// Key Attestation's attested_keys array — encodes the same public key
// as pub.
func matchesPublicKey(attestedKeyJSON []byte, pub crypto.PublicKey) (bool, error) {
	ok, err := jwk.Matches(attestedKeyJSON, pub)
	if err != nil {
		return false, fmt.Errorf("attestation: %w", err)
	}
	return ok, nil
}

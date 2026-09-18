package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzParseKeyAttestation exercises Parse/Verify against arbitrary
// strings — a Key Attestation JWT (Appendix D.1) is client-supplied at
// the Credential Endpoint, parsed before any authentication decision.
// Unlike jose.Verify itself, Parse extracts and validates claims
// (iat/attested_keys) before any signature check, so this target
// reaches real structured-payload parsing, not just the outer
// compact-JWS split — a successfully-parsed value is also run through
// Verify without panicking, whether or not it actually verifies.
func FuzzParseKeyAttestation(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	attestedKeyJWK, err := marshalJWK(&key.PublicKey)
	if err != nil {
		f.Fatalf("marshalJWK: %v", err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour).Unix()

	minimal, err := Issue(key, jose.ES256, Header{}, Claims{
		IssuedAt: now.Unix(), AttestedKeys: []json.RawMessage{attestedKeyJWK},
	})
	if err != nil {
		f.Fatalf("Issue(minimal): %v", err)
	}
	full, err := Issue(key, jose.ES256, Header{KeyID: "fuzz-kid"}, Claims{
		IssuedAt: now.Unix(), ExpiresAt: &exp,
		AttestedKeys:       []json.RawMessage{attestedKeyJWK},
		KeyStorage:         []AttackPotentialResistance{ISO18045High},
		UserAuthentication: []AttackPotentialResistance{ISO18045Basic},
		Certification:      "https://example.com/cert", Nonce: "fuzz-nonce",
	})
	if err != nil {
		f.Fatalf("Issue(full): %v", err)
	}

	f.Add(minimal)
	f.Add(full)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, compact string) {
		a, err := Parse(compact)
		if err != nil {
			return
		}
		_, _ = a.Verify(&key.PublicKey, jose.ES256, VerifyOptions{Now: now})
	})
}

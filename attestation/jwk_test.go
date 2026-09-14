package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestMarshalJWK_RejectsUnsupportedCurve(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := marshalJWK(&key.PublicKey); err == nil {
		t.Errorf("marshalJWK accepted a non-P-256 EC key")
	}
}

func TestMarshalJWK_RejectsUnsupportedKeyType(t *testing.T) {
	if _, err := marshalJWK("not a key"); err == nil {
		t.Errorf("marshalJWK accepted an unsupported key type")
	}
}

func TestMatchesPublicKey_RejectsUnsupportedKeyType(t *testing.T) {
	if _, err := matchesPublicKey([]byte(`{"kty":"EC"}`), "not a key"); err == nil {
		t.Errorf("matchesPublicKey accepted an unsupported key type")
	}
}

func TestMatchesPublicKey_RejectsMalformedAttestedKey(t *testing.T) {
	key := testKey(t)
	if _, err := matchesPublicKey([]byte("not json"), &key.PublicKey); err == nil {
		t.Errorf("matchesPublicKey accepted malformed attested-key JSON")
	}
}

package attestation_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// TestAttestedKey_RoundTrips checks a Key Attestation built with
// AttestedKey attests exactly those keys (VerifiedClaims.KeyAttested).
func TestAttestedKey_RoundTrips(t *testing.T) {
	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var keys []json.RawMessage
	for _, pub := range []any{&ecKey.PublicKey, edPub} {
		raw, err := attestation.AttestedKey(pub)
		if err != nil {
			t.Fatalf("AttestedKey(%T): %v", pub, err)
		}
		keys = append(keys, raw)
	}
	now := time.Now()
	compact, err := attestation.Issue(signer, jose.ES256, attestation.Header{}, attestation.Claims{IssuedAt: now.Unix(), AttestedKeys: keys})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&signer.PublicKey, jose.ES256, attestation.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for name, tc := range map[string]struct {
		pub  any
		want bool
	}{"ec": {&ecKey.PublicKey, true}, "ed25519": {edPub, true}, "unattested": {&other.PublicKey, false}} {
		if got, err := verified.KeyAttested(tc.pub); err != nil || got != tc.want {
			t.Errorf("%s: KeyAttested = %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

func TestAttestedKey_RejectsUnsupportedKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := attestation.AttestedKey(&rsaKey.PublicKey); err == nil {
		t.Error("AttestedKey accepted an RSA key")
	}
}

package wallet_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/attestation"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func testAttestedKeyJWK(t *testing.T) json.RawMessage {
	t.Helper()
	raw, err := jwk.Marshal(testP256Key(t).Public())
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal jwk: %v", err)
	}
	return encoded
}

func TestGenerateAttestationProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w, err := wallet.New(validConfig(), wallet.Dependencies{
		HTTP:  validDependencies().HTTP,
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	signer := testP256Key(t)
	attestedKey := testAttestedKeyJWK(t)

	compact, err := w.GenerateAttestationProof(signer, jose.ES256, attestation.Header{}, attestation.Claims{
		AttestedKeys: []json.RawMessage{attestedKey},
	}, "test-nonce")
	if err != nil {
		t.Fatalf("GenerateAttestationProof: %v", err)
	}

	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&signer.PublicKey, jose.ES256, attestation.VerifyOptions{Now: now})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Nonce != "test-nonce" {
		t.Errorf("Nonce = %q, want test-nonce", verified.Nonce)
	}
	if verified.IssuedAt.Unix() != now.Unix() {
		t.Errorf("IssuedAt = %v, want %v", verified.IssuedAt, now)
	}
	if len(verified.AttestedKeys) != 1 {
		t.Fatalf("AttestedKeys = %v, want 1 entry", verified.AttestedKeys)
	}
}

func TestGenerateAttestationProof_OmitsNonceWhenEmpty(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	signer := testP256Key(t)

	compact, err := w.GenerateAttestationProof(signer, jose.ES256, attestation.Header{}, attestation.Claims{
		AttestedKeys: []json.RawMessage{testAttestedKeyJWK(t)},
	}, "")
	if err != nil {
		t.Fatalf("GenerateAttestationProof: %v", err)
	}
	parsed, err := attestation.Parse(compact)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	verified, err := parsed.Verify(&signer.PublicKey, jose.ES256, attestation.VerifyOptions{Now: time.Now()})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verified.Nonce != "" {
		t.Errorf("Nonce = %q, want empty", verified.Nonce)
	}
}

func TestGenerateAttestationProof_RejectsNoAttestedKeys(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.GenerateAttestationProof(testP256Key(t), jose.ES256, attestation.Header{}, attestation.Claims{}, "test-nonce"); err == nil {
		t.Fatalf("GenerateAttestationProof = nil error, want error")
	}
}

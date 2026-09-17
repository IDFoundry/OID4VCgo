package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestGenerateProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	w, err := wallet.New(validConfig(), wallet.Dependencies{
		HTTP:  validDependencies().HTTP,
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)

	proof, err := w.GenerateProof(key, "https://issuer.example.com", "test-nonce")
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if header["typ"] != "openid4vci-proof+jwt" {
		t.Errorf("typ = %v, want openid4vci-proof+jwt", header["typ"])
	}
	if _, ok := header["jwk"]; !ok {
		t.Errorf("jwk header is missing")
	}

	var body struct {
		Aud   string `json:"aud"`
		Iat   int64  `json:"iat"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body.Aud != "https://issuer.example.com" {
		t.Errorf("aud = %q", body.Aud)
	}
	if body.Iat != now.Unix() {
		t.Errorf("iat = %d, want %d", body.Iat, now.Unix())
	}
	if body.Nonce != "test-nonce" {
		t.Errorf("nonce = %q, want %q", body.Nonce, "test-nonce")
	}
}

func TestGenerateProofWithKeyID(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)

	proof, err := w.GenerateProofWithKeyID(key, "did:example:wallet#key-1", "https://issuer.example.com", "test-nonce")
	if err != nil {
		t.Fatalf("GenerateProofWithKeyID: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if header["typ"] != "openid4vci-proof+jwt" {
		t.Errorf("typ = %v, want openid4vci-proof+jwt", header["typ"])
	}
	if header["kid"] != "did:example:wallet#key-1" {
		t.Errorf("kid = %v, want did:example:wallet#key-1", header["kid"])
	}
	if _, ok := header["jwk"]; ok {
		t.Errorf("jwk header present, want absent")
	}

	var body struct {
		Aud   string `json:"aud"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body.Aud != "https://issuer.example.com" {
		t.Errorf("aud = %q", body.Aud)
	}
	if body.Nonce != "test-nonce" {
		t.Errorf("nonce = %q", body.Nonce)
	}
}

func TestGenerateProofWithKeyID_RejectsEmptyKeyID(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.GenerateProofWithKeyID(testP256Key(t), "", "https://issuer.example.com", ""); err == nil {
		t.Fatalf("GenerateProofWithKeyID = nil error, want error")
	}
}

func TestGenerateProofWithX5C(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)

	proof, err := w.GenerateProofWithX5C(key, []string{"AAAA", "BBBB"}, "https://issuer.example.com", "")
	if err != nil {
		t.Fatalf("GenerateProofWithX5C: %v", err)
	}

	header, _, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 2 || x5c[0] != "AAAA" || x5c[1] != "BBBB" {
		t.Errorf("x5c = %v, want [AAAA BBBB]", header["x5c"])
	}
	if _, ok := header["jwk"]; ok {
		t.Errorf("jwk header present, want absent")
	}
}

func TestGenerateProofWithX5C_RejectsEmptyChain(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.GenerateProofWithX5C(testP256Key(t), nil, "https://issuer.example.com", ""); err == nil {
		t.Fatalf("GenerateProofWithX5C = nil error, want error")
	}
}

func TestGenerateProofWithKeyAttestation(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)

	proof, err := w.GenerateProofWithKeyAttestation(key, "https://issuer.example.com", "test-nonce", "fake.key.attestation")
	if err != nil {
		t.Fatalf("GenerateProofWithKeyAttestation: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if header["typ"] != "openid4vci-proof+jwt" {
		t.Errorf("typ = %v, want openid4vci-proof+jwt", header["typ"])
	}
	if _, ok := header["jwk"]; !ok {
		t.Errorf("jwk header is missing")
	}
	if header["key_attestation"] != "fake.key.attestation" {
		t.Errorf("key_attestation = %v, want fake.key.attestation", header["key_attestation"])
	}

	var body struct {
		Aud   string `json:"aud"`
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body.Aud != "https://issuer.example.com" {
		t.Errorf("aud = %q", body.Aud)
	}
	if body.Nonce != "test-nonce" {
		t.Errorf("nonce = %q", body.Nonce)
	}
}

func TestGenerateProofWithKeyAttestation_RejectsEmptyAttestation(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.GenerateProofWithKeyAttestation(testP256Key(t), "https://issuer.example.com", "", ""); err == nil {
		t.Fatalf("GenerateProofWithKeyAttestation = nil error, want error")
	}
}

func TestGenerateProof_OmitsNonceWhenEmpty(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)

	proof, err := w.GenerateProof(key, "https://issuer.example.com", "")
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}
	_, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, ok := body["nonce"]; ok {
		t.Errorf("nonce claim present, want omitted")
	}
}

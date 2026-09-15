package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/wallet"
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

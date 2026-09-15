package wallet_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func TestGenerateDPoPProof(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	deps := validDependencies()
	deps.Clock = fixedClock{now: now}
	w, err := wallet.New(validConfig(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	key := testP256Key(t)
	proof, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if header["typ"] != "dpop+jwt" {
		t.Errorf("typ = %v, want dpop+jwt", header["typ"])
	}
	if _, ok := header["jwk"]; !ok {
		t.Errorf("jwk header is missing")
	}

	var body struct {
		JTI string `json:"jti"`
		HTM string `json:"htm"`
		HTU string `json:"htu"`
		IAT int64  `json:"iat"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body.JTI == "" {
		t.Errorf("jti is empty")
	}
	if body.HTM != "POST" {
		t.Errorf("htm = %q, want POST", body.HTM)
	}
	if body.HTU != "https://issuer.example.com/token" {
		t.Errorf("htu = %q", body.HTU)
	}
	if body.IAT != now.Unix() {
		t.Errorf("iat = %d, want %d", body.IAT, now.Unix())
	}
	if _, ok := header["ath"]; ok {
		t.Errorf("ath header present, want absent")
	}
}

func TestGenerateDPoPProof_IncludesNonceAndAthWhenGiven(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)
	ath := wallet.DPoPAccessTokenHash("access-token-value")
	proof, err := w.GenerateDPoPProof(key, "GET", "https://issuer.example.com/credential", "server-nonce", ath)
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}

	_, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var body struct {
		Nonce string `json:"nonce"`
		Ath   string `json:"ath"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if body.Nonce != "server-nonce" {
		t.Errorf("nonce = %q, want server-nonce", body.Nonce)
	}
	if body.Ath != ath {
		t.Errorf("ath = %q, want %q", body.Ath, ath)
	}
}

func TestGenerateDPoPProof_ProducesDistinctJTIsPerCall(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)
	proof1, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	proof2, err := w.GenerateDPoPProof(key, "POST", "https://issuer.example.com/token", "", "")
	if err != nil {
		t.Fatalf("GenerateDPoPProof: %v", err)
	}
	if proof1 == proof2 {
		t.Fatalf("two proofs are identical, want distinct jti per call")
	}
}

func TestGenerateDPoPProof_RequiresRandom(t *testing.T) {
	deps := validDependencies()
	deps.Random = nil
	w, err := wallet.New(validConfig(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := w.GenerateDPoPProof(testP256Key(t), "POST", "https://issuer.example.com/token", "", ""); err == nil {
		t.Fatalf("GenerateDPoPProof = nil error, want error")
	}
}

func TestDPoPAccessTokenHash(t *testing.T) {
	// RFC 9449 §4.3's own example.
	got := wallet.DPoPAccessTokenHash("Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU")
	want := "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
	if got != want {
		t.Errorf("DPoPAccessTokenHash = %q, want %q", got, want)
	}
}

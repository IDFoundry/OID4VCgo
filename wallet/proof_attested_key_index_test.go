package wallet_test

import (
	"crypto/ecdsa"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// keyAttestationOf is a Key Attestation JWT attesting keys, signed by
// a key of its own; GenerateProofWithAttestedKeyIndex reads it without
// verifying it.
func keyAttestationOf(t *testing.T, keys ...*ecdsa.PrivateKey) string {
	t.Helper()
	attested := make([]jwk.JWK, 0, len(keys))
	for _, k := range keys {
		pub, err := jwk.Marshal(&k.PublicKey)
		if err != nil {
			t.Fatalf("marshal jwk: %v", err)
		}
		attested = append(attested, pub)
	}
	payload, err := json.Marshal(map[string]any{"iat": 1_700_000_000, "exp": 1_700_000_600, "attested_keys": attested})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	compact, err := jose.Sign(jose.ES256, testP256Key(t), map[string]any{"typ": "key-attestation+jwt"}, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return compact
}

func TestGenerateProofWithAttestedKeyIndex(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, second := testP256Key(t), testP256Key(t)
	ka := keyAttestationOf(t, first, second)

	for index, key := range []*ecdsa.PrivateKey{first, second} {
		proof, err := w.GenerateProofWithAttestedKeyIndex(key, "https://issuer.example.com", "test-nonce", ka, index)
		if err != nil {
			t.Fatalf("GenerateProofWithAttestedKeyIndex(%d): %v", index, err)
		}
		header, payload, err := jose.Verify(jose.ES256, &key.PublicKey, proof)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if want := []string{"0", "1"}[index]; header["kid"] != want {
			t.Errorf("kid = %v, want %q", header["kid"], want)
		}
		if _, ok := header["jwk"]; ok {
			t.Errorf("jwk header present, want absent (Appendix F.1: not beside kid)")
		}
		if header["key_attestation"] != ka || header["typ"] != "openid4vci-proof+jwt" {
			t.Errorf("header = %v", header)
		}
		var body struct {
			Aud   string `json:"aud"`
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(payload, &body); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if body.Aud != "https://issuer.example.com" || body.Nonce != "test-nonce" {
			t.Errorf("body = %+v", body)
		}
	}
}

func TestGenerateProofWithAttestedKeyIndex_Refuses(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, second := testP256Key(t), testP256Key(t)
	ka := keyAttestationOf(t, first, second)
	for name, tc := range map[string]struct {
		ka    string
		index int
	}{
		"no attestation":      {"", 0},
		"not a JWT":           {"fake.key.attestation", 0},
		"another key's index": {ka, 1},
		"negative index":      {ka, -1},
		"index past the end":  {ka, 2},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := w.GenerateProofWithAttestedKeyIndex(first, "https://issuer.example.com", "", tc.ka, tc.index); err == nil {
				t.Fatalf("GenerateProofWithAttestedKeyIndex = nil error, want error")
			}
		})
	}
}

package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// A Proof stands for its key: the COSE_Sign1 it proves verifies again
// without a signature check, and any other COSE_Sign1, external AAD or
// algorithm is checked under the key it proves, never accepted on its
// strength. For hands it over only for an equal key.
func TestProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(signer *ecdsa.PrivateKey, payload string) []byte {
		sign1, err := Sign(ES256, signer, Headers{Alg: ES256}, Headers{}, []byte(payload), nil)
		if err != nil {
			t.Fatal(err)
		}
		return sign1
	}
	sign1 := sign(key, "one")
	if _, err := VerifyProof(ES256, &other.PublicKey, sign1, nil); err == nil {
		t.Fatal("VerifyProof proved a signature by another key")
	}
	proof, err := VerifyProof(ES256, &key.PublicKey, sign1, nil)
	if err != nil {
		t.Fatal(err)
	}

	before := Checks()
	if _, _, payload, err := Verify(ES256, proof, sign1, nil); err != nil || string(payload) != "one" {
		t.Fatalf("Verify with the proof: %q, %v", payload, err)
	}
	if n := Checks() - before; n != 0 {
		t.Errorf("the proved COSE_Sign1 was checked again (%d checks)", n)
	}

	for name, c := range map[string]struct {
		sign1   []byte
		aad     []byte
		wantErr bool
	}{
		"another payload by the key":     {sign(key, "two"), nil, false},
		"another payload by another key": {sign(other, "one"), nil, true},
		"the proved one, other AAD":      {sign1, []byte("aad"), true},
		"the proved one, as a control":   {sign1, nil, false},
	} {
		if _, _, _, err := Verify(ES256, proof, c.sign1, c.aad); (err != nil) != c.wantErr {
			t.Errorf("%s: Verify = %v, want error %v", name, err, c.wantErr)
		}
	}

	if proof.For(&other.PublicKey, ES256) != &other.PublicKey {
		t.Error("For handed the proof over for another key")
	}
	if proof.For(&key.PublicKey, ES384) != &key.PublicKey {
		t.Error("For handed the proof over for another algorithm")
	}
	if proof.For(&key.PublicKey, ES256) != proof {
		t.Error("For didn't hand the proof over for its own key")
	}
	var none *Proof
	if none.For(&key.PublicKey, ES256) != &key.PublicKey {
		t.Error("a nil proof's For isn't the key")
	}
	if _, _, _, err := Verify(ES256, none, sign1, nil); err == nil {
		t.Error("a nil proof verified")
	}
}

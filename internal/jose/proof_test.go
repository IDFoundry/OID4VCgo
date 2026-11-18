package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// A Proof stands for its key: the JWS it proves verifies again without a
// signature check, and any other JWS, signature or algorithm is checked
// under the key it proves, never accepted on its strength. For hands it
// over only for an equal key.
func TestProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(signer *ecdsa.PrivateKey, payload string) string {
		jws, err := Sign(ES256, signer, map[string]any{"typ": "test"}, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		return jws
	}
	jws := sign(key, "one")
	if _, err := VerifyProof(ES256, &other.PublicKey, jws); err == nil {
		t.Fatal("VerifyProof proved a signature by another key")
	}
	proof, err := VerifyProof(ES256, &key.PublicKey, jws)
	if err != nil {
		t.Fatal(err)
	}

	before := Checks()
	if _, payload, err := Verify(ES256, proof, jws); err != nil || string(payload) != "one" {
		t.Fatalf("Verify with the proof: %q, %v", payload, err)
	}
	if n := Checks() - before; n != 0 {
		t.Errorf("the proved JWS was checked again (%d checks)", n)
	}

	forged := jws[:len(jws)-4] + "AAAA"
	for name, c := range map[string]struct {
		jws     string
		wantErr bool
	}{
		"another JWS by the key":       {sign(key, "two"), false},
		"another JWS by another key":   {sign(other, "one"), true},
		"the same input, another sig":  {forged, true},
		"another signature encoding":   {sign(key, "one"), false},
		"the proved one, as a control": {jws, false},
	} {
		if _, _, err := Verify(ES256, proof, c.jws); (err != nil) != c.wantErr {
			t.Errorf("%s: Verify = %v, want error %v", name, err, c.wantErr)
		}
	}
	if _, _, err := Verify(EdDSA, proof, jws); err == nil {
		t.Error("the proof was accepted for another algorithm")
	}

	if got := proof.For(&other.PublicKey, ES256); got != &other.PublicKey {
		t.Error("For handed the proof over for another key")
	}
	if got := proof.For(&key.PublicKey, ES384); got != &key.PublicKey {
		t.Error("For handed the proof over for another algorithm")
	}
	if got := proof.For(&key.PublicKey, ES256); got != proof {
		t.Error("For didn't hand the proof over for its own key")
	}
	var none *Proof
	if got := none.For(&key.PublicKey, ES256); got != &key.PublicKey {
		t.Error("a nil proof's For isn't the key")
	}
	if _, _, err := Verify(ES256, none, jws); err == nil {
		t.Error("a nil proof verified")
	}
}

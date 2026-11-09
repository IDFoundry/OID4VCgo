package cose

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// An EdDSA COSE_Sign1 whose signature doesn't verify is refused: a
// signature from another key, a changed signature, the wrong external
// AAD, or the wrong detached payload.
func TestVerifyRefusesBadEdDSASignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, aad := []byte(`{"a":1}`), []byte("aad")
	sign1, err := Sign(EdDSA, priv, Headers{}, Headers{}, payload, aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Verify(EdDSA, pub, sign1, aad); err != nil {
		t.Fatalf("the untampered COSE_Sign1: %v", err)
	}
	// The signature is the last element, a 64-byte bstr.
	tampered := append([]byte{}, sign1...)
	tampered[len(tampered)-1] ^= 1

	for name, tc := range map[string]struct {
		pub   ed25519.PublicKey
		sign1 []byte
		aad   []byte
	}{
		"another key":       {otherPub, sign1, aad},
		"changed signature": {pub, tampered, aad},
		"other AAD":         {pub, sign1, []byte("other")},
	} {
		_, _, _, err := Verify(EdDSA, tc.pub, tc.sign1, tc.aad)
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("%s: Verify = %v, want a signature verification failure", name, err)
		}
	}

	detached, err := SignDetached(EdDSA, priv, Headers{}, Headers{}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyDetached(EdDSA, pub, detached, payload, nil); err != nil {
		t.Fatalf("the untampered detached COSE_Sign1: %v", err)
	}
	_, _, err = VerifyDetached(EdDSA, pub, detached, []byte(`{"a":2}`), nil)
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Errorf("other detached payload: VerifyDetached = %v, want a signature verification failure", err)
	}
}

package ecdsafixed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := key.Sign(rand.Reader, []byte("digest-sized-input-000000000000"), nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	fixed, err := ToFixed(der, 32)
	if err != nil {
		t.Fatalf("ToFixed: %v", err)
	}
	if len(fixed) != 64 {
		t.Fatalf("len(fixed) = %d, want 64", len(fixed))
	}

	roundTripped, err := ToDER(fixed, 32)
	if err != nil {
		t.Fatalf("ToDER: %v", err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, []byte("digest-sized-input-000000000000"), roundTripped) {
		t.Errorf("round-tripped signature failed to verify")
	}
}

func TestToFixedRejectsMalformedDER(t *testing.T) {
	if _, err := ToFixed([]byte("not der"), 32); err == nil {
		t.Errorf("ToFixed accepted malformed DER")
	}
}

func TestToDERRejectsWrongLength(t *testing.T) {
	if _, err := ToDER(make([]byte, 10), 32); err == nil {
		t.Errorf("ToDER accepted a signature of the wrong length")
	}
}

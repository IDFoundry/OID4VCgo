package cose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

// A header label in both the protected and the unprotected bucket is
// refused (RFC 9052 §3), by Verify, DecodeUnverified and VerifyMAC
// alike: a reader taking the unprotected value would read one nobody
// signed. One label in each bucket is fine.
func TestHeaderLabelInBothBuckets(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	ok, err := Sign(ES256, key, Headers{KID: []byte("a")}, Headers{X5Chain: [][]byte{{1}}}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Verify(ES256, &key.PublicKey, ok, nil); err != nil {
		t.Fatalf("Verify refused distinct labels: %v", err)
	}
	for name, h := range map[string][2]Headers{
		"kid":     {{KID: []byte("a")}, {KID: []byte("b")}},
		"x5chain": {{X5Chain: [][]byte{{1}}}, {X5Chain: [][]byte{{2}}}},
	} {
		sign1, err := Sign(ES256, key, h[0], h[1], payload, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := Verify(ES256, &key.PublicKey, sign1, nil); err == nil || !strings.Contains(err.Error(), "both") {
			t.Errorf("%s: Verify = %v, want a refusal", name, err)
		}
		if _, _, _, err := DecodeUnverified(sign1); err == nil {
			t.Errorf("%s: DecodeUnverified accepted it", name)
		}
	}
	macKey := []byte("a shared 32-byte HMAC key!!!!!!")
	mac0, err := ComputeMAC(macKey, Headers{KID: []byte("a")}, Headers{KID: []byte("b")}, payload, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyMAC(macKey, mac0, payload, nil); err == nil || !strings.Contains(err.Error(), "both") {
		t.Errorf("VerifyMAC = %v, want a refusal", err)
	}
}

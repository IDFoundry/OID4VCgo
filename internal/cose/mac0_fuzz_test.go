package cose

import (
	"crypto/rand"
	"testing"
)

// FuzzVerifyMAC exercises VerifyMAC against arbitrary bytes — mirrors
// FuzzDecodeUnverified's attacker model for the MAC0 structure mdoc's
// DeviceSigned uses when a device authenticates via a shared key
// instead of a signature.
func FuzzVerifyMAC(f *testing.F) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := ComputeMAC(key, Headers{KID: []byte("fuzz-kid")}, Headers{}, []byte("hi"), nil)
	if err != nil {
		f.Fatalf("compute mac: %v", err)
	}

	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0x84})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, mac0 []byte) {
		_, _, _ = VerifyMAC(key, mac0, []byte("hi"), nil)
	})
}

package appattest

import (
	"crypto/elliptic"
	"errors"
	"testing"
)

// FuzzVerifyAttestation: any attestation object verifies or is refused
// with one of the package's errors, without panicking; one that
// verifies is over the client data hash it was checked against.
func FuzzVerifyAttestation(f *testing.F) {
	apple := newFakeApple(f)
	hash := hashOf("client data")
	good, _ := apple.attest(f, attSpec{clientDataHash: hash})
	f.Add(good)
	dev, _ := apple.attest(f, attSpec{clientDataHash: hash, aaguid: aaguidDevelopment})
	f.Add(dev)
	f.Add([]byte{0xa0})
	v := apple.verifier()
	v.AllowDevelopment = true
	f.Fuzz(func(t *testing.T, obj []byte) {
		att, err := v.VerifyAttestation(obj, hash)
		if err != nil {
			if !isPackageError(err) {
				t.Errorf("error %v wraps none of the package's", err)
			}
			return
		}
		if att.PublicKey == nil || att.AppID != testAppID || len(att.KeyID) != 32 {
			t.Errorf("verified %+v", att)
		}
	})
}

// FuzzVerifyAssertion: any assertion verifies or is refused with one of
// the package's errors, without panicking.
func FuzzVerifyAssertion(f *testing.F) {
	apple := newFakeApple(f)
	key := newKey(f, elliptic.P256())
	hash := hashOf("client data")
	f.Add(assert(f, key, testAppID, 1, hash))
	f.Add([]byte{0xa2, 0x60, 0x40, 0x61, 0x61, 0x40})
	v := apple.verifier()
	f.Fuzz(func(t *testing.T, obj []byte) {
		a, err := v.VerifyAssertion(obj, hash, &key.PublicKey, 0)
		if err != nil {
			if !isPackageError(err) {
				t.Errorf("error %v wraps none of the package's", err)
			}
			return
		}
		if a.Counter == 0 || a.AppID != testAppID {
			t.Errorf("verified %+v", a)
		}
	})
}

func isPackageError(err error) bool {
	for _, kind := range []error{ErrConfig, ErrMalformed, ErrUntrustedRoot, ErrNonce, ErrKeyID, ErrAppNotAllowed, ErrEnvironment, ErrCounter, ErrSignature} {
		if errors.Is(err, kind) {
			return true
		}
	}
	return false
}

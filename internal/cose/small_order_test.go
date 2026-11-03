package cose

import (
	"crypto"
	"crypto/ed25519"
	"io"
	"strings"
	"testing"
)

// forgingSigner "signs" with Ed25519's identity point as its key: the
// signature R = identity, S = 0 verifies under that key for any
// message, without any private key.
type forgingSigner struct{}

func identityKey() ed25519.PublicKey {
	return append(ed25519.PublicKey{1}, make([]byte, 31)...)
}

func (forgingSigner) Public() crypto.PublicKey { return identityKey() }

func (forgingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return append(append([]byte{1}, make([]byte, 31)...), make([]byte, 32)...), nil
}

func TestVerifyRefusesSmallOrderEd25519Key(t *testing.T) {
	sign1, err := Sign(EdDSA, forgingSigner{}, Headers{}, Headers{}, []byte("any message"), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = Verify(EdDSA, identityKey(), sign1, nil)
	if err == nil || !strings.Contains(err.Error(), "small order") {
		t.Fatalf("Verify = %v, want a small-order refusal", err)
	}
}

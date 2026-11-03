package jose

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
	compact, err := Sign(EdDSA, forgingSigner{}, map[string]any{"typ": "test+jwt"}, []byte(`{"any":"message"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(identityKey(), []byte("anything at all"), mustSig(t, compact)) {
		t.Fatal("the forgery doesn't verify under crypto/ed25519: the test proves nothing")
	}
	_, _, err = Verify(EdDSA, identityKey(), compact)
	if err == nil || !strings.Contains(err.Error(), "small order") {
		t.Fatalf("Verify = %v, want a small-order refusal", err)
	}
}

func mustSig(t *testing.T, compact string) []byte {
	t.Helper()
	parts := strings.Split(compact, ".")
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

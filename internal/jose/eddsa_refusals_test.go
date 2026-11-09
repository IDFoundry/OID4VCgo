package jose

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
)

// An EdDSA JWS whose signature doesn't verify is refused: a signature
// from another key, a changed payload or header, or a changed
// signature.
func TestVerifyRefusesBadEdDSASignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := Sign(EdDSA, priv, map[string]any{"typ": "test+jwt"}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(EdDSA, pub, compact); err != nil {
		t.Fatalf("the untampered JWS: %v", err)
	}
	parts := strings.Split(compact, ".")
	other, err := Sign(EdDSA, priv, map[string]any{"typ": "other+jwt"}, []byte(`{"a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	otherParts := strings.Split(other, ".")
	sig := mustSig(t, compact)
	sig[0] ^= 1

	for name, tc := range map[string]struct {
		pub     ed25519.PublicKey
		compact string
	}{
		"another key":       {otherPub, compact},
		"changed payload":   {pub, parts[0] + "." + otherParts[1] + "." + parts[2]},
		"changed header":    {pub, otherParts[0] + "." + parts[1] + "." + parts[2]},
		"changed signature": {pub, parts[0] + "." + parts[1] + "." + b64.EncodeToString(sig)},
	} {
		_, _, err := Verify(EdDSA, tc.pub, tc.compact)
		if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
			t.Errorf("%s: Verify = %v, want a signature verification failure", name, err)
		}
	}
}

// The header's "alg" must be the one the caller expects, even when the
// signature verifies under that algorithm: a JWS signed with EdDSA
// whose header names another algorithm, or none, is refused.
func TestVerifyRefusesHeaderAlgOtherThanExpected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{
		`{"alg":"ES256"}`,
		`{"alg":"none"}`,
		`{"alg":"eddsa"}`,
		`{"typ":"test+jwt"}`,
	} {
		compact := signRaw(t, EdDSA, priv, header, []byte(`{}`))
		_, _, err := Verify(EdDSA, pub, compact)
		if err == nil || !strings.Contains(err.Error(), "does not match expected") {
			t.Errorf("%s: Verify = %v, want a header alg refusal", header, err)
		}
	}
	if _, _, err := Verify(EdDSA, pub, signRaw(t, EdDSA, priv, `{"alg":"EdDSA"}`, []byte(`{}`))); err != nil {
		t.Errorf(`the same JWS with {"alg":"EdDSA"}: %v`, err)
	}
}

// signRaw signs payload with alg under a header given as raw JSON,
// which Sign, always setting "alg" itself, can't express.
func signRaw(t *testing.T, alg Alg, signer crypto.Signer, header string, payload []byte) string {
	t.Helper()
	signingInput := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(payload)
	sig, err := signBytes(alg, signer, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64.EncodeToString(sig)
}

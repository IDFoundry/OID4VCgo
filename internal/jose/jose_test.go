package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignVerifyES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := Sign(ES256, key, map[string]any{"typ": "test+jwt"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	header, got, err := Verify(ES256, &key.PublicKey, compact)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
	if header["typ"] != "test+jwt" {
		t.Errorf("typ header = %v, want test+jwt", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Errorf("alg header = %v, want ES256", header["alg"])
	}
}

func TestSignVerifyEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := Sign(EdDSA, priv, nil, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, got, err := Verify(EdDSA, pub, compact)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Flip a character early in the signature segment, not the last
	// one: a fixed-width R||S signature's final base64url character
	// can carry unused padding bits (64 bytes % 3 == 1, so the last
	// char only encodes the top 2 of its 6 bits), so changing only
	// that character can legally decode to the same bytes and this
	// test would pass for the wrong reason.
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts, want 3", len(parts))
	}
	sig := []rune(parts[2])
	if sig[0] == 'x' {
		sig[0] = 'y'
	} else {
		sig[0] = 'x'
	}
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")
	if tampered == compact {
		t.Fatalf("tamper produced identical string")
	}
	if _, _, err := Verify(ES256, &key.PublicKey, tampered); err == nil {
		t.Errorf("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key1, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := Verify(ES256, &key2.PublicKey, compact); err == nil {
		t.Errorf("Verify accepted a signature under the wrong key")
	}
}

func TestVerifyRejectsAlgMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := Verify(EdDSA, &key.PublicKey, compact); err == nil {
		t.Errorf("Verify accepted a JWS whose header alg does not match the requested alg")
	}
}

func TestDecodeUnverified(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{"kid": "k1"}, []byte(`{"iss":"issuer"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	header, payload, err := DecodeUnverified(compact)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	if header["kid"] != "k1" {
		t.Errorf("kid = %v, want k1", header["kid"])
	}
	if string(payload) != `{"iss":"issuer"}` {
		t.Errorf("payload = %s", payload)
	}
}

func TestVerifyRejectsOversizedCompact(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, nil, make([]byte, MaxCompactBytes))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(compact) <= MaxCompactBytes {
		t.Fatalf("compact is %d bytes, want > MaxCompactBytes (%d)", len(compact), MaxCompactBytes)
	}

	if _, _, err := Verify(ES256, &key.PublicKey, compact); err == nil {
		t.Error("Verify = nil error, want error (oversized compact JWS)")
	}
	if _, _, err := DecodeUnverified(compact); err == nil {
		t.Error("DecodeUnverified = nil error, want error (oversized compact JWS)")
	}

	// VerifyMax/DecodeUnverifiedMax with a raised ceiling accept the
	// same input Verify/DecodeUnverified reject.
	if _, _, err := VerifyMax(ES256, &key.PublicKey, compact, len(compact)); err != nil {
		t.Errorf("VerifyMax with a raised ceiling: %v", err)
	}
	if _, _, err := DecodeUnverifiedMax(compact, len(compact)); err != nil {
		t.Errorf("DecodeUnverifiedMax with a raised ceiling: %v", err)
	}
}

func TestVerifyRejectsCriticalExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{"crit": []string{"exp"}, "exp": 1}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, _, err := Verify(ES256, &key.PublicKey, compact); err == nil {
		t.Error("Verify = nil error, want error (unrecognized crit extension)")
	}
	if _, _, err := DecodeUnverified(compact); err == nil {
		t.Error("DecodeUnverified = nil error, want error (unrecognized crit extension)")
	}
}

// A signature segment whose unused trailing bits aren't zero decodes to
// the same signature under a lenient decoder, which would give one JWS
// a second serialization: it's refused.
func TestVerifyRejectsNonCanonicalBase64(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// A 64-byte ES256 signature is 86 characters: the last carries 4
	// unused bits.
	last := strings.IndexByte(alphabet, compact[len(compact)-1])
	variant := compact[:len(compact)-1] + string(alphabet[last|1])
	if _, _, err := Verify(ES256, &key.PublicKey, variant); err == nil {
		t.Error("Verify accepted a non-canonical signature encoding")
	}
}

// A line break in any segment is refused (RFC 7515 §2): encoding/base64
// skips it, and the signing input doesn't cover the signature segment,
// so it would give one JWS any number of serializations that verify.
func TestVerifyRejectsLineBreakInSegment(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{}, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	parts := strings.Split(compact, ".")
	for i := range parts {
		for _, brk := range []string{"\r\n", "\n", "\r"} {
			mutated := append([]string(nil), parts...)
			mutated[i] = mutated[i][:4] + brk + mutated[i][4:]
			variant := strings.Join(mutated, ".")
			if _, _, err := Verify(ES256, &key.PublicKey, variant); err == nil {
				t.Errorf("Verify accepted %q in segment %d", brk, i)
			}
			if i < 2 {
				if _, _, err := DecodeUnverified(variant); err == nil {
					t.Errorf("DecodeUnverified accepted %q in segment %d", brk, i)
				}
			}
		}
	}
}

// RFC 7515 §4.1.11: "Producers MUST NOT use the empty list".
func TestVerifyRejectsEmptyCrit(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{"crit": []string{}}, []byte(`{}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, _, err := Verify(ES256, &key.PublicKey, compact); err == nil {
		t.Error("Verify = nil error, want error (empty crit)")
	}
}

// signRawHeader signs payload under a header given as raw JSON, which
// Sign, taking a map, can't express when a member appears twice.
func signRawHeader(t *testing.T, key *ecdsa.PrivateKey, header string, payload []byte) string {
	t.Helper()
	signingInput := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(payload)
	sig, err := signBytes(ES256, key, []byte(signingInput))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + b64.EncodeToString(sig)
}

// RFC 7515 §4: a JWS with a Header Parameter named twice is rejected,
// not read last-wins — {"crit":["exp"],"crit":[]} isn't a JWS without
// a critical extension.
func TestVerifyRejectsDuplicateHeaderParameters(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	for _, header := range []string{
		`{"alg":"ES256","crit":["exp"],"exp":1,"crit":[]}`,
		`{"alg":"ES256","typ":"a","typ":"b"}`,
		`{"alg":"ES256","jwk":{"kty":"EC","kty":"OKP"}}`,
	} {
		compact := signRawHeader(t, key, header, []byte(`{}`))
		if _, _, err := Verify(ES256, &key.PublicKey, compact); err == nil {
			t.Errorf("%s: Verify = nil error, want error", header)
		}
		if _, _, err := DecodeUnverified(compact); err == nil {
			t.Errorf("%s: DecodeUnverified = nil error, want error", header)
		}
	}
	if _, _, err := Verify(ES256, &key.PublicKey, signRawHeader(t, key, `{"alg":"ES256","typ":"a"}`, []byte(`{}`))); err != nil {
		t.Errorf("the same header without the duplicate: %v", err)
	}
}

func TestIsSupported(t *testing.T) {
	cases := map[Alg]bool{ES256: true, EdDSA: true, "": false, "RS256": false, "es256": false}
	for alg, want := range cases {
		if got := IsSupported(alg); got != want {
			t.Errorf("IsSupported(%q) = %v, want %v", alg, got, want)
		}
	}
}

// An Ed25519 key of the wrong length is an error, not ed25519.Verify's
// panic.
func TestVerifyRefusesShortEd25519Key(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := Sign(EdDSA, priv, map[string]any{"typ": "test+jwt"}, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(EdDSA, pub[:31], compact); err == nil {
		t.Error("a 31-byte Ed25519 key verified")
	}
}

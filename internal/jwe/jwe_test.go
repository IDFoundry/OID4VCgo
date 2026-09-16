package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, enc := range []Enc{A128GCM, A192GCM, A256GCM} {
		t.Run(string(enc), func(t *testing.T) {
			key := testP256Key(t)
			payload := []byte(`{"hello":"world","n":42}`)

			compact, err := Encrypt(&key.PublicKey, enc, payload, EncryptOptions{KeyID: "test-kid"})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			got, err := Decrypt(key, compact)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			if string(got) != string(payload) {
				t.Errorf("payload = %s, want %s", got, payload)
			}
		})
	}
}

func TestEncryptDecryptRoundTrip_Zip(t *testing.T) {
	key := testP256Key(t)
	payload := []byte(strings.Repeat("compress me please ", 50))

	compact, err := Encrypt(&key.PublicKey, A128GCM, payload, EncryptOptions{Zip: DEF})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(key, compact)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload mismatch after zip round-trip")
	}
}

func TestEncryptHeaderFields(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A256GCM, []byte("hi"), EncryptOptions{KeyID: "kid-1", Zip: DEF})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	header, err := DecodeHeader(compact)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if header["alg"] != string(ECDHES) {
		t.Errorf("alg = %v, want %v", header["alg"], ECDHES)
	}
	if header["enc"] != string(A256GCM) {
		t.Errorf("enc = %v, want %v", header["enc"], A256GCM)
	}
	if header["kid"] != "kid-1" {
		t.Errorf("kid = %v, want kid-1", header["kid"])
	}
	if header["zip"] != string(DEF) {
		t.Errorf("zip = %v, want %v", header["zip"], DEF)
	}
	if _, ok := header["epk"]; !ok {
		t.Errorf("epk header is missing")
	}
}

func TestEncryptOmitsKidAndZipWhenUnset(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	header, err := DecodeHeader(compact)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if _, ok := header["kid"]; ok {
		t.Errorf("kid header present, want absent")
	}
	if _, ok := header["zip"]; ok {
		t.Errorf("zip header present, want absent")
	}
}

func TestEncryptedKeySegmentIsEmpty(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("got %d parts, want 5", len(parts))
	}
	if parts[1] != "" {
		t.Errorf("encrypted key segment = %q, want empty (ECDH-ES direct key agreement)", parts[1])
	}
}

func TestDecryptRejectsWrongRecipientKey(t *testing.T) {
	recipient := testP256Key(t)
	attacker := testP256Key(t)
	compact, err := Encrypt(&recipient.PublicKey, A128GCM, []byte("secret"), EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(attacker, compact); err == nil {
		t.Fatalf("Decrypt with wrong key = nil error, want error")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("secret"), EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(compact, ".")
	ct, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	ct[0] ^= 0xFF
	parts[3] = base64.RawURLEncoding.EncodeToString(ct)
	tampered := strings.Join(parts, ".")

	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatalf("Decrypt of tampered ciphertext = nil error, want error")
	}
}

// tamperHeader rewrites compact's own header segment after applying
// mutate to its decoded form, leaving every other segment untouched —
// shared by every test that needs a JWE whose header no longer matches
// the one AES-GCM originally authenticated as AAD.
func tamperHeader(t *testing.T, compact string, mutate func(map[string]any)) string {
	t.Helper()
	header, err := DecodeHeader(compact)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	mutate(header)
	rawHeader, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	parts := strings.Split(compact, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString(rawHeader)
	return strings.Join(parts, ".")
}

func TestDecryptRejectsTamperedHeader(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("secret"), EncryptOptions{KeyID: "k1"})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := tamperHeader(t, compact, func(h map[string]any) { h["kid"] = "attacker-controlled" })

	// The header is the GCM AAD, so changing it (even a field GCM
	// doesn't otherwise interpret) must invalidate the tag.
	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatalf("Decrypt of tampered header = nil error, want error")
	}
}

func TestDecryptRejectsMalformedCompact(t *testing.T) {
	key := testP256Key(t)
	cases := map[string]string{
		"too few parts":  "a.b.c.d",
		"too many parts": "a.b.c.d.e.f",
		"non-empty second segment": func() string {
			key2 := testP256Key(t)
			compact, err := Encrypt(&key2.PublicKey, A128GCM, []byte("hi"), EncryptOptions{})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			parts := strings.Split(compact, ".")
			parts[1] = "not-empty"
			return strings.Join(parts, ".")
		}(),
	}
	for name, compact := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(key, compact); err == nil {
				t.Fatalf("Decrypt(%q) = nil error, want error", name)
			}
		})
	}
}

func TestDecryptRejectsUnsupportedAlg(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	tampered := tamperHeader(t, compact, func(h map[string]any) { h["alg"] = "RSA-OAEP" })

	if _, err := Decrypt(key, tampered); err == nil {
		t.Fatalf("Decrypt with unsupported alg = nil error, want error")
	}
}

func TestEncryptRejectsUnsupportedZip(t *testing.T) {
	key := testP256Key(t)
	if _, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{Zip: "GZIP"}); err == nil {
		t.Fatalf("Encrypt with unsupported zip = nil error, want error")
	}
}

func TestDecodeHeaderDoesNotRequireAPrivateKey(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{KeyID: "k1"})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	header, err := DecodeHeader(compact)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if header["kid"] != "k1" {
		t.Errorf("kid = %v, want k1", header["kid"])
	}
}

func TestConcatKDFProducesRequestedLength(t *testing.T) {
	z := []byte("shared-secret-material")
	for _, keyLen := range []int{16, 24, 32} {
		out, err := concatKDF(z, "A128GCM", nil, nil, keyLen)
		if err != nil {
			t.Fatalf("concatKDF(%d): %v", keyLen, err)
		}
		if len(out) != keyLen {
			t.Errorf("len = %d, want %d", len(out), keyLen)
		}
	}
}

func TestConcatKDFIsDeterministic(t *testing.T) {
	z := []byte("shared-secret-material")
	a, err := concatKDF(z, "A128GCM", nil, nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	b, err := concatKDF(z, "A128GCM", nil, nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("concatKDF is not deterministic for identical inputs")
	}
}

func TestConcatKDFDependsOnEnc(t *testing.T) {
	z := []byte("shared-secret-material")
	a, err := concatKDF(z, "A128GCM", nil, nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	b, err := concatKDF(z, "A256GCM", nil, nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	if string(a) == string(b) {
		t.Errorf("concatKDF output does not depend on enc (AlgorithmID)")
	}
}

// TestConcatKDFDependsOnPartyInfo is the regression test for the real
// interop bug the OIDF conformance suite's own live direct_post.jwt
// responses surfaced: Decrypt used to silently treat every sender's
// apu/apv as absent, so a peer that actually sets them (as this suite
// always does) got a derived key that never matched — an opaque AEAD
// failure with no hint that apu/apv was the cause. Confirms apu/apv
// are actually mixed into the derived key, not just accepted and
// ignored.
func TestConcatKDFDependsOnPartyInfo(t *testing.T) {
	z := []byte("shared-secret-material")
	withoutParty, err := concatKDF(z, "A128GCM", nil, nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	withApu, err := concatKDF(z, "A128GCM", []byte("party-u"), nil, 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	withApv, err := concatKDF(z, "A128GCM", nil, []byte("party-v"), 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	withBoth, err := concatKDF(z, "A128GCM", []byte("party-u"), []byte("party-v"), 16)
	if err != nil {
		t.Fatalf("concatKDF: %v", err)
	}
	outputs := [][]byte{withoutParty, withApu, withApv, withBoth}
	for i := range outputs {
		for j := i + 1; j < len(outputs); j++ {
			if string(outputs[i]) == string(outputs[j]) {
				t.Errorf("concatKDF outputs %d and %d matched, want distinct apu/apv to change the derived key", i, j)
			}
		}
	}
}

func TestConcatKDFRejectsOversizedKeyLen(t *testing.T) {
	if _, err := concatKDF([]byte("z"), "A128GCM", nil, nil, 64); err == nil {
		t.Fatalf("concatKDF(64) = nil error, want error (exceeds one SHA-256 round)")
	}
}

func TestDecodePartyInfo_AbsentReturnsNil(t *testing.T) {
	got, err := decodePartyInfo(map[string]any{}, "apu")
	if err != nil {
		t.Fatalf("decodePartyInfo: %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil for an absent member", got)
	}
}

func TestDecodePartyInfo_DecodesPresentValue(t *testing.T) {
	// base64url("hello") == "aGVsbG8"
	got, err := decodePartyInfo(map[string]any{"apu": "aGVsbG8"}, "apu")
	if err != nil {
		t.Fatalf("decodePartyInfo: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestDecodePartyInfo_RejectsNonString(t *testing.T) {
	if _, err := decodePartyInfo(map[string]any{"apv": 42}, "apv"); err == nil {
		t.Fatalf("decodePartyInfo = nil error, want error for a non-string member")
	}
}

func TestDecodePartyInfo_RejectsInvalidBase64(t *testing.T) {
	if _, err := decodePartyInfo(map[string]any{"apv": "not valid base64url!"}, "apv"); err == nil {
		t.Fatalf("decodePartyInfo = nil error, want error for invalid base64url")
	}
}

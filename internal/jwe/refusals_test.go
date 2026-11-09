package jwe

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
)

// encryptWithHeader is Encrypt with A128GCM, its header changed by
// mutate before sealing: the result authenticates, so only Decrypt's
// own header checks can refuse it.
func encryptWithHeader(t *testing.T, recipientPub *ecdsa.PublicKey, payload []byte, mutate func(map[string]any)) string {
	t.Helper()
	recipientECDH, err := recipientPub.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	z, err := ephemeral.ECDH(recipientECDH)
	if err != nil {
		t.Fatal(err)
	}
	cek, err := concatKDF(z, string(A128GCM), nil, nil, 16)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{"alg": string(ECDHES), "enc": string(A128GCM), "epk": jwkFromECDHPublicKey(ephemeral.PublicKey())}
	mutate(header)
	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	encHeader := b64.EncodeToString(headerJSON)
	gcm, err := newGCM(cek)
	if err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, gcmIVSize)
	sealed := gcm.Seal(nil, iv, payload, []byte(encHeader))
	n := len(sealed) - gcmTagSize
	return strings.Join([]string{encHeader, "", b64.EncodeToString(iv), b64.EncodeToString(sealed[:n]), b64.EncodeToString(sealed[n:])}, ".")
}

// A JWE whose header names an algorithm other than ECDH-ES, or none, is
// refused even when it decrypts under ECDH-ES.
func TestDecryptRefusesAlgOtherThanECDHES(t *testing.T) {
	key := testP256Key(t)
	if got, err := Decrypt(key, encryptWithHeader(t, &key.PublicKey, []byte("hi"), func(map[string]any) {})); err != nil || string(got) != "hi" {
		t.Fatalf("the unchanged header: Decrypt = %q, %v", got, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"ECDH-ES+A128KW": func(h map[string]any) { h["alg"] = "ECDH-ES+A128KW" },
		"lower case":     func(h map[string]any) { h["alg"] = "ecdh-es" },
		"no alg":         func(h map[string]any) { delete(h, "alg") },
	} {
		_, err := Decrypt(key, encryptWithHeader(t, &key.PublicKey, []byte("hi"), mutate))
		if err == nil || !strings.Contains(err.Error(), "unsupported alg") {
			t.Errorf("%s: Decrypt = %v, want an unsupported alg refusal", name, err)
		}
	}
}

// An IV or tag of the wrong length is refused before AES-GCM sees it:
// crypto/cipher's Open panics on a nonce of the wrong size.
func TestDecryptRefusesWrongIVAndTagLengths(t *testing.T) {
	key := testP256Key(t)
	compact, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		segment, length int
		want            string
	}{
		{2, 0, "iv has unexpected length"},
		{2, 8, "iv has unexpected length"},
		{2, 16, "iv has unexpected length"},
		{4, 0, "tag has unexpected length"},
		{4, 12, "tag has unexpected length"},
		{4, 32, "tag has unexpected length"},
	} {
		parts := strings.Split(compact, ".")
		parts[tc.segment] = b64.EncodeToString(make([]byte, tc.length))
		_, err := Decrypt(key, strings.Join(parts, "."))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("segment %d of %d bytes: Decrypt = %v, want %q", tc.segment, tc.length, err, tc.want)
		}
	}
}

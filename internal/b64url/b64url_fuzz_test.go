package b64url

import (
	"bytes"
	"encoding/base64"
	"testing"
)

// FuzzDecodeString checks DecodeString on arbitrary strings: it accepts
// only the RFC 7515 §2 alphabet, with no padding, agrees with
// base64.RawURLEncoding.Strict() on every string of that alphabet, and
// what it decodes encodes back to the same string, so no value has two
// accepted encodings. Every byte slice round-trips through
// EncodeToString.
func FuzzDecodeString(f *testing.F) {
	for _, seed := range []string{
		"", "YQ", "YWI", "YWJj", "-_8BAg", "-_8BAg+/", "YR", "YQ==", "YQ\n", "Y\rQ", " YQ", "YQ\x00", "A", "AAAAA",
	} {
		f.Add(seed)
	}
	var b64 Encoding
	strictRaw := base64.RawURLEncoding.Strict()
	f.Fuzz(func(t *testing.T, s string) {
		got, err := b64.DecodeString(s)
		alphabetOnly := true
		for i := 0; i < len(s); i++ {
			if !isReferenceAlphabet(s[i]) {
				alphabetOnly = false
				break
			}
		}
		if !alphabetOnly {
			if err == nil {
				t.Fatalf("DecodeString(%q) accepted a byte outside the base64url alphabet", s)
			}
		} else {
			want, wantErr := strictRaw.DecodeString(s)
			if (err == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
				t.Fatalf("DecodeString(%q) = %x, %v; RawURLEncoding.Strict() = %x, %v", s, got, err, want, wantErr)
			}
		}
		if err == nil {
			if enc := b64.EncodeToString(got); enc != s {
				t.Fatalf("DecodeString(%q) = %x, which encodes as %q", s, got, enc)
			}
		}

		raw := []byte(s)
		enc := b64.EncodeToString(raw)
		back, err := b64.DecodeString(enc)
		if err != nil || !bytes.Equal(back, raw) {
			t.Fatalf("EncodeToString(%x) = %q, which decodes as %x, %v", raw, enc, back, err)
		}
	})
}

// isReferenceAlphabet is RFC 4648 §5's alphabet, spelled out apart from
// isAlphabet.
func isReferenceAlphabet(c byte) bool {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return bytes.IndexByte([]byte(alphabet), c) >= 0
}

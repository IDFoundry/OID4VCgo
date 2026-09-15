package hkdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// The three vectors below are RFC 5869's own SHA-256 test cases
// (Appendix A.1-A.3) — known-answer vectors, not just round-trip
// checks.
func TestVectorRFC5869Case1(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	wantPRK := mustHex(t, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	wantOKM := mustHex(t, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	prk := Extract(salt, ikm)
	if !bytes.Equal(prk, wantPRK) {
		t.Errorf("PRK = %x, want %x", prk, wantPRK)
	}
	okm, err := Expand(prk, info, 42)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Errorf("OKM = %x, want %x", okm, wantOKM)
	}

	keyed, err := Key(salt, ikm, info, 42)
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	if !bytes.Equal(keyed, wantOKM) {
		t.Errorf("Key = %x, want %x", keyed, wantOKM)
	}
}

func TestVectorRFC5869Case2(t *testing.T) {
	ikm := mustHex(t, "000102030405060708090a0b0c0d0e0f"+
		"101112131415161718191a1b1c1d1e1f"+
		"202122232425262728292a2b2c2d2e2f"+
		"303132333435363738393a3b3c3d3e3f"+
		"404142434445464748494a4b4c4d4e4f")
	salt := mustHex(t, "606162636465666768696a6b6c6d6e6f"+
		"707172737475767778797a7b7c7d7e7f"+
		"808182838485868788898a8b8c8d8e8f"+
		"909192939495969798999a9b9c9d9e9f"+
		"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
	info := mustHex(t, "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"+
		"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"+
		"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"+
		"e0e1e2e3e4e5e6e7e8e9eaebecedeeef"+
		"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	wantPRK := mustHex(t, "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")
	wantOKM := mustHex(t, "b11e398dc80327a1c8e7f78c596a4934"+
		"4f012eda2d4efad8a050cc4c19afa97c"+
		"59045a99cac7827271cb41c65e590e09"+
		"da3275600c2f09b8367793a9aca3db71"+
		"cc30c58179ec3e87c14c01d5c1f3434f"+
		"1d87")

	prk := Extract(salt, ikm)
	if !bytes.Equal(prk, wantPRK) {
		t.Errorf("PRK = %x, want %x", prk, wantPRK)
	}
	okm, err := Expand(prk, info, 82)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Errorf("OKM = %x, want %x", okm, wantOKM)
	}
}

func TestVectorRFC5869Case3(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	wantPRK := mustHex(t, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
	wantOKM := mustHex(t, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")

	prk := Extract(nil, ikm)
	if !bytes.Equal(prk, wantPRK) {
		t.Errorf("PRK = %x, want %x", prk, wantPRK)
	}
	okm, err := Expand(prk, nil, 42)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}
	if !bytes.Equal(okm, wantOKM) {
		t.Errorf("OKM = %x, want %x", okm, wantOKM)
	}
}

func TestExpandRejectsNonPositiveLength(t *testing.T) {
	if _, err := Expand([]byte("prk"), nil, 0); err == nil {
		t.Errorf("Expand accepted a zero length")
	}
	if _, err := Expand([]byte("prk"), nil, -1); err == nil {
		t.Errorf("Expand accepted a negative length")
	}
}

func TestExpandRejectsExcessiveLength(t *testing.T) {
	if _, err := Expand([]byte("prk"), nil, maxLength+1); err == nil {
		t.Errorf("Expand accepted a length beyond 255*HashLen")
	}
}

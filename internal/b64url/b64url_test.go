package b64url

import (
	"bytes"
	"testing"
)

// Only the RFC 7515 §2 alphabet decodes: line breaks, whitespace,
// padding and the standard alphabet's '+' and '/' are refused, where
// encoding/base64 alone would skip '\r' and '\n'.
func TestDecodeString(t *testing.T) {
	var b64 Encoding
	want := []byte{0xfb, 0xff, 0x01, 0x02}
	enc := b64.EncodeToString(want)
	got, err := b64.DecodeString(enc)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("DecodeString(%q) = %x, %v", enc, got, err)
	}
	for _, s := range []string{
		enc[:2] + "\r\n" + enc[2:],
		enc + "\n",
		"\r" + enc,
		enc[:2] + " " + enc[2:],
		enc + "==",
		"-_8BAg+/",
		"YQ\x00",
		"YR", // non-zero trailing bits (RFC 4648 §3.5)
	} {
		if _, err := b64.DecodeString(s); err == nil {
			t.Errorf("DecodeString(%q) accepted", s)
		}
	}
}

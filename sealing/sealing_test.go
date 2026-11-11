package sealing_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/sealing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestAESGCMSealer_RefusesWeakKeys: a key of the wrong length, one byte
// repeated, or all printable text (a passphrase, or an encoded key not
// yet decoded) is refused; random bytes, and text with one byte that
// isn't printable, are taken.
func TestAESGCMSealer_RefusesWeakKeys(t *testing.T) {
	printable := bytes.Repeat([]byte("ab"), 16)
	printable[31] = '\n' // whitespace is text too
	nearlyText := bytes.Clone(printable)
	nearlyText[0] = 0x80
	random := randomKey(t)
	for name, tc := range map[string]struct {
		key  []byte
		want string // "" for taken
	}{
		"random":         {random, ""},
		"one byte isn't": {nearlyText, ""},
		"16 bytes":       {random[:16], "want 32"},
		"zeros":          {make([]byte, 32), "one byte repeated"},
		"repeated 0x41":  {bytes.Repeat([]byte{0x41}, 32), "one byte repeated"},
		"passphrase":     {[]byte("correct horse battery staple!!!!"), "printable text"},
		"hex":            {[]byte("00112233445566778899aabbccddeeff"), "printable text"},
		"text":           {printable, "printable text"},
	} {
		_, err := sealing.AESGCMSealer(tc.key)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: AESGCMSealer = %v, want %q", name, err, tc.want)
		}
	}
}

// TestAESGCMSealer_SealsAndBinds: a sealed value opens with its own
// additional data alone, not altered, and carries the documented
// layout (nonce, then the GCM ciphertext and tag), so a Sealer of one's
// own can open it.
func TestAESGCMSealer_SealsAndBinds(t *testing.T) {
	key := randomKey(t)
	s, err := sealing.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, ad := []byte("the holder's claims"), []byte("record-1")
	sealed, err := s.Seal(plaintext, ad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Error("the sealed value carries its plaintext")
	}
	if got, err := s.Open(sealed, ad); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	if _, err := s.Open(sealed, []byte("record-2")); err == nil {
		t.Error("opened under other additional data")
	}
	altered := bytes.Clone(sealed)
	altered[len(altered)-1] ^= 1
	if _, err := s.Open(altered, ad); err == nil {
		t.Error("opened an altered value")
	}
	if _, err := s.Open(sealed[:5], ad); err == nil {
		t.Error("opened a value shorter than its nonce")
	}

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	if got, err := aead.Open(nil, sealed[:12], sealed[12:], ad); err != nil || !bytes.Equal(got, plaintext) {
		t.Errorf("crypto/cipher's GCM didn't open it: %q, %v", got, err)
	}
}

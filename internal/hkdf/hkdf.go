package hkdf

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// maxLength is RFC 5869 §2.3's bound on Expand's output: 255*HashLen.
const maxLength = 255 * sha256.Size

// Extract implements RFC 5869 §2.2 (HKDF-Extract) using SHA-256:
// PRK = HMAC-Hash(salt, IKM). A zero-length salt is set to a string of
// HashLen zero bytes, per §2.2.
func Extract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// Expand implements RFC 5869 §2.3 (HKDF-Expand) using SHA-256,
// producing length bytes of output keying material from prk (as
// produced by Extract) and info.
func Expand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("hkdf: length must be positive, got %d", length)
	}
	if length > maxLength {
		return nil, fmt.Errorf("hkdf: length %d exceeds the maximum of %d", length, maxLength)
	}

	var t, okm []byte
	for counter := byte(1); len(okm) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		okm = append(okm, t...)
	}
	return okm[:length], nil
}

// Key derives length bytes of output keying material from ikm/salt/info
// in one call: Expand(Extract(salt, ikm), info, length).
func Key(salt, ikm, info []byte, length int) ([]byte, error) {
	return Expand(Extract(salt, ikm), info, length)
}

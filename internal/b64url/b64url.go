// Package b64url is base64url as JOSE uses it (RFC 7515 §2): the
// URL- and filename-safe alphabet of RFC 4648 §5, with no padding,
// line breaks, whitespace or any other character.
package b64url

import (
	"encoding/base64"
	"fmt"
)

// strict refuses an encoding whose unused trailing bits aren't zero
// (RFC 4648 §3.5), as every encoder emits zero bits.
var strict = base64.RawURLEncoding.Strict()

// Encoding encodes and decodes base64url. Its zero value is ready to
// use.
type Encoding struct{}

// EncodeToString is src in base64url, without padding.
func (Encoding) EncodeToString(src []byte) string {
	return strict.EncodeToString(src)
}

// DecodeString decodes s, refusing any byte outside the base64url
// alphabet before decoding. encoding/base64 skips '\r' and '\n' even in
// Strict mode, so without the check one value would have any number of
// distinct encodings: a JWS signature segment, which its own signing
// input doesn't cover, could be altered without failing verification.
func (Encoding) DecodeString(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !isAlphabet(s[i]) {
			return nil, fmt.Errorf("base64url: illegal byte %#02x at offset %d", s[i], i)
		}
	}
	return strict.DecodeString(s)
}

func isAlphabet(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}

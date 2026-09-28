package credential

import (
	"bytes"
	"encoding/base64"
	"strings"
)

// portraitDataURIPrefix is how an SD-JWT's picture claim carries the
// portrait: a data: URL holding the JPEG.
const portraitDataURIPrefix = "data:image/jpeg;base64,"

// jpegMagic is the start of every JPEG file (SOI, then another marker).
var jpegMagic = []byte{0xFF, 0xD8, 0xFF}

func portraitDataURI(jpeg []byte) string {
	return portraitDataURIPrefix + base64.StdEncoding.EncodeToString(jpeg)
}

// PortraitJPEG reads the portrait from a credential's disclosed claims,
// flattened to element or claim name: JPEG bytes in an mdoc's portrait,
// a JPEG data: URL in an SD-JWT's picture. It returns false when
// neither is disclosed or the value isn't a JPEG.
func PortraitJPEG(claims map[string]any) ([]byte, bool) {
	var jpeg []byte
	switch {
	case claims[Portrait] != nil:
		b, ok := claims[Portrait].([]byte)
		if !ok {
			return nil, false
		}
		jpeg = b
	case claims[SDJWTPicture] != nil:
		s, ok := claims[SDJWTPicture].(string)
		if !ok || !strings.HasPrefix(s, portraitDataURIPrefix) {
			return nil, false
		}
		b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, portraitDataURIPrefix))
		if err != nil {
			return nil, false
		}
		jpeg = b
	default:
		return nil, false
	}
	if !bytes.HasPrefix(jpeg, jpegMagic) {
		return nil, false
	}
	return jpeg, true
}

// PortraitDataURI returns the disclosed portrait as a data: URL for an
// <img src>. It's re-encoded from the decoded JPEG, so only base64
// from this function reaches a page, never the claim's own text.
func PortraitDataURI(claims map[string]any) (string, bool) {
	jpeg, ok := PortraitJPEG(claims)
	if !ok {
		return "", false
	}
	return portraitDataURI(jpeg), true
}

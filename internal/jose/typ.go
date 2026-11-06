package jose

import "strings"

// TypeIs reports whether typ, a JOSE "typ" header value, names the
// media type want. "typ" is a media type (RFC 7515 §4.1.9), compared
// case-insensitively in ASCII only (RFC 6838 §4.2): "ſ" doesn't name
// "s", nor the Kelvin sign "k". One without a "/" has "application/"
// implied: "DPoP+JWT" and "application/dpop+jwt" both name "dpop+jwt".
func TypeIs(typ, want string) bool {
	return asciiEqualFold(mediaType(typ), mediaType(want))
}

// asciiEqualFold reports whether a and b are equal with ASCII letters
// compared case-insensitively and every other byte exactly.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if 'A' <= c && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// mediaType is typ with "application/" added when it has no "/".
func mediaType(typ string) string {
	if !strings.Contains(typ, "/") {
		return "application/" + typ
	}
	return typ
}

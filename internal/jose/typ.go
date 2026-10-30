package jose

import "strings"

// TypeIs reports whether typ, a JOSE "typ" header value, names the
// media type want. "typ" is a media type (RFC 7515 §4.1.9), compared
// case-insensitively (RFC 6838 §4.2), and one without a "/" has
// "application/" implied: "DPoP+JWT" and "application/dpop+jwt" both
// name "dpop+jwt".
func TypeIs(typ, want string) bool {
	return strings.EqualFold(mediaType(typ), mediaType(want))
}

// mediaType is typ with "application/" added when it has no "/".
func mediaType(typ string) string {
	if !strings.Contains(typ, "/") {
		return "application/" + typ
	}
	return typ
}

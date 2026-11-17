package wallet

import (
	"errors"
	"net/url"
	"strings"
)

// errNonNormalPath refuses a DPoP-protected request to an endpoint
// whose path isn't in normal form (hasNormalPath).
var errNonNormalPath = errors.New("the endpoint's path has dot segments or percent-encoded unreserved characters, which a DPoP proof's htu can't name unambiguously")

// hasNormalPath reports whether the path net/http sends for u is the
// path a server compares a DPoP proof's htu with once it has
// normalized it (RFC 9449 §4.3, RFC 3986 §6.2.2): u isn't opaque, and
// its escaped path has no "." or ".." segment and no percent-encoded
// unreserved character, which normalization would change. Otherwise a
// front end routing by the raw path and a resource server comparing the
// normalized htu would disagree on which resource a proof is for, as
// fapigo/client's protected resource client refuses such a URL for.
// A lowercase percent-encoding counts as normal: normalization only
// uppercases it, which names the same octet.
func hasNormalPath(u *url.URL) bool {
	if u.Opaque != "" {
		return false
	}
	escaped := u.EscapedPath()
	for i := 0; i+2 < len(escaped); i++ {
		if escaped[i] != '%' {
			continue
		}
		if b, err := url.PathUnescape(escaped[i : i+3]); err == nil && isUnreserved(b[0]) {
			return false
		}
	}
	for _, segment := range strings.Split(escaped, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// isUnreserved reports whether c is one of RFC 3986 §2.3's unreserved
// characters.
func isUnreserved(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	default:
		return c == '-' || c == '.' || c == '_' || c == '~'
	}
}

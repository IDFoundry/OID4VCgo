package dpop

import (
	"net"
	"net/url"
	"strings"
)

// sameTarget reports whether htu, a proof's claim, names target, the
// request's URI: both absolute http or https URLs with an ASCII host,
// equal once normalized (canonicalURI). A relative htu, or one with
// another scheme, binds the proof to no origin, so it never matches.
func sameTarget(htu, target string) bool {
	h, ok := parseHTTPURL(htu)
	if !ok {
		return false
	}
	t, ok := parseHTTPURL(target)
	return ok && canonicalURI(h) == canonicalURI(t)
}

// parseHTTPURL parses raw as an absolute http or https URL (the scheme
// compared case-insensitively, RFC 3986 §3.1) with a host. A host that
// isn't ASCII is refused: hosts compare case-insensitively in ASCII
// only, and a non-ASCII one names, through IDNA, a different DNS name
// than any spelling of it this comparison could equate. An
// internationalized host is given as its xn-- A-label.
func parseHTTPURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" || !isASCII(u.Host) {
		return nil, false
	}
	scheme := strings.ToLower(u.Scheme)
	return u, scheme == "https" || scheme == "http"
}

// canonicalURI normalizes u for comparison as a DPoP "htu" (RFC 9449
// §4.3: "the query and fragment parts of the htu ... are ignored", and
// syntax-based and scheme-based normalization, RFC 3986 §6.2.2 and
// §6.2.3, apply): scheme and host lowercased, a default port dropped,
// userinfo, query and fragment removed, and the path's percent-encodings
// uppercased, those of unreserved characters decoded, dot segments
// removed, and an empty path made "/". It mirrors fapigo/server's own
// htu comparison, so both of an issuer's Token Endpoint grants agree on
// which proofs name it. u must have come from parseHTTPURL.
func canonicalURI(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	path := normalizePath(u.EscapedPath())
	if path == "" {
		path = "/"
	}
	return scheme + "://" + canonicalHost(u.Host, scheme) + path
}

// canonicalHost is host lowercased, without scheme's default port.
func canonicalHost(host, scheme string) string {
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return strings.ToLower(host)
	}
	h = strings.ToLower(h)
	if strings.Contains(h, ":") {
		h = "[" + h + "]" // an IPv6 literal, its brackets stripped by SplitHostPort
	}
	if port == "" || (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return h
	}
	return h + ":" + port
}

// normalizePath applies RFC 3986 §6.2.2's syntax-based normalization to
// an escaped path: percent-encodings uppercased (§6.2.2.1), those of
// unreserved characters decoded (§6.2.2.2), then dot segments removed
// (§6.2.2.3, by §5.2.4's algorithm). A "%" not followed by two hex
// digits is kept as it is.
func normalizePath(escaped string) string {
	var b strings.Builder
	b.Grow(len(escaped))
	for i := 0; i < len(escaped); i++ {
		c := escaped[i]
		if c != '%' || i+2 >= len(escaped) || !isHex(escaped[i+1]) || !isHex(escaped[i+2]) {
			b.WriteByte(c)
			continue
		}
		decoded := unhex(escaped[i+1])<<4 | unhex(escaped[i+2])
		if isUnreserved(decoded) {
			b.WriteByte(decoded)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(escaped[i+1 : i+3]))
		}
		i += 2
	}
	return removeDotSegments(b.String())
}

// removeDotSegments is RFC 3986 §5.2.4's algorithm.
func removeDotSegments(in string) string {
	var out []string // output segments, each with its leading "/" if any
	for in != "" {
		switch {
		case strings.HasPrefix(in, "../"):
			in = in[3:]
		case strings.HasPrefix(in, "./"):
			in = in[2:]
		case strings.HasPrefix(in, "/./"):
			in = in[2:]
		case in == "/.":
			in = "/"
		case strings.HasPrefix(in, "/../"):
			in = in[3:]
			out = dropLast(out)
		case in == "/..":
			in = "/"
			out = dropLast(out)
		case in == "." || in == "..":
			in = ""
		default:
			end := strings.IndexByte(in[1:], '/') + 1
			if end == 0 {
				end = len(in)
			}
			out = append(out, in[:end])
			in = in[end:]
		}
	}
	return strings.Join(out, "")
}

func dropLast(segments []string) []string {
	if len(segments) == 0 {
		return segments
	}
	return segments[:len(segments)-1]
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func isUnreserved(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

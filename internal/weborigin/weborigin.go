// Package weborigin checks and normalizes serialized web origins
// (https://html.spec.whatwg.org/multipage/browsers.html#ascii-serialisation-of-an-origin),
// the form a browser gives a Digital Credentials API response's origin
// in — for package verifier's OpenID4VP requests (OpenID4VP 1.0
// Appendix A) and package mdocdcapi's ISO/IEC TS 18013-7 Annex C ones
// alike.
package weborigin

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Check checks origin is a serialized web origin (scheme, host and
// optional port, no trailing slash), spelled as the browser gives it:
// anything else would never match the origin a response is bound to.
func Check(origin string) error {
	u, err := url.Parse(origin)
	switch {
	case err != nil:
		return fmt.Errorf("origin %q isn't a URL: %w", origin, err)
	case u.Scheme == "" || u.Host == "":
		return fmt.Errorf("origin %q needs a scheme and a host", origin)
	// A bare "#" leaves Fragment empty, as a bare "?" leaves RawQuery.
	case u.Path != "" || u.RawQuery != "" || u.ForceQuery || strings.Contains(origin, "#") || u.User != nil || u.Opaque != "":
		return fmt.Errorf("origin %q must be a scheme, host and optional port only (no trailing slash)", origin)
	case !isCanonical(origin, u):
		return fmt.Errorf("origin %q isn't serialized as a browser gives it: a lowercase scheme and ASCII host, and a port only when it isn't the scheme's default", origin)
	}
	return nil
}

// isCanonical reports whether origin, parsed as u, is spelled as the
// browser serializes an origin: url.Parse accepts an uppercase scheme
// or host, an empty or zero-padded port, or the scheme's default one,
// none of which the browser ever gives, so such an origin can never
// match.
func isCanonical(origin string, u *url.URL) bool {
	// url.Parse lowercases the scheme it returns.
	if !strings.HasPrefix(origin, u.Scheme+"://") {
		return false
	}
	for i := 0; i < len(u.Host); i++ {
		if c := u.Host[i]; c >= utf8.RuneSelf || ('A' <= c && c <= 'Z') {
			return false
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return false
	}
	port := u.Port()
	if port == "" {
		return true
	}
	n, err := strconv.Atoi(port)
	if err != nil || strconv.Itoa(n) != port {
		return false
	}
	defaultPort := map[string]string{"http": "80", "https": "443"}[u.Scheme]
	return port != defaultPort
}

// Normalize is origin as a browser serializes it: its scheme and host
// lowercased, without a trailing "/" or the scheme's default port.
// Anything else it carries is kept, for Check to refuse.
func Normalize(origin string) string {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.ForceQuery || strings.Contains(origin, "#") || u.User != nil || u.Opaque != "" {
		return origin
	}
	host := strings.ToLower(u.Host)
	switch u.Scheme {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	return u.Scheme + "://" + host
}

// CheckPage checks origin is a serialized origin (Check) a page can
// use the Digital Credentials API from — browsers offer it to secure
// contexts only: https, or, where allowLoopbackHTTP (development),
// loopback http.
func CheckPage(origin string, allowLoopbackHTTP bool) error {
	if err := Check(origin); err != nil {
		return err
	}
	u, _ := url.Parse(origin)
	switch {
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && allowLoopbackHTTP && IsLoopback(u.Hostname()):
		return nil
	}
	return fmt.Errorf("origin %q must be https", origin)
}

// NormalizeAll is origins, each normalized (Normalize) and checked by
// CheckPage, for a configured allow-list; nil for none.
func NormalizeAll(origins []string, allowLoopbackHTTP bool) ([]string, error) {
	var out []string
	for _, origin := range origins {
		normalized := Normalize(origin)
		if err := CheckPage(normalized, allowLoopbackHTTP); err != nil {
			return nil, err
		}
		out = append(out, normalized)
	}
	return out, nil
}

// IsLoopback reports whether host is "localhost" or a loopback IP
// address.
func IsLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

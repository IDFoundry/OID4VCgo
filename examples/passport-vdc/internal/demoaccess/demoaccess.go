// Package demoaccess guards the demo's pages under /demo/ at the
// origin: the operator pages (uploading, reviews, revocation, kept
// passports, verifier requests) that have no login of their own.
//
// Exposed through a tunnel, those pages are meant to sit behind an edge
// rule on the path /demo/ (Cloudflare Access; see the iOS demo app's
// README). Guard backs that rule at the origin:
//
//   - A request whose path, decoded and cleaned, is under /demo/ must
//     have spelled it canonically: no percent-encoding (r.URL.RawPath
//     set) and nothing path.Clean would change. Go's ServeMux routes
//     /%64emo/status to the /demo/status handler, so an edge that
//     matches the raw path would otherwise let it through unguarded.
//   - With Access configured, each such request must carry a
//     Cf-Access-Jwt-Assertion header holding a token Cloudflare Access
//     signed for the application's audience (VerifyAccessToken).
//   - A state-changing request (anything but GET, HEAD or OPTIONS)
//     must come from the app's own origin, by its Origin header or,
//     without one, its Referer (SameOrigin): one with neither is
//     refused, so a non-browser client can't skip the check.
//
// Everything outside /demo/ is the protocol surface wallets and
// verifiers call, and Guard passes it through unchanged.
package demoaccess

import (
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// Prefix is the path the guarded pages are under.
const Prefix = "/demo/"

// Guard returns next, guarding the requests under Prefix: refusing a
// non-canonical path (400), one without a valid Cloudflare Access token
// when access is non-nil (403), and a state-changing one not from
// origin (403). origin is the app's own, as a browser sends it in an
// Origin header ("https://issuer.example.com"); OriginOf derives it
// from the app's URL.
func Guard(next http.Handler, origin string, access *AccessVerifier) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !underPrefix(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if !canonical(r.URL) {
			refuse(w, r, http.StatusBadRequest, "non-canonical path refused: request "+Prefix+" pages by their plain path", nil)
			return
		}
		if access != nil {
			if err := access.Verify(r.Context(), r.Header.Get(AccessTokenHeader)); err != nil {
				refuse(w, r, http.StatusForbidden, "this page needs a Cloudflare Access login", err)
				return
			}
		}
		if !safeMethod(r.Method) && !SameOrigin(r, origin) {
			refuse(w, r, http.StatusForbidden, "cross-origin request refused", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// refuse answers r with status and msg, and logs the refusal (and
// err, its cause, if any).
func refuse(w http.ResponseWriter, r *http.Request, status int, msg string, err error) {
	reason := msg
	if err != nil {
		reason = err.Error()
	}
	log.Printf("demoaccess: %d for %q %q: %q", status, r.Method, r.URL.EscapedPath(), reason) // #nosec G706 -- quoted: a request can't forge a log line
	http.Error(w, msg, status)
}

// underPrefix reports whether p, cleaned, is Prefix or under it.
func underPrefix(p string) bool {
	clean := path.Clean("/" + p)
	return clean == strings.TrimSuffix(Prefix, "/") || strings.HasPrefix(clean, Prefix)
}

// canonical reports whether u's path is spelled as it's routed: not
// percent-encoded, and unchanged by path.Clean (but for a trailing
// slash).
func canonical(u *url.URL) bool {
	if u.RawPath != "" {
		return false
	}
	clean := path.Clean(u.Path)
	if strings.HasSuffix(u.Path, "/") && clean != "/" {
		clean += "/"
	}
	return clean == u.Path
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// SameOrigin reports whether r comes from a page of origin: its Origin
// header is origin or, without one, its Referer is a URL on origin. A
// request with neither is not.
func SameOrigin(r *http.Request, origin string) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return o == origin
	}
	ref, err := url.Parse(r.Referer())
	if err != nil || ref.Host == "" {
		return false
	}
	return OriginOf(ref) == origin
}

// OriginOf is u's origin, scheme://host[:port], as a browser's Origin
// header names it.
func OriginOf(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// OriginOfURL is OriginOf the URL raw, or raw itself if it doesn't
// parse.
func OriginOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return OriginOf(u)
}

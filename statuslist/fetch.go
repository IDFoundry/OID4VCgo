package statuslist

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"syscall"
	"time"
)

// Fetcher fetches Status List Tokens (draft-14 §8.1): an HTTPS GET of a
// Referenced Token's status_list uri, asking for one token format.
//
// It fetches exactly the uri given — https only, redirects refused —
// and accepts only a 2xx response of the requested media type, no
// larger than MaxBytes. A redirect is refused because the uri is what
// the Referenced Token's issuer signed; following one could leave https,
// or reach somewhere the issuer never named.
//
// It connects only to public addresses: a uri whose host is, or
// resolves to, anything but a global unicast address is refused when
// the connection is dialled, so a Referenced Token can't point this
// Verifier at its own network. That covers loopback, private,
// link-local, shared (100.64.0.0/10), unspecified, multicast and the
// other special-purpose ranges, and an IPv6 address that embeds an
// IPv4 one (NAT64 64:ff9b::/96, 6to4, IPv4-compatible) is judged by
// the IPv4 address it reaches. AllowLoopback and AllowPrivate lift
// that for local development and internal deployments.
type Fetcher struct {
	// HTTP is the client fetches use, e.g. one trusting a private CA.
	// Nil means a client with a 30-second timeout. Its CheckRedirect is
	// overridden to refuse redirects, and its Transport must be nil or
	// an *http.Transport: a copy of it is used whose connections are
	// checked against the address policy above, with its proxy and
	// custom dial hooks removed. Any other RoundTripper is refused
	// unless UncheckedTransport is set.
	HTTP *http.Client

	// MaxBytes bounds a token's size; zero means 1 MiB.
	MaxBytes int

	// AllowLoopback permits loopback addresses (127.0.0.0/8, ::1) —
	// for local development only.
	AllowLoopback bool

	// AllowPrivate permits private, shared, link-local and site-local
	// unicast addresses, and local-use NAT64 (64:ff9b:1::/48) — for a
	// Status List served inside the deployment's own network.
	AllowPrivate bool

	// AllowProxy keeps HTTP.Transport's Proxy, e.g. to honour
	// HTTPS_PROXY. Only the proxy's address is then checked, not the
	// status list's host: the proxy must refuse internal destinations
	// itself.
	AllowProxy bool

	// UncheckedTransport permits an HTTP.Transport that isn't an
	// *http.Transport — one wrapped for tracing, say — which Fetcher
	// can't apply its address policy to. That transport must then keep
	// fetches away from internal addresses itself.
	UncheckedTransport bool
}

// Fetch GETs uri, asking for mediaType (TokenMediaType or
// CWTTokenMediaType), and returns the token's bytes.
func (f Fetcher) Fetch(ctx context.Context, uri, mediaType string) ([]byte, error) {
	if u, err := url.Parse(uri); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("statuslist: status list uri %q isn't an https URL", uri)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch: %w", err)
	}
	req.Header.Set("Accept", mediaType)
	client := http.Client{Timeout: 30 * time.Second}
	if f.HTTP != nil {
		client = *f.HTTP
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Transport, err = f.transport(client.Transport); err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("statuslist: fetch %s: HTTP %d", uri, resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != mediaType {
		return nil, fmt.Errorf("statuslist: fetch %s: content type %q, want %q", uri, got, mediaType)
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = maxTokenBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("statuslist: fetch %s: %w", uri, err)
	}
	if len(body) > limit {
		return nil, fmt.Errorf("statuslist: fetch %s: token exceeds %d bytes", uri, limit)
	}
	return body, nil
}

// Checker checks a Referenced Token's status end to end (draft-14
// §8.3): it fetches the Status List Token its reference names, then
// verifies it with CheckX5C or CheckCWTX5Chain — its signer's
// certificate chain to Roots, its sub against the reference, and the
// status at the reference's index.
type Checker struct {
	Fetcher Fetcher

	// Roots are the trust anchors for Status List Token signers,
	// REQUIRED — normally the same anchors the Referenced Tokens'
	// issuers chain to. Options.LeafPolicy can narrow them further.
	Roots *x509.CertPool

	Options VerifyOptions
}

// Check fetches and checks the Status List Token ref names: the CWT
// form when cwt is true (an mdoc's reference), the JWT form otherwise
// (an SD-JWT VC's — SD-JWT VC requires a JWT Status List Token).
func (c Checker) Check(ctx context.Context, ref StatusListRef, cwt bool) (StatusType, TokenClaims, error) {
	if c.Roots == nil {
		return 0, TokenClaims{}, errors.New("statuslist: Checker.Roots is required")
	}
	mediaType := TokenMediaType
	if cwt {
		mediaType = CWTTokenMediaType
	}
	token, err := c.Fetcher.Fetch(ctx, ref.URI, mediaType)
	if err != nil {
		return 0, TokenClaims{}, err
	}
	if cwt {
		return CheckCWTX5Chain(token, c.Roots, ref, c.Options)
	}
	return CheckX5C(string(token), c.Roots, ref, c.Options)
}

// transport returns rt with f's address policy applied to its
// connections, when rt is an *http.Transport or nil.
func (f Fetcher) transport(rt http.RoundTripper) (http.RoundTripper, error) {
	var base *http.Transport
	switch t := rt.(type) {
	case nil:
		base = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		base = t.Clone()
	default:
		if !f.UncheckedTransport {
			return nil, fmt.Errorf("statuslist: fetch: HTTP.Transport is a %T, which the address policy can't be applied to; set UncheckedTransport to use it anyway", rt)
		}
		return rt, nil
	}
	if !f.AllowProxy {
		base.Proxy = nil
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: f.checkDial}
	base.DialContext = dialer.DialContext
	base.DialTLSContext = nil
	// The deprecated hooks would bypass the checked dialer: DialTLS is
	// used for https whenever it's set.
	base.Dial, base.DialTLS = nil, nil //nolint:staticcheck // clearing them, not using them
	return base, nil
}

// checkDial refuses a connection to an address f's policy excludes.
// It runs on the resolved address, so a public name that resolves to
// an internal address is refused too.
func (f Fetcher) checkDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("statuslist: fetch: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("statuslist: fetch: %w", err)
	}
	if !f.addressAllowed(ip) {
		return fmt.Errorf("statuslist: fetch: refusing to connect to %s: not a public address", ip)
	}
	return nil
}

// Address ranges the policy treats specially, beyond what netip.Addr's
// own predicates classify (IANA's IPv4 and IPv6 Special-Purpose Address
// Registries).
var (
	// privatePrefixes are internal ranges AllowPrivate permits.
	privatePrefixes = []netip.Prefix{
		v4Prefix(100, 64, 0, 0, 10),             // shared address space (RFC 6598)
		netip.MustParsePrefix("fec0::/10"),      // site-local (deprecated, RFC 3879)
		netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64 (RFC 8215)
	}

	// reservedPrefixes are never a public status list's address.
	reservedPrefixes = []netip.Prefix{
		v4Prefix(0, 0, 0, 0, 8),                // "this network"
		v4Prefix(192, 0, 0, 0, 24),             // IETF protocol assignments
		v4Prefix(192, 0, 2, 0, 24),             // documentation
		v4Prefix(192, 88, 99, 0, 24),           // 6to4 relay anycast (deprecated)
		v4Prefix(198, 18, 0, 0, 15),            // benchmarking
		v4Prefix(198, 51, 100, 0, 24),          // documentation
		v4Prefix(203, 0, 113, 0, 24),           // documentation
		v4Prefix(240, 0, 0, 0, 4),              // reserved, and broadcast
		netip.MustParsePrefix("100::/64"),      // discard-only
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments, including Teredo
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("3fff::/20"),     // documentation
		netip.MustParsePrefix("5f00::/16"),     // segment routing SIDs
	}

	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
	v4Compat    = netip.MustParsePrefix("::/96")
)

// v4Prefix is the IPv4 prefix a.b.c.d/bits.
func v4Prefix(a, b, c, d byte, bits int) netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{a, b, c, d}), bits)
}

func inAny(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// embeddedIPv4 returns the IPv4 address ip reaches through an IPv4
// embedding — IPv4-mapped, NAT64 64:ff9b::/96, 6to4 2002::/16 or
// IPv4-compatible ::/96 — or ip itself.
func embeddedIPv4(ip netip.Addr) netip.Addr {
	b := ip.As16()
	switch {
	case ip.Is4In6():
		return ip.Unmap()
	case nat64Prefix.Contains(ip), v4Compat.Contains(ip) && !ip.IsUnspecified() && !ip.IsLoopback():
		return netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFour.Contains(ip):
		return netip.AddrFrom4([4]byte(b[2:6]))
	}
	return ip
}

func (f Fetcher) addressAllowed(ip netip.Addr) bool {
	ip = embeddedIPv4(ip)
	switch {
	case ip.IsLoopback():
		return f.AllowLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), inAny(privatePrefixes, ip):
		return f.AllowPrivate
	case !ip.IsGlobalUnicast(), inAny(reservedPrefixes, ip):
		return false
	}
	return true
}

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
// resolves to, a loopback, private, link-local, unspecified, multicast
// or shared (100.64.0.0/10) address is refused when the connection is
// dialled, so a Referenced Token can't point this Verifier at its own
// network. AllowLoopback and AllowPrivate lift that for local
// development and internal deployments.
type Fetcher struct {
	// HTTP is the client fetches use, e.g. one trusting a private CA.
	// Nil means a client with a 30-second timeout. Its CheckRedirect is
	// overridden to refuse redirects, and when its Transport is an
	// *http.Transport (or nil), a copy of it is used whose connections
	// are checked against the address policy above. Any other
	// RoundTripper is used as it is: the address policy is then its own.
	// A proxy the Transport names is what gets checked, not the uri's
	// host.
	HTTP *http.Client

	// MaxBytes bounds a token's size; zero means 1 MiB.
	MaxBytes int

	// AllowLoopback permits loopback addresses (127.0.0.0/8, ::1) —
	// for local development only.
	AllowLoopback bool

	// AllowPrivate permits private, shared and link-local unicast
	// addresses — for a Status List served inside the deployment's own
	// network.
	AllowPrivate bool
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
	client.Transport = f.transport(client.Transport)
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
func (f Fetcher) transport(rt http.RoundTripper) http.RoundTripper {
	var base *http.Transport
	switch t := rt.(type) {
	case nil:
		base = http.DefaultTransport.(*http.Transport).Clone()
		base.Proxy = nil
	case *http.Transport:
		base = t.Clone()
	default:
		return rt
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: f.checkDial}
	base.DialContext = dialer.DialContext
	base.DialTLSContext = nil
	return base
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
	if !f.addressAllowed(ip.Unmap()) {
		return fmt.Errorf("statuslist: fetch: refusing to connect to %s: not a public address", ip)
	}
	return nil
}

// sharedAddressSpace is RFC 6598's carrier-grade NAT range.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

func (f Fetcher) addressAllowed(ip netip.Addr) bool {
	switch {
	case ip.IsUnspecified(), ip.IsMulticast(), ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast():
		return false
	case ip.IsLoopback():
		return f.AllowLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), sharedAddressSpace.Contains(ip):
		return f.AllowPrivate
	}
	return true
}

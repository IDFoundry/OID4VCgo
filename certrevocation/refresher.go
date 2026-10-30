package certrevocation

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// Defaults for a RefresherConfig field left zero, and the fixed bounds
// of Run's schedule.
const (
	// DefaultCRLMaxBytes bounds a fetched CRL's size. An IACA's CRL is
	// a few kilobytes, and a large CA shards its CRLs so each stays well
	// below this; the bound is what a broken or hostile distribution
	// point can make the process buffer.
	DefaultCRLMaxBytes = 8 << 20

	// DefaultCRLFetchTimeout bounds one fetch, every redirect hop
	// included, when RefresherConfig.HTTPClient sets no Timeout.
	DefaultCRLFetchTimeout = 30 * time.Second

	// DefaultCRLMaxInterval is the longest Run waits between passes
	// when every list is current: a revocation the CA publishes is
	// picked up within it, however far off the held list's nextUpdate.
	DefaultCRLMaxInterval = time.Hour

	// MaxCRLRedirects is how many redirects a fetch follows.
	MaxCRLRedirects = 3

	// minRefreshInterval is the shortest Run waits after a pass that
	// succeeded, so a list close to its nextUpdate isn't fetched in a
	// tight loop.
	minRefreshInterval = time.Minute

	// retryBase and retryMax bound Run's backoff after a failed pass:
	// it doubles from retryBase up to retryMax, with jitter.
	retryBase = 30 * time.Second
	retryMax  = 30 * time.Minute
)

// RefresherConfig configures a Refresher.
type RefresherConfig struct {
	// URLs are the CRL distribution points to fetch, http or https:
	// those named by the CRLDistributionPoints of the CA certificates
	// whose issued certificates are checked, configured here by the
	// deployment. They're never discovered from a presented
	// certificate, which would let whoever presents one choose where
	// this process connects. Required, without duplicates.
	URLs []string

	// Issuers are the CA certificates whose CRLs URLs serve. A fetched
	// list replaces the held one only when one of them, by name and
	// signature, issued it. CRLs checks the signature itself at every
	// check; checking it on fetch too keeps a forged or corrupted
	// response from evicting a good list, and makes the rollback checks
	// (see Refresh) compare signed values rather than whatever a plain
	// http response carried. Two of them with the same subject name but
	// different keys are refused unless AllowSameNameIssuers is set.
	// Required.
	Issuers []*x509.Certificate

	// AllowSameNameIssuers lets Issuers hold two or more certificates
	// with the same subject name but different public keys: a CA that
	// re-keyed under its name and still issues CRLs under its old key
	// too, or two CAs that chose the same name, as nothing stops a
	// self-signed IACA from doing. The rollback floor (see Refresh) is
	// kept per issuer name and key either way, so one key's lists never
	// raise, or are refused by, the floor of another's, and a re-keyed
	// CA may restart its CRL numbering. It's an explicit choice because
	// X.509 names aren't unique across CAs (RFC 5280 §4.1.2.6 requires
	// a name to be unique only among the subjects one CA certifies, and
	// a self-signed root names itself), and such issuers are usually a
	// mistake: bind each of their URLs with URLIssuers, since an
	// unbound URL accepts a current list under either key in place of
	// the other's.
	AllowSameNameIssuers bool

	// URLIssuers binds a URL to the one of Issuers whose CRL it serves:
	// a list fetched from it is accepted only when that issuer signed
	// it. Each key must be one of URLs, each certificate one of Issuers.
	// Bind every URL whose issuer is known. An unbound URL is bound by
	// the list it holds instead: a list from another of Issuers is
	// refused until the held one is past its nextUpdate, and accepted
	// after. So an unbound URL that once answered with another CA's
	// genuine list — a mix-up, or an attacker on a plain http fetch —
	// refuses its own CA's lists until that list expires; a bound one
	// never holds another CA's list at all.
	URLIssuers map[string]*x509.Certificate

	// RequireHTTPS refuses http URLs: NewRefresher fails for one.
	// Distribution points are commonly plain http, since a CRL is
	// signed; but over http an attacker on the path chooses which of an
	// issuer's still-current lists a fetch gets (see Floors).
	RequireHTTPS bool

	// Floors are lists accepted before, by an earlier process: a
	// fetched list is refused if older than the newest of these from
	// its issuer (see Refresh), as it is if older than any list this
	// Refresher has accepted since. Persist what OnAccept hands over
	// and pass it back here on restart, so a restart doesn't reopen the
	// rollback a running Refresher refuses. Only their signed issuer,
	// thisUpdate and CRL number are used, so an expired list does as
	// well as a current one. Each is a floor for the one of Issuers
	// whose key verifies its signature, by that issuer's name and key,
	// never for another by the same name. A list none of Issuers signed
	// is ignored, so lists persisted from an issuer since removed from
	// Issuers don't stop a Refresher being built. They aren't held or
	// served.
	Floors []*x509.RevocationList

	// OnAccept, if set, is called with every list a fetch accepted, and
	// the URL (its password redacted) it was fetched from, after it
	// replaced the held one: the list to persist for Floors. It runs on
	// the goroutine calling Refresh or Run, and must not block for long.
	// Calls never overlap, even from concurrent Refresh and Run passes,
	// and come in the order the lists were accepted, so a list handed
	// over is never older than one handed over before from its issuer:
	// persisting the last one received from each issuer keeps its
	// newest. Until it
	// returns, no other fetched list is accepted; it mustn't call
	// Refresh itself.
	OnAccept func(url string, list *x509.RevocationList)

	// HTTPClient makes the fetches. Nil means a client built with
	// fapihttp.NewClient (fapihttp.RecommendedTransportConfig), which
	// dials only public addresses: loopback, private, link-local,
	// unspecified, multicast and the other special-purpose ranges are
	// refused when the connection is dialled, after resolving the
	// host, so a name resolving to an internal address is refused too.
	// A client given here is used as given, and its transport decides
	// what it can reach: build it with fapihttp.NewClient too. Either
	// way its CheckRedirect is replaced (see Refresh), and a client
	// without a Timeout gets DefaultCRLFetchTimeout.
	HTTPClient *http.Client

	// AllowLoopback lets the default client dial loopback addresses,
	// for local development and tests. It can't be combined with
	// HTTPClient, whose own transport decides that.
	AllowLoopback bool

	// MaxBytes bounds a CRL's size; zero means DefaultCRLMaxBytes.
	MaxBytes int64

	// MaxInterval is the longest Run waits between passes; zero means
	// DefaultCRLMaxInterval.
	MaxInterval time.Duration

	// OnError, if set, is called by Run for every URL a pass failed
	// for, with the URL (its password redacted) and the error. Run has
	// no other way to report one: the library logs nothing.
	OnError func(url string, err error)

	// Clock is the current time; nil means time.Now. Tests set it.
	Clock func() time.Time
}

// Refresher fetches CRLs from configured distribution points and holds
// the last good list from each in memory, for CRLs to check against:
// CRLs{Lists: r.Lists}, which Checker returns. Lists never fetches.
//
// NewRefresher starts nothing. Run keeps the lists current in a loop
// the caller starts in its own goroutine (go r.Run(ctx)); Refresh is
// one pass, for a caller that schedules refreshes itself. Fetch once
// with Refresh before serving, or CRLs fails closed with
// ErrNoCurrentCRL until Run's first pass completes. On a phone, let
// the operating system's background scheduler drive refreshes and
// hand the lists to the mobile library's SetCRLs (mobile/ABI.md)
// instead: an app's own goroutine doesn't run while it's suspended.
//
// A fetched list must not be older than the newest this Refresher has
// accepted from the same issuer, nor than Floors. Nothing bounds the
// first list ever accepted from an issuer, though: one fetched over
// plain http, before anything is persisted for Floors, can be any list
// the issuer signed that is still inside its validity — one predating a
// revocation, under a long CRL cadence such as ISO/IEC 18013-5 Annex B
// allows for an IACA. RequireHTTPS closes that where the distribution
// points serve https; otherwise seed Floors from a list obtained over a
// trusted channel.
//
// A Refresher is safe for concurrent use.
type Refresher struct {
	urls        []string
	issuers     []*x509.Certificate
	bound       map[string]*x509.Certificate
	client      http.Client
	maxBytes    int64
	maxInterval time.Duration
	onError     func(string, error)
	onAccept    func(string, *x509.RevocationList)
	now         func() time.Time

	// wait sleeps for d, returning false when ctx ends first, and
	// jitter returns a random duration in [0, n); tests replace them.
	wait   func(ctx context.Context, d time.Duration) bool
	jitter func(n time.Duration) time.Duration

	// acceptMu serialises accepting a fetched list with handing it to
	// onAccept (see refreshOne). It's taken before mu, never after.
	acceptMu sync.Mutex

	mu   sync.RWMutex
	held map[string]heldCRL
	// floors is, by issuer — its name and the key that signed its lists
	// — the newest thisUpdate and highest CRL number accepted from it or
	// in Floors.
	floors map[floorKey]crlFloor
}

// floorKey identifies an issuer for its rollback floor: its name (a
// list's RawIssuer) and the SubjectPublicKeyInfo of the configured
// issuer certificate that verified the list's signature. A name alone
// isn't unique: keyed by it, another configured CA by the same name
// could raise this one's floor with a list of its own carrying a huge
// CRL number, and so have the CA's next genuine list, the one revoking
// a certificate, refused as a rollback.
type floorKey struct {
	name, key string
}

// floorKeyOf is the floorKey of the lists issuer signs.
func floorKeyOf(issuer *x509.Certificate) floorKey {
	return floorKey{name: string(issuer.RawSubject), key: string(issuer.RawSubjectPublicKeyInfo)}
}

// heldCRL is the last good list from one URL, and when it was fetched.
type heldCRL struct {
	list      *x509.RevocationList
	fetchedAt time.Time
}

// crlFloor is what an issuer's next list may not be older than: the
// newest thisUpdate and highest CRL number (nil when none had one) of
// the lists accepted from it.
type crlFloor struct {
	thisUpdate time.Time
	number     *big.Int
}

// raise lifts f to list's thisUpdate and number where they're higher.
func (f crlFloor) raise(list *x509.RevocationList) crlFloor {
	if list.ThisUpdate.After(f.thisUpdate) {
		f.thisUpdate = list.ThisUpdate
	}
	if list.Number != nil && (f.number == nil || list.Number.Cmp(f.number) > 0) {
		f.number = list.Number
	}
	return f
}

// NewRefresher validates cfg and returns a Refresher holding no lists
// yet.
func NewRefresher(cfg RefresherConfig) (*Refresher, error) {
	if err := validateURLs(cfg); err != nil {
		return nil, err
	}
	if len(cfg.Issuers) == 0 || slices.Contains(cfg.Issuers, nil) {
		return nil, errors.New("certrevocation: RefresherConfig.Issuers is required, without nil certificates")
	}
	if err := validateURLIssuers(cfg); err != nil {
		return nil, err
	}
	if err := validateIssuerNames(cfg); err != nil {
		return nil, err
	}
	if slices.Contains(cfg.Floors, nil) {
		return nil, errors.New("certrevocation: RefresherConfig.Floors has a nil list")
	}
	if cfg.MaxBytes < 0 || cfg.MaxInterval < 0 {
		return nil, errors.New("certrevocation: RefresherConfig.MaxBytes and MaxInterval can't be negative")
	}
	client, err := refresherClient(cfg)
	if err != nil {
		return nil, err
	}
	r := &Refresher{
		urls:        slices.Clone(cfg.URLs),
		issuers:     slices.Clone(cfg.Issuers),
		bound:       maps.Clone(cfg.URLIssuers),
		client:      client,
		maxBytes:    cmp.Or(cfg.MaxBytes, DefaultCRLMaxBytes),
		maxInterval: cmp.Or(cfg.MaxInterval, DefaultCRLMaxInterval),
		onError:     cfg.OnError,
		onAccept:    cfg.OnAccept,
		now:         cfg.Clock,
		wait:        sleep,
		jitter:      func(n time.Duration) time.Duration { return rand.N(n) }, //nolint:gosec // retry jitter, not a secret
		held:        make(map[string]heldCRL, len(cfg.URLs)),
		floors:      make(map[floorKey]crlFloor, len(cfg.Issuers)),
	}
	if r.now == nil {
		r.now = time.Now
	}
	for _, list := range cfg.Floors {
		if signer := signerOf(list, r.issuers); signer != nil {
			r.raiseFloor(floorKeyOf(signer), list)
		}
	}
	return r, nil
}

// raiseFloor raises the floor of the issuer k to list.
func (r *Refresher) raiseFloor(k floorKey, list *x509.RevocationList) {
	r.floors[k] = r.floors[k].raise(list)
}

// validateURLs refuses cfg.URLs when empty, repeating a URL, or holding
// one that isn't http or https — or isn't https, with RequireHTTPS.
func validateURLs(cfg RefresherConfig) error {
	if len(cfg.URLs) == 0 {
		return errors.New("certrevocation: RefresherConfig.URLs is required")
	}
	for i, raw := range cfg.URLs {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("certrevocation: RefresherConfig.URLs[%d] isn't an http or https URL", i)
		}
		if cfg.RequireHTTPS && u.Scheme != "https" {
			return fmt.Errorf("certrevocation: RefresherConfig.URLs[%d] isn't https, which RequireHTTPS requires", i)
		}
		if slices.Contains(cfg.URLs[:i], raw) {
			return fmt.Errorf("certrevocation: RefresherConfig.URLs[%d] repeats %s", i, u.Redacted())
		}
	}
	return nil
}

// validateURLIssuers refuses a cfg.URLIssuers entry for a URL not in
// URLs, or binding one to a certificate not in Issuers.
func validateURLIssuers(cfg RefresherConfig) error {
	for u, issuer := range cfg.URLIssuers {
		switch {
		case !slices.Contains(cfg.URLs, u):
			return fmt.Errorf("certrevocation: RefresherConfig.URLIssuers binds %s, which isn't one of URLs", redacted(u))
		case issuer == nil || !slices.ContainsFunc(cfg.Issuers, issuer.Equal):
			return fmt.Errorf("certrevocation: RefresherConfig.URLIssuers binds %s to a certificate that isn't one of Issuers", redacted(u))
		}
	}
	return nil
}

// validateIssuerNames refuses two cfg.Issuers by the same name with
// different keys, unless cfg.AllowSameNameIssuers is set.
func validateIssuerNames(cfg RefresherConfig) error {
	if cfg.AllowSameNameIssuers {
		return nil
	}
	for i, issuer := range cfg.Issuers {
		for _, earlier := range cfg.Issuers[:i] {
			if bytes.Equal(issuer.RawSubject, earlier.RawSubject) && !bytes.Equal(issuer.RawSubjectPublicKeyInfo, earlier.RawSubjectPublicKeyInfo) {
				return fmt.Errorf("certrevocation: RefresherConfig.Issuers[%d] has the name of an earlier issuer, %q, with another key; set AllowSameNameIssuers if that's intended", i, issuer.Subject)
			}
		}
	}
	return nil
}

// refresherClient is the client cfg asks for, with the redirect policy
// and a timeout applied.
func refresherClient(cfg RefresherConfig) (http.Client, error) {
	var client http.Client
	switch {
	case cfg.HTTPClient != nil && cfg.AllowLoopback:
		return client, errors.New("certrevocation: RefresherConfig.AllowLoopback applies only to the default client, not to HTTPClient")
	case cfg.HTTPClient != nil:
		client = *cfg.HTTPClient
	default:
		tc := fapihttp.RecommendedTransportConfig()
		tc.AllowLoopbackHosts = cfg.AllowLoopback
		built, err := fapihttp.NewClient(tc)
		if err != nil {
			return client, fmt.Errorf("certrevocation: build the HTTP client: %w", err)
		}
		client = *built
	}
	if client.Timeout <= 0 {
		client.Timeout = DefaultCRLFetchTimeout
	}
	client.CheckRedirect = checkCRLRedirect
	return client, nil
}

// checkCRLRedirect follows at most MaxCRLRedirects redirects, each on
// the original host and port, over the same scheme or from http up to
// https. A distribution point moving its file behind a redirect stays
// reachable, but the configured URL can't send the fetch to another
// host: the URL list is the whole set of places this process fetches
// from.
func checkCRLRedirect(next *http.Request, via []*http.Request) error {
	first := via[0].URL
	switch {
	case len(via) > MaxCRLRedirects:
		return fmt.Errorf("more than %d redirects", MaxCRLRedirects)
	case next.URL.Host != first.Host:
		return fmt.Errorf("a redirect to another host, %s", next.URL.Redacted())
	case next.URL.Scheme != first.Scheme && next.URL.Scheme != "https":
		return fmt.Errorf("a redirect from %s to %s", first.Scheme, next.URL.Scheme)
	}
	return nil
}

// Lists returns the list held from each URL that has been fetched, in
// URLs order, for CRLs.Lists. It never fetches and never fails. A list
// past its nextUpdate is returned too, until a newer one replaces it:
// CRLs doesn't use it, so a certificate its CA issued is refused with
// ErrNoCurrentCRL, as it would be with no list at all.
func (r *Refresher) Lists(context.Context) ([]*x509.RevocationList, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lists := make([]*x509.RevocationList, 0, len(r.held))
	for _, u := range r.urls {
		if h, ok := r.held[u]; ok {
			lists = append(lists, h.list)
		}
	}
	return lists, nil
}

// Checker returns CRLs checking against r's held lists, with r's
// Issuers as its own, for a pinned certificate one of them issued.
func (r *Refresher) Checker() CRLs {
	return CRLs{Lists: r.Lists, Issuers: slices.Clone(r.issuers)}
}

// Refresh fetches every URL once, in turn, and returns the failures
// joined, each naming its URL; it never includes a response body.
//
// A fetch is a GET that must answer 2xx with a CRL no larger than
// MaxBytes, in DER or as a PEM "X509 CRL" block, whatever its Content-
// Type. Redirects are followed only on the same host (see
// RefresherConfig.HTTPClient). The list replaces the one held from
// that URL only when it is complete and direct (as CRLs requires: not
// a delta CRL, no issuing distribution point, no critical extension it
// doesn't process), has a nextUpdate, is current now (within
// CRLClockSkew), and was issued by the issuer URLIssuers binds the URL
// to or, for an unbound URL, by one of Issuers, naming the same issuer
// as the held list while that one is current. It must also not be
// older than any list accepted from its issuer — the same name and
// key — from any URL, or in Floors: its thisUpdate isn't before
// theirs, and when both carry a CRL number, its number isn't lower. That last check stops a replayed old
// list, one still inside its validity, from bringing back a
// certificate revoked since. Any failure keeps the held list, and a
// URL whose held list has passed its nextUpdate is a failure too,
// until a current one is fetched.
func (r *Refresher) Refresh(ctx context.Context) error {
	var errs []error
	r.refresh(ctx, func(_ string, err error) { errs = append(errs, err) })
	return errors.Join(errs...)
}

// refresh is Refresh, reporting each URL's failure to fail.
func (r *Refresher) refresh(ctx context.Context, fail func(url string, err error)) {
	for _, u := range r.urls {
		if err := r.refreshOne(ctx, u); err != nil {
			fail(redacted(u), fmt.Errorf("certrevocation: CRL %s: %w", redacted(u), err))
		}
	}
}

// refreshOne fetches u and keeps the list if it's acceptable, telling
// OnAccept when it is. Accepting and telling OnAccept happen together
// under acceptMu, so concurrent passes deliver lists in the order they
// were accepted — never, for one issuer, an older list after a newer
// one — while a slow OnAccept holds up only other acceptances, not
// Lists.
func (r *Refresher) refreshOne(ctx context.Context, u string) error {
	fetched, fetchErr := r.fetch(ctx, u)
	r.acceptMu.Lock()
	defer r.acceptMu.Unlock()
	if err := r.keep(u, fetched, fetchErr); err != nil {
		return err
	}
	if r.onAccept != nil {
		r.onAccept(redacted(u), fetched)
	}
	return nil
}

// keep makes fetched the list held from u if the fetch succeeded and
// it's acceptable, raising its issuer's floor, and otherwise returns
// why not.
func (r *Refresher) keep(u string, fetched *x509.RevocationList, fetchErr error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	held, holding := r.held[u]
	now := r.now()
	if fetchErr == nil {
		var k floorKey
		if k, fetchErr = r.acceptable(u, fetched, held.list, now); fetchErr == nil {
			r.held[u] = heldCRL{list: fetched, fetchedAt: now}
			r.raiseFloor(k, fetched)
			return nil
		}
	}
	if holding && !now.Before(held.list.NextUpdate) {
		return fmt.Errorf("%w; the held list expired at %s", fetchErr, held.list.NextUpdate.UTC().Format(time.RFC3339))
	}
	return fetchErr
}

// acceptable refuses list from u in place of held (nil when nothing is
// held yet) at now, and otherwise returns the floorKey of its issuer.
func (r *Refresher) acceptable(u string, list, held *x509.RevocationList, now time.Time) (floorKey, error) {
	switch {
	case !completeAndDirect(list):
		return floorKey{}, errors.New("a delta or scoped CRL (issuing distribution point), not a complete one")
	case !criticalUnderstood(list):
		return floorKey{}, errors.New("the CRL carries a critical extension this package doesn't process")
	case list.NextUpdate.IsZero():
		return floorKey{}, errors.New("the CRL has no nextUpdate")
	case notYetValid(list, now):
		return floorKey{}, fmt.Errorf("the CRL isn't valid until %s", list.ThisUpdate.UTC().Format(time.RFC3339))
	case !now.Before(list.NextUpdate):
		return floorKey{}, fmt.Errorf("the CRL expired at %s", list.NextUpdate.UTC().Format(time.RFC3339))
	}
	return r.fromRightIssuer(u, list, held, now)
}

// fromRightIssuer refuses list, at now, unless the issuer u is bound to
// signed it — or, for an unbound u, one of r's issuers did and held,
// if current, names the same — and it isn't older than r's floor for
// that issuer, by name and key. It returns that issuer's floorKey.
func (r *Refresher) fromRightIssuer(u string, list, held *x509.RevocationList, now time.Time) (floorKey, error) {
	bound := r.bound[u]
	candidates := r.issuers
	if bound != nil {
		candidates = []*x509.Certificate{bound}
	}
	signer := signerOf(list, candidates)
	switch {
	case bound != nil && signer == nil:
		return floorKey{}, errors.New("the CRL isn't signed by the issuer RefresherConfig.URLIssuers binds this URL to")
	case signer == nil:
		return floorKey{}, errors.New("the CRL isn't signed by any of the configured issuers")
	case bound == nil && held != nil && now.Before(held.NextUpdate) && !bytes.Equal(list.RawIssuer, held.RawIssuer):
		return floorKey{}, fmt.Errorf("the CRL names another issuer than the held one, current until %s", held.NextUpdate.UTC().Format(time.RFC3339))
	}
	k := floorKeyOf(signer)
	floor := r.floors[k]
	switch {
	case list.ThisUpdate.Before(floor.thisUpdate):
		return floorKey{}, fmt.Errorf("the CRL's thisUpdate %s is before that of the newest list accepted from its issuer", list.ThisUpdate.UTC().Format(time.RFC3339))
	case list.Number != nil && floor.number != nil && list.Number.Cmp(floor.number) < 0:
		return floorKey{}, fmt.Errorf("the CRL number %s is lower than that of the newest list accepted from its issuer, %s", list.Number, floor.number)
	}
	return k, nil
}

// signerOf is the one of issuers that, by name and signature, issued
// list, or nil when none did.
func signerOf(list *x509.RevocationList, issuers []*x509.Certificate) *x509.Certificate {
	for _, issuer := range issuers {
		if bytes.Equal(list.RawIssuer, issuer.RawSubject) && list.CheckSignatureFrom(issuer) == nil {
			return issuer
		}
	}
	return nil
}

// fetch GETs u and parses the CRL it answers with.
func (r *Refresher) fetch(ctx context.Context, u string) (*x509.RevocationList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, errors.New("can't build the request")
	}
	req.Header.Set("Accept", "application/pkix-crl")
	resp, err := r.client.Do(req)
	if err != nil {
		// url.Error repeats the URL, which the caller names already.
		if ue := (*url.Error)(nil); errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, r.maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the response: %w", err)
	}
	if int64(len(body)) > r.maxBytes {
		return nil, fmt.Errorf("the response exceeds %d bytes", r.maxBytes)
	}
	return parseCRL(body)
}

// parseCRL parses a DER CRL, or one PEM "X509 CRL" block.
func parseCRL(body []byte) (*x509.RevocationList, error) {
	der := body
	if trimmed := bytes.TrimSpace(body); bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		block, _ := pem.Decode(trimmed)
		if block == nil || block.Type != "X509 CRL" {
			return nil, errors.New("the response is PEM, but not an X509 CRL block")
		}
		der = block.Bytes
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse the CRL: %w", err)
	}
	return list, nil
}

// redacted is u with any password redacted, for an error.
func redacted(u string) string {
	if parsed, err := url.Parse(u); err == nil {
		return parsed.Redacted()
	}
	return u
}

// Run keeps the held lists current until ctx ends: a pass of Refresh,
// then a wait, then another. After a pass that succeeded for every
// URL, it waits until the first held list is halfway from when it was
// fetched to its nextUpdate, but no longer than MaxInterval and no
// less than a minute. Since each fetch moves that point on, the waits
// shorten as a nextUpdate nears without the CA having published a
// newer list, and never run past it unless it's under a minute away.
// After a pass that failed for any URL, it retries after a backoff
// that starts at 30 seconds and doubles up to 30 minutes, with jitter,
// or sooner if the schedule above says so. OnError hears of each
// failure. Run returns when ctx ends, and starts no goroutine of its
// own: run it with go r.Run(ctx).
func (r *Refresher) Run(ctx context.Context) {
	failures := 0
	for ctx.Err() == nil {
		failed := false
		r.refresh(ctx, func(u string, err error) {
			failed = true
			if r.onError != nil && ctx.Err() == nil {
				r.onError(u, err)
			}
		})
		delay := r.nextDelay()
		if failed {
			failures++
			delay = min(delay, retryDelay(failures, r.jitter))
		} else {
			failures = 0
		}
		if !r.wait(ctx, delay) {
			return
		}
	}
}

// nextDelay is how long Run waits after a pass, by refreshDelay.
func (r *Refresher) nextDelay() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := make([]scheduleEntry, len(r.urls))
	for i, u := range r.urls {
		if h, ok := r.held[u]; ok {
			entries[i] = scheduleEntry{held: true, fetchedAt: h.fetchedAt, nextUpdate: h.list.NextUpdate}
		}
	}
	return refreshDelay(r.now(), entries, r.maxInterval)
}

// scheduleEntry is what refreshDelay knows of one URL: whether a list
// is held, when it was fetched and its nextUpdate.
type scheduleEntry struct {
	held                  bool
	fetchedAt, nextUpdate time.Time
}

// refreshDelay is how long to wait at now before the next pass: until
// the earliest point halfway from an entry's fetchedAt to its
// nextUpdate, at once for an entry with no list held, capped at
// maxInterval and at least minRefreshInterval.
func refreshDelay(now time.Time, entries []scheduleEntry, maxInterval time.Duration) time.Duration {
	delay := maxInterval
	for _, e := range entries {
		due := now
		if e.held {
			due = e.fetchedAt.Add(e.nextUpdate.Sub(e.fetchedAt) / 2)
		}
		delay = min(delay, due.Sub(now))
	}
	return max(delay, minRefreshInterval)
}

// retryDelay is the backoff after the given number of consecutive
// failed passes: retryBase doubled per failure past the first, capped
// at retryMax, of which a random half is taken off.
func retryDelay(failures int, jitter func(time.Duration) time.Duration) time.Duration {
	delay := retryMax
	if shift := failures - 1; shift < 16 {
		delay = min(retryBase<<shift, retryMax)
	}
	half := delay / 2
	return half + jitter(half)
}

// sleep waits for d, returning false when ctx ends first.
func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

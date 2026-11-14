package mobile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// crlDistributionPoint is a "crl_distribution_points" entry: where
// RefreshCRLs fetches a CA's Certificate Revocation List from, and the
// CA's certificate, the only one whose list that URL may serve.
type crlDistributionPoint struct {
	URL string `json:"url"`
	// Issuer is the CA's certificate, PEM.
	Issuer string `json:"issuer"`
}

// crlPoint is a distribution point as RefreshCRLs uses it.
type crlPoint struct {
	url    string
	issuer *x509.Certificate
}

// crlRefreshConfig is the part of a Wallet's or ProximityReader's
// configuration RefreshCRLs reads.
type crlRefreshConfig struct {
	// points are the explicit "crl_distribution_points".
	points []crlDistributionPoint
	// fromRoots is "crl_distribution_points_from_roots", and roots the
	// PEM roots of the roles "revocation" names, with "crl_issuers",
	// whose self-signed CA certificates' distribution points it adds.
	fromRoots bool
	roots     []string
	// requireHTTPS is "crl_require_https", development the
	// configuration's "development".
	requireHTTPS, development bool
	// http, set in development for "development_roots", is the client
	// the lists are fetched with, trusting those roots beside the
	// system's (developmentClient), as the configuration's other
	// requests do; nil fetches with certrevocation's own client, from
	// public addresses only outside development.
	http *http.Client
	// privateHosts is the Wallet's "allowed_private_hosts": hosts whose
	// private addresses certrevocation's own client may dial.
	privateHosts []string
}

// crlHTTP is the client RefreshCRLs fetches with for a configuration
// with developmentRoots, its "development_roots", in development: one
// trusting them, as the wallet's other requests do in development
// (developmentClient). nil, for certrevocation's own client, without
// them; outside development they're refused, as the wallet refuses them.
func crlHTTP(development bool, developmentRoots string) (*http.Client, error) {
	if developmentRoots == "" {
		return nil, nil
	}
	if !development {
		return nil, newError(CodeInvalidInput, errors.New("development_roots needs development"))
	}
	client, err := developmentClient(developmentRoots)
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("development_roots: %w", err))
	}
	return client, nil
}

// Bounds of the schedule RefreshCRLs reports in next_refresh.
const (
	// crlMinRefresh is the soonest a list RefreshCRLs just accepted is
	// due again, so a list close to its nextUpdate isn't fetched in a
	// tight loop (certrevocation.Refresher's own floor).
	crlMinRefresh = time.Minute
	// crlRetryBase and crlRetryMax bound the backoff of a distribution
	// point a refresh failed for: it doubles from crlRetryBase per
	// consecutive failure, up to crlRetryMax, and a random half is taken
	// off, so a fleet that failed together during an outage doesn't
	// retry together after it.
	crlRetryBase = 5 * time.Minute
	crlRetryMax  = time.Hour
)

// configureRefresh sets the distribution points s.refresh fetches, from
// cfg, refusing a malformed one as invalid_input.
func (s *crlSet) configureRefresh(cfg crlRefreshConfig) error {
	var points []crlPoint
	for i, p := range cfg.points {
		issuers, err := parseCRLIssuers(p.Issuer)
		switch {
		case err != nil:
			return newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points[%d].issuer: %w", i, err))
		case len(issuers) != 1:
			return newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points[%d].issuer: want one CA certificate, got %d", i, len(issuers)))
		case !fetchableURL(p.URL, cfg.requireHTTPS):
			return newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points[%d].url isn't an %s URL", i, map[bool]string{false: "http or https", true: "https"}[cfg.requireHTTPS]))
		case slices.ContainsFunc(points, func(q crlPoint) bool { return q.url == p.URL }):
			return newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points[%d] repeats %s", i, redactedURL(p.URL)))
		}
		points = append(points, crlPoint{url: p.URL, issuer: issuers[0]})
	}
	if cfg.fromRoots {
		var err error
		if points, err = pointsFromRoots(points, cfg.roots, cfg.requireHTTPS); err != nil {
			return err
		}
	}
	if len(points) > maxCRLs {
		return newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points: more than %d", maxCRLs))
	}
	s.points, s.refreshCfg = points, cfg
	s.learn(knownCAs(points, cfg.roots))
	return nil
}

// knownCAs are the CA certificates of points, the distribution points'
// issuers, and among roots, the PEM roots of the roles "revocation"
// names: the CAs whose lists a crlSet verifies before holding them
// (crlSet.known).
func knownCAs(points []crlPoint, roots []string) []*x509.Certificate {
	var cas []*x509.Certificate
	for _, p := range points {
		cas = append(cas, p.issuer)
	}
	for _, pemText := range roots {
		for _, cert := range parseCertificates(pemCertificates(pemText)) {
			if cert.BasicConstraintsValid && cert.IsCA {
				cas = append(cas, cert)
			}
		}
	}
	return cas
}

// pointsFromRoots adds to points, the explicit ones, the http and https
// CRL distribution points of each self-signed CA certificate in roots:
// such a CA signs the list covering what it issued at the point its own
// certificate names, as an IACA's does (ISO/IEC 18013-5 Annex B.1).
// With requireHTTPS, only the https ones. An explicit entry for the URL
// wins; two roots naming one URL are refused, to be bound explicitly.
func pointsFromRoots(points []crlPoint, roots []string, requireHTTPS bool) ([]crlPoint, error) {
	explicit := len(points)
	for _, pemText := range roots {
		for _, cert := range parseCertificates(pemCertificates(pemText)) {
			if !cert.BasicConstraintsValid || !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) || cert.CheckSignatureFrom(cert) != nil {
				continue
			}
			for _, u := range cert.CRLDistributionPoints {
				if !fetchableURL(u, requireHTTPS) {
					continue
				}
				i := slices.IndexFunc(points, func(p crlPoint) bool { return p.url == u })
				switch {
				case i < 0:
					points = append(points, crlPoint{url: u, issuer: cert})
				case i >= explicit && !points[i].issuer.Equal(cert):
					return nil, newError(CodeInvalidInput, fmt.Errorf("crl_distribution_points_from_roots: two roots, %q and %q, name %s: bind it in crl_distribution_points", points[i].issuer.Subject, cert.Subject, redactedURL(u)))
				}
			}
		}
	}
	return points, nil
}

// fetchableURL reports whether u is an absolute http or https URL with
// a host, as certrevocation.Refresher fetches: https only, with
// requireHTTPS.
func fetchableURL(u string, requireHTTPS bool) bool {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && !requireHTTPS)
}

// refresher is a certrevocation.Refresher fetching p alone, bound to
// its issuer, with floors as the lists it may not be older than,
// fetching with client: it caps the response's size and follows
// redirects only on p's host.
func (p crlPoint) refresher(cfg crlRefreshConfig, client *http.Client, floors []*x509.RevocationList, now func() time.Time) (*certrevocation.Refresher, error) {
	return certrevocation.NewRefresher(certrevocation.RefresherConfig{
		URLs:         []string{p.url},
		Issuers:      []*x509.Certificate{p.issuer},
		URLIssuers:   map[string]*x509.Certificate{p.url: p.issuer},
		RequireHTTPS: cfg.requireHTTPS,
		HTTPClient:   client,
		Floors:       floors,
		Clock:        now,
	})
}

// refreshClient is the client cfg's lists are fetched with: with
// development_roots, in development, cfg.http, which trusts them;
// otherwise the hardened client certrevocation.Refresher builds by
// default, dialling public addresses only outside development, and the
// private ones of cfg.privateHosts.
func refreshClient(cfg crlRefreshConfig) (*http.Client, error) {
	if cfg.http != nil {
		return cfg.http, nil
	}
	tc := fapihttp.RecommendedTransportConfig()
	tc.AllowLoopbackHosts = cfg.development
	tc.AllowedPrivateHosts = cfg.privateHosts
	return fapihttp.NewClient(tc)
}

// pointRefreshers returns s's points' Refreshers, building them the
// first time, with the lists held then as their floors.
func (s *crlSet) pointRefreshers(now func() time.Time) ([]*certrevocation.Refresher, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	if s.refreshers != nil {
		return s.refreshers, nil
	}
	client, err := refreshClient(s.refreshCfg)
	if err != nil {
		return nil, fmt.Errorf("certrevocation: build the HTTP client: %w", err)
	}
	var floors []*x509.RevocationList
	if held := s.lists.Load(); held != nil {
		floors = *held
	}
	refreshers := make([]*certrevocation.Refresher, len(s.points))
	for i, p := range s.points {
		if refreshers[i], err = p.refresher(s.refreshCfg, client, floors, now); err != nil {
			return nil, err
		}
	}
	s.refreshers, s.failures = refreshers, make([]int, len(s.points))
	return refreshers, nil
}

// CRL refresh outcomes, a crlRefreshResult's "outcome".
const (
	crlUpdated   = "updated"
	crlUnchanged = "unchanged"
	crlFailed    = "failed"
)

// crlRefreshResult is one distribution point's outcome.
type crlRefreshResult struct {
	URL     string `json:"url"`
	Outcome string `json:"outcome"`
	// Error is a failure's "[code] message" text.
	Error string `json:"error,omitempty"`
}

// crlRefreshJSON is RefreshCRLs' result.
type crlRefreshJSON struct {
	result
	Results     []crlRefreshResult `json:"results"`
	CRLs        string             `json:"crls"`
	NextRefresh string             `json:"next_refresh"`
}

// refresh fetches each of s's distribution points once, keeping each
// list fetched that its CA signed, is current and isn't older than the
// one held for its CA, and returns the outcome as RefreshCRLs' JSON. A
// failure keeps the list held. It returns an error only when nothing
// is configured to fetch, or ctx was cancelled.
func (s *crlSet) refresh(ctx context.Context) (string, error) {
	if len(s.points) == 0 {
		return "", &Error{Code: CodeInvalidInput, Detail: DetailNotConfigured, Message: "no CRL distribution points are configured: set crl_distribution_points or crl_distribution_points_from_roots"}
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	out := crlRefreshJSON{result: result{ABIVersion}, Results: make([]crlRefreshResult, 0, len(s.points))}
	refreshers, err := s.pointRefreshers(now)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	var next time.Time
	for i, p := range s.points {
		res := crlRefreshResult{URL: redactedURL(p.url)}
		list, err := fetchOne(ctx, refreshers[i])
		if err == nil {
			var changed bool
			if changed, err = s.merge(list); err == nil {
				res.Outcome = crlUnchanged
				if changed {
					res.Outcome = crlUpdated
				}
			}
		}
		var due time.Time
		if err != nil {
			res.Outcome, res.Error = crlFailed, crlError(err).Error()
			due = s.retryDue(now(), i, p)
		} else {
			due = s.refreshedDue(now(), i, list.NextUpdate)
		}
		if next.IsZero() || due.Before(next) {
			next = due
		}
		out.Results = append(out.Results, res)
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "", newError(CodeCancelled, errors.New("cancelled"))
	}
	out.CRLs = s.pem()
	out.NextRefresh = next.UTC().Format(time.RFC3339)
	return marshal(out)
}

// refreshedDue is when point i, whose list just fetched at now is
// current until nextUpdate, is due again: halfway there, no later than
// certrevocation.DefaultCRLMaxInterval, which certrevocation.Refresher's
// Run waits by too, so a revocation the CA publishes is picked up
// within it; less a random part of up to a fifth, so devices that
// fetched together, or whose lists share a nextUpdate, don't fetch
// together again; and no sooner than crlMinRefresh. It ends the point's
// backoff.
func (s *crlSet) refreshedDue(now time.Time, i int, nextUpdate time.Time) time.Time {
	s.refreshMu.Lock()
	s.failures[i] = 0
	s.refreshMu.Unlock()
	d := min(nextUpdate.Sub(now)/2, certrevocation.DefaultCRLMaxInterval)
	if d > 0 {
		d -= s.random(d / 5)
	}
	return now.Add(max(d, crlMinRefresh))
}

// retryDue is when point i, p, a fetch just failed for at now, is due
// again: after a backoff growing with its consecutive failures (see
// crlRetryBase), but no later than halfway to the nextUpdate of the
// list held for p's CA while that's current, so it's tried again
// before the list expires.
func (s *crlSet) retryDue(now time.Time, i int, p crlPoint) time.Time {
	s.refreshMu.Lock()
	s.failures[i]++
	failures := s.failures[i]
	s.refreshMu.Unlock()
	d := crlRetryMax
	if shift := failures - 1; shift < 16 {
		d = min(crlRetryBase<<shift, crlRetryMax)
	}
	d = d/2 + s.random(d/2)
	if held := s.heldFrom(p.issuer); held != nil && now.Before(held.NextUpdate) {
		d = min(d, max(held.NextUpdate.Sub(now)/2, crlMinRefresh))
	}
	return now.Add(d)
}

// heldFrom is the list s holds that issuer signed, or nil.
func (s *crlSet) heldFrom(issuer *x509.Certificate) *x509.RevocationList {
	p := s.lists.Load()
	if p == nil {
		return nil
	}
	for _, l := range *p {
		if bytes.Equal(l.RawIssuer, issuer.RawSubject) && l.CheckSignatureFrom(issuer) == nil {
			return l
		}
	}
	return nil
}

// random is a random duration in [0, n), by s.jitter; zero for n ≤ 0.
func (s *crlSet) random(n time.Duration) time.Duration {
	switch {
	case n <= 0:
		return 0
	case s.jitter != nil:
		return s.jitter(n)
	}
	return rand.N(n) //nolint:gosec // schedule jitter, not a secret
}

// fetchOne fetches with r, a point's Refresher, and returns the list
// if r accepted it.
func fetchOne(ctx context.Context, r *certrevocation.Refresher) (*x509.RevocationList, error) {
	if err := r.Refresh(ctx); err != nil {
		return nil, err
	}
	lists, _ := r.Lists(ctx)
	if len(lists) != 1 {
		return nil, errors.New("certrevocation: no list held after a refresh")
	}
	return lists[0], nil
}

// merge makes list, which its distribution point's CA signed, the one
// s holds for its CA, in place of any held, unless it's older than one
// held that the same CA's key signed (as set refuses), and reports
// whether the lists changed: false when list is the one held already. A
// list held for the CA that it didn't sign is replaced, never a floor.
func (s *crlSet) merge(list *x509.RevocationList) (bool, error) {
	signer, err := s.signer(list)
	switch {
	case err != nil:
		return false, err
	case signer == nil:
		return false, errors.New("the CRL isn't signed by a CA the configuration has")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var held []*x509.RevocationList
	if p := s.lists.Load(); p != nil {
		held = *p
	}
	next := make([]*x509.RevocationList, 0, len(held)+1)
	for _, h := range held {
		if !sameCRLIssuer(list, h) {
			next = append(next, h)
			continue
		}
		hs, _ := s.signer(h)
		switch {
		case bytes.Equal(list.Raw, h.Raw):
			return false, nil
		case hs != nil && sameKey(signer, hs) && olderCRL(list, h):
			return false, fmt.Errorf("the CRL is older than the one held for its CA, %q", h.Issuer)
		}
	}
	if next = append(next, list); len(next) > maxCRLs {
		return false, fmt.Errorf("more than %d CRLs", maxCRLs)
	}
	s.lists.Store(&next)
	return true, nil
}

// pem is s's lists, as PEM X509 CRL blocks: what SetCRLs or "crls"
// take back.
func (s *crlSet) pem() string {
	p := s.lists.Load()
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, l := range *p {
		_ = pem.Encode(&b, &pem.Block{Type: "X509 CRL", Bytes: l.Raw})
	}
	return b.String()
}

// crlError is err, one distribution point's failure, as an Error: a
// cancelled or network failure as such (a host on a non-public
// address, outside development, too), anything else, a list refused
// or an HTTP error status, protocol. Its message never carries a
// response body (certrevocation's errors don't).
func crlError(err error) *Error {
	var netErr net.Error
	code := CodeProtocol
	switch {
	case errors.Is(err, context.Canceled):
		code = CodeCancelled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, fapihttp.ErrSSRFBlocked), errors.As(err, &netErr):
		// Unreachable, as an address outside the public internet is
		// outside development.
		code = CodeNetwork
	}
	return &Error{Code: code, Message: cleanText(err.Error())}
}

// redactedURL is u with any password redacted.
func redactedURL(u string) string {
	if parsed, err := url.Parse(u); err == nil {
		return parsed.Redacted()
	}
	return u
}

package androidkey

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"
)

// DefaultStatusURL is where Google publishes its attestation status
// list.
const DefaultStatusURL = "https://android.googleapis.com/attestation/status"

// Defaults for StatusSource's zero values.
const (
	// DefaultStatusMaxAge is how long a fetched list is used: Google
	// serves it with max-age=86400.
	DefaultStatusMaxAge = 24 * time.Hour
	// DefaultStatusRetryAfter is how long a failed fetch is remembered
	// before the next one is tried.
	DefaultStatusRetryAfter = time.Minute
	// DefaultStatusMaxBytes bounds the list's size. Google's was about
	// 180 KB in November 2026.
	DefaultStatusMaxBytes = 4 << 20
	// DefaultStatusFetchTimeout bounds one fetch, redirects included.
	DefaultStatusFetchTimeout = 30 * time.Second
)

// StatusSource fetches Google's attestation status list and caches it:
// Current returns the held list while it is younger than MaxAge, and
// otherwise fetches a new one, so a Verifier using it fetches at most
// once per MaxAge. A list older than MaxAge is never returned, so when
// fetching fails Current fails too — and a Verifier that requires
// revocation refuses, with ErrStatusUnavailable — until a fetch
// succeeds. A failed fetch isn't retried for RetryAfter.
//
// Fetches go through fapihttp's hardened client: https only, public
// addresses only, at most two same-origin redirects, a bounded body
// of type application/json. A StatusSource is safe for concurrent use;
// concurrent calls share one fetch. Don't copy one after first use.
type StatusSource struct {
	// URL is the list's location; empty means DefaultStatusURL.
	URL string
	// HTTP is the transport fetches use; nil means one built by
	// fapihttp.NewClient(fapihttp.RecommendedTransportConfig()). Build
	// any other with fapihttp.NewClient too: it's what keeps a fetch to
	// public addresses.
	HTTP *http.Client
	// AllowLoopback permits a loopback URL, for tests and local
	// development only. It doesn't change HTTP's own transport.
	AllowLoopback bool
	// MaxAge is how long a fetched list is used; zero means
	// DefaultStatusMaxAge.
	MaxAge time.Duration
	// RetryAfter is how long a failed fetch is remembered; zero means
	// DefaultStatusRetryAfter.
	RetryAfter time.Duration
	// MaxBytes bounds the list's size; zero means DefaultStatusMaxBytes.
	MaxBytes int64
	// Now is the clock; nil means time.Now.
	Now func() time.Time

	mu        sync.Mutex
	client    *fapihttp.Client
	list      *StatusList
	fetchedAt time.Time
	failedAt  time.Time
	failure   error
}

// Current returns the held list if it's younger than MaxAge, and
// otherwise fetches one. Its errors wrap ErrStatusUnavailable.
func (s *StatusSource) Current(ctx context.Context) (*StatusList, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if s.list != nil && now.Sub(s.fetchedAt) < orDefault(s.MaxAge, DefaultStatusMaxAge) {
		return s.list, nil
	}
	if s.failure != nil && now.Sub(s.failedAt) < orDefault(s.RetryAfter, DefaultStatusRetryAfter) {
		return nil, s.failure
	}
	if err := s.refreshLocked(ctx); err != nil {
		return nil, err
	}
	return s.list, nil
}

// Refresh fetches the list now, whatever is held. On failure the held
// list, if any, is kept until it ages out. Its errors wrap
// ErrStatusUnavailable.
func (s *StatusSource) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshLocked(ctx)
}

// Set replaces the held list with list, as fetched at fetchedAt: one
// persisted across a restart, say. It is used until it is MaxAge old.
func (s *StatusSource) Set(list *StatusList, fetchedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list, s.fetchedAt, s.failure = list, fetchedAt, nil
}

func (s *StatusSource) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// refreshLocked fetches and parses the list. Callers hold s.mu.
func (s *StatusSource) refreshLocked(ctx context.Context) error {
	list, err := s.fetch(ctx)
	if err != nil {
		s.failure = fmt.Errorf("%w: %w", ErrStatusUnavailable, err)
		s.failedAt = s.now()
		return s.failure
	}
	s.list, s.fetchedAt, s.failure = list, s.now(), nil
	return nil
}

func (s *StatusSource) fetch(ctx context.Context) (*StatusList, error) {
	raw := s.URL
	if raw == "" {
		raw = DefaultStatusURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("status list URL %q isn't an https URL", raw)
	}
	client, err := s.fetcher()
	if err != nil {
		return nil, err
	}
	resp, err := client.Fetch(ctx, fapihttp.FetchRequest{URL: u, Accept: "application/json", ExpectedContentType: "application/json"})
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", u.Redacted(), err)
	}
	return ParseStatusList(resp.Body)
}

// fetcher builds the hardened client on first use. Callers hold s.mu.
func (s *StatusSource) fetcher() (*fapihttp.Client, error) {
	if s.client != nil {
		return s.client, nil
	}
	transport := s.HTTP
	if transport == nil {
		tc := fapihttp.RecommendedTransportConfig()
		tc.AllowLoopbackHosts = s.AllowLoopback
		built, err := fapihttp.NewClient(tc)
		if err != nil {
			return nil, err
		}
		transport = built
	}
	maxBytes := s.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultStatusMaxBytes
	}
	client, err := fapihttp.New(transport, fapihttp.Config{
		MaxResponseBytes:   maxBytes,
		RequestTimeout:     DefaultStatusFetchTimeout,
		MaxRedirects:       2,
		AllowLoopbackHosts: s.AllowLoopback,
	})
	if err != nil {
		return nil, err
	}
	s.client = client
	return client, nil
}

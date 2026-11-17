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
	// DefaultStatusMaxAge is how long a fetched list is current: Google
	// serves it with max-age=86400.
	DefaultStatusMaxAge = 24 * time.Hour
	// DefaultStatusGrace is how long past MaxAge the last list fetched
	// is still used while no newer one can be: Google's list changes
	// about daily, so a list a few hours past its max-age is very
	// nearly current.
	DefaultStatusGrace = 12 * time.Hour
	// DefaultStatusRetryAfter is how long a failed fetch is remembered
	// before the next one is tried.
	DefaultStatusRetryAfter = time.Minute
	// DefaultStatusMaxBytes bounds the list's size. Google's was about
	// 180 KB in November 2026.
	DefaultStatusMaxBytes = 4 << 20
	// DefaultStatusFetchTimeout bounds one fetch, redirects included.
	DefaultStatusFetchTimeout = 30 * time.Second
)

// StatusSource fetches Google's attestation status list and caches it.
// Current returns the held list while it is younger than MaxAge; from
// three quarters of MaxAge on, it also starts fetching a newer one in
// the background, so callers needn't wait for it. Should fetching fail,
// the last list fetched is used for Grace past MaxAge; after that, or
// with no list held at all, Current fetches one, and fails — a Verifier
// that requires revocation then refuses with ErrStatusUnavailable —
// until a fetch succeeds. A failed fetch isn't retried for RetryAfter.
//
// A fetch is never cut short by the context of the call that started
// it: it runs on its own, bounded by DefaultStatusFetchTimeout, and
// each caller waiting for it stops waiting when its own context ends,
// without the fetch's result, or anyone else's, depending on it. So
// one caller giving up — a client hanging up mid-request — neither
// fails the fetch for the others nor leaves a failure cached.
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
	// MaxAge is how long a fetched list is current; zero means
	// DefaultStatusMaxAge.
	MaxAge time.Duration
	// Grace is how long past MaxAge the last list fetched is still used
	// while no newer one can be fetched; zero means DefaultStatusGrace,
	// and a negative Grace none: a list is then never used past MaxAge.
	// A certificate Google lists in that time is found only once a
	// fetch succeeds, so keep it short of a day.
	Grace time.Duration
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
	flight    *statusFetch // the fetch under way, if any
}

// statusFetch is one fetch, shared by the callers waiting for it: done
// is closed once list and err hold its outcome — err its failure, if it
// failed, and list the list Current then answers with: the one fetched,
// or the last one, within Grace, when the fetch failed.
type statusFetch struct {
	done chan struct{}
	list *StatusList
	err  error
}

// Current returns the held list if it's younger than MaxAge, or, while
// fetching a newer one fails, younger than MaxAge plus Grace; otherwise
// it waits, at most until ctx ends, for a fetch. Its errors wrap
// ErrStatusUnavailable.
func (s *StatusSource) Current(ctx context.Context) (*StatusList, error) {
	s.mu.Lock()
	list, f, err := s.currentLocked(ctx)
	s.mu.Unlock()
	if f == nil {
		return list, err
	}
	if list, err = wait(ctx, f); list != nil {
		return list, nil
	}
	return nil, err
}

// currentLocked returns the list to use, or the failure to report, or
// the fetch to wait for. Callers hold s.mu.
func (s *StatusSource) currentLocked(ctx context.Context) (*StatusList, *statusFetch, error) {
	now := s.now()
	maxAge := s.maxAge()
	retrying := s.failure != nil && now.Sub(s.failedAt) < orDefault(s.RetryAfter, DefaultStatusRetryAfter)
	age := now.Sub(s.fetchedAt)
	if s.list == nil || age >= maxAge+s.grace() {
		if retrying {
			return nil, nil, s.failure
		}
		return nil, s.startLocked(ctx), nil
	}
	if age >= maxAge-maxAge/4 && !retrying {
		s.startLocked(ctx) // ahead of expiry, in the background
	}
	if age >= maxAge && s.failure == nil {
		// Past MaxAge with no fetch failed yet: wait for the one under
		// way, which answers with this list if it fails.
		return nil, s.startLocked(ctx), nil
	}
	return s.list, nil, nil
}

// Refresh fetches the list now, whatever is held, waiting at most until
// ctx ends; a fetch already under way is waited for instead. On
// failure the held list, if any, is kept, and used until it's MaxAge
// plus Grace old. Its errors wrap ErrStatusUnavailable.
func (s *StatusSource) Refresh(ctx context.Context) error {
	s.mu.Lock()
	f := s.startLocked(ctx)
	s.mu.Unlock()
	_, err := wait(ctx, f)
	return err
}

// Set replaces the held list with list, as fetched at fetchedAt: one
// persisted across a restart, say. It is used until it is MaxAge old,
// or MaxAge plus Grace while fetching a newer one fails.
func (s *StatusSource) Set(list *StatusList, fetchedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list, s.fetchedAt, s.failure = list, fetchedAt, nil
}

// wait waits for f, or for ctx to end.
func wait(ctx context.Context, f *statusFetch) (*StatusList, error) {
	select {
	case <-f.done:
		return f.list, f.err
	case <-ctx.Done():
		return nil, fmt.Errorf("%w: waiting for the list: %w", ErrStatusUnavailable, ctx.Err())
	}
}

// startLocked returns the fetch under way, starting one if there's
// none. The fetch runs without ctx's cancellation, bounded by
// DefaultStatusFetchTimeout. Callers hold s.mu.
func (s *StatusSource) startLocked(ctx context.Context) *statusFetch {
	if s.flight != nil {
		return s.flight
	}
	f := &statusFetch{done: make(chan struct{})}
	s.flight = f
	go s.run(context.WithoutCancel(ctx), f)
	return f
}

// run fetches the list for f and records the outcome: the list, or a
// failure remembered for RetryAfter.
func (s *StatusSource) run(ctx context.Context, f *statusFetch) {
	ctx, cancel := context.WithTimeout(ctx, DefaultStatusFetchTimeout)
	defer cancel()
	list, err := s.fetch(ctx)
	s.mu.Lock()
	now := s.now()
	if err == nil {
		s.list, s.fetchedAt, s.failure = list, now, nil
		f.list = list
	} else {
		s.failure, s.failedAt = fmt.Errorf("%w: %w", ErrStatusUnavailable, err), now
		f.err = s.failure
		if s.list != nil && now.Sub(s.fetchedAt) < s.maxAge()+s.grace() {
			f.list = s.list // within Grace, as Current now answers
		}
	}
	s.flight = nil
	s.mu.Unlock()
	close(f.done)
}

func (s *StatusSource) maxAge() time.Duration { return orDefault(s.MaxAge, DefaultStatusMaxAge) }

func (s *StatusSource) grace() time.Duration {
	switch {
	case s.Grace < 0:
		return 0
	case s.Grace == 0:
		return DefaultStatusGrace
	}
	return s.Grace
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

// fetcher builds the hardened client on first use.
func (s *StatusSource) fetcher() (*fapihttp.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

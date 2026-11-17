package androidkey_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// statusServer serves body as the status list, counting requests; set
// fail to answer 500 instead. With gated set, each request waits for a
// value on release first, after announcing itself on arrived.
type statusServer struct {
	*httptest.Server
	requests    atomic.Int32
	fail        atomic.Bool
	contentType string
	body        []byte

	gated   bool
	arrived chan struct{}
	release chan struct{}
}

func newStatusServer(t *testing.T) *statusServer {
	return newStatusServerGated(t, false)
}

// newGatedStatusServer is a statusServer whose answers wait for
// release.
func newGatedStatusServer(t *testing.T) *statusServer {
	return newStatusServerGated(t, true)
}

func newStatusServerGated(t *testing.T, gated bool) *statusServer {
	body, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &statusServer{
		contentType: "application/json; charset=utf-8", body: body,
		gated: gated, arrived: make(chan struct{}, 16), release: make(chan struct{}, 16),
	}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if s.gated {
			s.arrived <- struct{}{}
			select {
			case <-s.release:
			case <-r.Context().Done():
				return
			}
		}
		if s.fail.Load() || r.URL.Path != "/attestation/status" {
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", s.contentType)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.Close)
	return s
}

// testClock is a clock the test moves, safe to read from the source's
// fetches.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// source is a StatusSource for s, on clock.
func (s *statusServer) source(t *testing.T, clock *testClock) *androidkey.StatusSource {
	pool := x509.NewCertPool()
	pool.AddCert(s.Certificate())
	tc := fapihttp.RecommendedTransportConfig()
	tc.RootCAs, tc.AllowLoopbackHosts = pool, true
	transport, err := fapihttp.NewClient(tc)
	if err != nil {
		t.Fatal(err)
	}
	return &androidkey.StatusSource{
		URL: s.URL + "/attestation/status", HTTP: transport, AllowLoopback: true,
		Now: clock.now,
	}
}

var statusEpoch = time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)

// TestStatusSource_Caches: a list is fetched once and used for MaxAge,
// a newer one fetched from three quarters of MaxAge on; a failed fetch
// isn't retried for RetryAfter, and the last list is used for Grace
// past MaxAge while fetches fail, and never after.
func TestStatusSource_Caches(t *testing.T) {
	srv := newStatusServer(t)
	clock := &testClock{t: statusEpoch}
	src := srv.source(t, clock)
	ctx := context.Background()
	maxAge, grace, retry := androidkey.DefaultStatusMaxAge, androidkey.DefaultStatusGrace, androidkey.DefaultStatusRetryAfter
	expect := func(when string, wantErr bool, requests int32) {
		t.Helper()
		l, err := src.Current(ctx)
		if wantErr != (err != nil) || (err != nil && !errors.Is(err, androidkey.ErrStatusUnavailable)) || (err == nil && l.Len() != 4) {
			t.Fatalf("%s: %v, %v", when, l, err)
		}
		if n := srv.requests.Load(); n != requests {
			t.Fatalf("%s: %d requests, want %d", when, n, requests)
		}
	}

	expect("first Current", false, 1)
	clock.set(statusEpoch.Add(maxAge / 2))
	expect("within three quarters of MaxAge", false, 1)
	// From three quarters of MaxAge, a fetch starts in the background;
	// past MaxAge, Current waits for it.
	clock.set(statusEpoch.Add(maxAge * 3 / 4))
	if _, err := src.Current(ctx); err != nil {
		t.Fatal(err)
	}
	clock.set(statusEpoch.Add(maxAge))
	expect("at MaxAge, refreshed ahead", false, 2)

	// fetchedAt is now somewhere in [3/4 MaxAge, MaxAge]: from here on,
	// the list ages from base.
	base := statusEpoch.Add(maxAge)
	if err := src.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	clock.set(base.Add(maxAge))
	expect("server failing, list past MaxAge", false, 4)
	clock.set(base.Add(maxAge + retry/2))
	expect("within RetryAfter, within Grace", false, 4)
	clock.set(base.Add(maxAge + grace))
	expect("past MaxAge and Grace", true, 5)
	clock.set(base.Add(maxAge + grace + retry/2))
	expect("within RetryAfter, no list", true, 5)
	srv.fail.Store(false)
	clock.set(base.Add(maxAge + grace + retry))
	expect("after RetryAfter", false, 6)

	// Refresh fetches whatever is held; a failed one keeps the held list.
	srv.fail.Store(true)
	if err := src.Refresh(ctx); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("failed Refresh: %v", err)
	}
	expect("after a failed Refresh, the held list", false, 7)
}

// TestStatusSource_CancelledCallerDoesntPoison: the caller whose call
// started a fetch hanging up neither cuts the fetch short nor leaves a
// failure for the others: the next caller gets the list that fetch
// fetched.
func TestStatusSource_CancelledCallerDoesntPoison(t *testing.T) {
	srv := newGatedStatusServer(t)
	src := srv.source(t, &testClock{t: statusEpoch})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := src.Current(ctx)
		done <- err
	}()
	<-srv.arrived
	cancel()
	if err := <-done; !errors.Is(err, androidkey.ErrStatusUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("the cancelled caller: %v, want ErrStatusUnavailable for its own context", err)
	}
	srv.release <- struct{}{}
	if l, err := src.Current(context.Background()); err != nil || l.Len() != 4 {
		t.Fatalf("the next caller: %v, %v", l, err)
	}
	if n := srv.requests.Load(); n != 1 {
		t.Fatalf("%d requests, want the one fetch", n)
	}
}

// TestStatusSource_WaiterHonoursItsContext: a caller waiting for
// another's fetch stops when its own context ends, not when the fetch
// does.
func TestStatusSource_WaiterHonoursItsContext(t *testing.T) {
	srv := newGatedStatusServer(t)
	src := srv.source(t, &testClock{t: statusEpoch})
	first := make(chan error)
	go func() {
		_, err := src.Current(context.Background())
		first <- err
	}()
	<-srv.arrived
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src.Current(ctx); !errors.Is(err, androidkey.ErrStatusUnavailable) || !errors.Is(err, context.Canceled) {
		t.Fatalf("a caller whose context ended: %v", err)
	}
	srv.release <- struct{}{}
	if err := <-first; err != nil {
		t.Fatalf("the fetch's own caller: %v", err)
	}
}

// TestStatusSource_NoGrace: with a negative Grace, a list is never used
// past MaxAge.
func TestStatusSource_NoGrace(t *testing.T) {
	srv := newStatusServer(t)
	clock := &testClock{t: statusEpoch}
	src := srv.source(t, clock)
	src.Grace = -1
	if _, err := src.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	clock.set(statusEpoch.Add(androidkey.DefaultStatusMaxAge))
	if _, err := src.Current(context.Background()); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("past MaxAge without Grace: %v", err)
	}
}

// TestStatusSource_RetryAfter: a failure says when the next fetch is
// tried, which walletprovider's Handler answers as Retry-After: all of
// RetryAfter from the failed fetch, the rest of it while the failure is
// remembered.
func TestStatusSource_RetryAfter(t *testing.T) {
	srv := newStatusServer(t)
	srv.fail.Store(true)
	clock := &testClock{t: statusEpoch}
	src := srv.source(t, clock)
	src.RetryAfter = 2 * time.Minute
	retryAfter := func() time.Duration {
		t.Helper()
		_, err := src.Current(context.Background())
		var hint interface{ RetryAfter() time.Duration }
		if !errors.Is(err, androidkey.ErrStatusUnavailable) || !errors.As(err, &hint) {
			t.Fatalf("Current = %v, want ErrStatusUnavailable saying when to retry", err)
		}
		return hint.RetryAfter()
	}
	if got := retryAfter(); got != 2*time.Minute {
		t.Fatalf("the failed fetch says retry after %v, want 2m", got)
	}
	clock.set(statusEpoch.Add(90 * time.Second))
	if got := retryAfter(); got != 30*time.Second {
		t.Fatalf("the remembered failure says retry after %v, want 30s", got)
	}
}

// TestStatusSource_Verify: a Verifier with a StatusSource checks the
// chain against the fetched list, and refuses while none is current.
func TestStatusSource_Verify(t *testing.T) {
	srv := newStatusServer(t)
	now := time.Now()
	clock := &testClock{t: now}
	src := srv.source(t, clock)
	c := newChain(t, goodSpec(t), chainOpts{serials: [3]int64{0, 0xf00d, 0}})
	v := verifierFor(t, c)
	v.Revocation = src
	ctx := context.Background()
	if _, err := v.Verify(ctx, c.der, testChallenge); !errors.Is(err, androidkey.ErrRevoked) {
		t.Fatalf("revoked intermediate: %v", err)
	}
	good := newChain(t, goodSpec(t), chainOpts{})
	v = verifierFor(t, good)
	v.Revocation = src
	if r, err := v.Verify(ctx, good.der, testChallenge); err != nil || !r.RevocationChecked {
		t.Fatalf("good chain: %v", err)
	}
	srv.fail.Store(true)
	clock.set(now.Add(androidkey.DefaultStatusMaxAge + androidkey.DefaultStatusGrace + time.Hour))
	v.Now = time.Now
	_, err := v.Verify(ctx, good.der, testChallenge)
	var hint interface{ RetryAfter() time.Duration }
	if !errors.Is(err, androidkey.ErrStatusUnavailable) || !errors.As(err, &hint) {
		t.Fatalf("no current list: %v, want ErrStatusUnavailable saying when to retry", err)
	}
	v.RevocationOptional = true
	if r, err := v.Verify(ctx, good.der, testChallenge); err != nil || r.RevocationChecked {
		t.Fatalf("no current list, optional: %+v, %v", r, err)
	}
}

// TestStatusSource_Refuses: fetches that don't give a list fail.
func TestStatusSource_Refuses(t *testing.T) {
	clock := &testClock{t: time.Now()}
	for name, tc := range map[string]struct {
		setup func(s *statusServer, src *androidkey.StatusSource)
		want  string
	}{
		"wrong content type": {setup: func(s *statusServer, _ *androidkey.StatusSource) { s.contentType = "text/html" }, want: "content type"},
		"too large":          {setup: func(_ *statusServer, src *androidkey.StatusSource) { src.MaxBytes = 100 }, want: "size limit"},
		"not a list":         {setup: func(s *statusServer, _ *androidkey.StatusSource) { s.body = []byte(`{"entries":[]}`) }, want: "status list"},
		"http URL": {setup: func(s *statusServer, src *androidkey.StatusSource) {
			src.URL = strings.Replace(src.URL, "https:", "http:", 1)
		}, want: "isn't an https URL"},
		"bad URL":    {setup: func(_ *statusServer, src *androidkey.StatusSource) { src.URL = "https://%zz" }, want: "isn't an https URL"},
		"not found":  {setup: func(_ *statusServer, src *androidkey.StatusSource) { src.URL += "/missing" }, want: "unexpected status"},
		"loopback":   {setup: func(_ *statusServer, src *androidkey.StatusSource) { src.AllowLoopback = false }, want: "not allowed"},
		"no default": {setup: func(_ *statusServer, src *androidkey.StatusSource) { src.HTTP = nil; src.AllowLoopback = false }, want: "not allowed"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newStatusServer(t)
			src := srv.source(t, clock)
			tc.setup(srv, src)
			_, err := src.Current(context.Background())
			if !errors.Is(err, androidkey.ErrStatusUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrStatusUnavailable mentioning %q", err, tc.want)
			}
		})
	}
}

// TestStatusSource_Set: a list handed over is used until it ages out:
// past MaxAge while it can't be refreshed, until Grace has passed too.
func TestStatusSource_Set(t *testing.T) {
	clock := &testClock{t: statusEpoch}
	src := &androidkey.StatusSource{URL: "https://127.0.0.1:1/status", MaxAge: time.Hour, Grace: time.Hour, RetryAfter: time.Minute, Now: clock.now}
	src.Set(statusFixture(t), statusEpoch.Add(-30*time.Minute))
	if l, err := src.Current(context.Background()); err != nil || l.Len() != 4 {
		t.Fatalf("Current: %v, %v", l, err)
	}
	clock.set(statusEpoch.Add(time.Hour))
	if l, err := src.Current(context.Background()); err != nil || l.Len() != 4 {
		t.Fatalf("past MaxAge, within Grace: %v, %v", l, err)
	}
	clock.set(statusEpoch.Add(2 * time.Hour))
	if _, err := src.Current(context.Background()); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("aged out: %v", err)
	}
}

// TestStatusSource_Concurrent: concurrent callers share the source
// safely.
func TestStatusSource_Concurrent(t *testing.T) {
	srv := newStatusServer(t)
	src := srv.source(t, &testClock{t: time.Now()})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := src.Current(context.Background()); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if n := srv.requests.Load(); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
}

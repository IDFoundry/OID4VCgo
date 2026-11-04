package statuslist

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// testClock is a clock tests move by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Now().Truncate(time.Second)} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// cacheServer serves Status List Tokens signed at its clock's time, in
// either form, and counts the requests it gets.
type cacheServer struct {
	srv     *httptest.Server
	roots   *x509.CertPool
	leaf    *x509.Certificate
	leafKey *ecdsa.PrivateKey
	clock   *testClock

	mu       sync.Mutex
	ttl      *int64
	expIn    time.Duration // zero: no exp
	statuses []uint8
	failing  bool
	gate     chan struct{} // when set, requests wait for it to close

	fetches atomic.Int32
}

func newCacheServer(t *testing.T) *cacheServer {
	t.Helper()
	ca, caKey := testcert.CA(t, "status CA")
	leaf, leafKey := testcert.Leaf(t, "status signer", ca, caKey)
	s := &cacheServer{roots: x509.NewCertPool(), leaf: leaf, leafKey: leafKey, clock: newTestClock(), expIn: time.Hour, statuses: []uint8{0, 1}}
	s.roots.AddCert(ca)
	s.srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *cacheServer) set(f func(s *cacheServer)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f(s)
}

func (s *cacheServer) serve(w http.ResponseWriter, r *http.Request) {
	s.fetches.Add(1)
	s.mu.Lock()
	gate, failing, ttl, expIn, statuses := s.gate, s.failing, s.ttl, s.expIn, s.statuses
	s.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if failing {
		http.Error(w, "down", http.StatusServiceUnavailable)
		return
	}
	sl, err := New(Bits1, statuses, "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	now := s.clock.Now()
	claims := TokenClaims{Sub: s.srv.URL + r.URL.Path, Iat: now.Unix(), TTL: ttl, StatusList: sl}
	if expIn != 0 {
		exp := now.Add(expIn).Unix()
		claims.Exp = &exp
	}
	if r.Header.Get("Accept") == CWTTokenMediaType {
		token, err := IssueTokenCWTX5Chain(s.leafKey, cose.ES256, claims, []*x509.Certificate{s.leaf})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", CWTTokenMediaType)
		_, _ = w.Write(token)
		return
	}
	token, err := IssueTokenX5C(s.leafKey, jose.ES256, claims, []*x509.Certificate{s.leaf})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", TokenMediaType)
	_, _ = w.Write([]byte(token))
}

func (s *cacheServer) uri(path string) string { return s.srv.URL + path }

// checker is a Checker of s's lists through cache, bound to s's signer
// by its key, at s's clock.
func (s *cacheServer) checker(cache *Cache) Checker {
	return Checker{
		Fetcher: Fetcher{HTTP: s.srv.Client(), AllowLoopback: true},
		Roots:   s.roots,
		Options: VerifyOptions{IssuerKey: &s.leafKey.PublicKey, Now: s.clock.Now},
		Cache:   cache,
	}
}

// check checks idx on path's list and returns the status, failing t on
// an error.
func (s *cacheServer) check(t *testing.T, c Checker, path string, idx uint64, cwt bool) StatusType {
	t.Helper()
	status, _, err := c.Check(context.Background(), StatusListRef{Idx: idx, URI: s.uri(path)}, cwt)
	if err != nil {
		t.Fatalf("Check %s[%d]: %v", path, idx, err)
	}
	return status
}

func (s *cacheServer) wantFetches(t *testing.T, want int32, when string) {
	t.Helper()
	if got := s.fetches.Load(); got != want {
		t.Errorf("%s: %d fetches, want %d", when, got, want)
	}
}

// A cached token answers later checks, of any index, in both forms,
// until it expires.
func TestCache_Hit(t *testing.T) {
	for _, cwt := range []bool{false, true} {
		s := newCacheServer(t)
		c := s.checker(NewCache(CacheOptions{Now: s.clock.Now}))
		if got := s.check(t, c, "/l", 0, cwt); got != StatusValid {
			t.Errorf("cwt=%v: index 0 is %v", cwt, got)
		}
		if got := s.check(t, c, "/l", 1, cwt); got != StatusInvalid {
			t.Errorf("cwt=%v: index 1 is %v (cached)", cwt, got)
		}
		s.wantFetches(t, 1, fmt.Sprintf("cwt=%v, two checks", cwt))
		// The other form is another media type: fetched on its own.
		s.check(t, c, "/l", 0, !cwt)
		s.wantFetches(t, 2, fmt.Sprintf("cwt=%v, the other form", cwt))
		// A nil Cache fetches every time.
		c.Cache = nil
		s.check(t, c, "/l", 0, cwt)
		s.wantFetches(t, 3, fmt.Sprintf("cwt=%v, no cache", cwt))
	}
}

// A token is kept until the earliest of its iat plus ttl, its exp, and
// MaxAge after it was fetched; a token without ttl for MaxAge, 5
// minutes by default.
func TestCache_Expiry(t *testing.T) {
	ttl := int64(60)
	for name, tc := range map[string]struct {
		ttl    *int64
		expIn  time.Duration
		maxAge time.Duration
		lives  time.Duration
	}{
		"ttl":             {&ttl, time.Hour, 0, time.Minute},
		"exp":             {nil, 2 * time.Minute, 10 * time.Minute, 2 * time.Minute},
		"MaxAge":          {nil, time.Hour, 3 * time.Minute, 3 * time.Minute},
		"MaxAge over ttl": {&ttl, time.Hour, 30 * time.Second, 30 * time.Second},
		"default MaxAge":  {nil, time.Hour, 0, DefaultCacheMaxAge},
		"default, no exp": {nil, 0, 0, DefaultCacheMaxAge},
	} {
		t.Run(name, func(t *testing.T) {
			s := newCacheServer(t)
			s.set(func(s *cacheServer) { s.ttl, s.expIn = tc.ttl, tc.expIn })
			c := s.checker(NewCache(CacheOptions{MaxAge: tc.maxAge, Now: s.clock.Now}))
			s.check(t, c, "/l", 0, false)
			s.clock.Add(tc.lives - time.Second)
			s.check(t, c, "/l", 0, false)
			s.wantFetches(t, 1, "just before expiry")
			s.clock.Add(time.Second)
			s.check(t, c, "/l", 0, false)
			s.wantFetches(t, 2, "at expiry")
		})
	}
}

// Each hit is verified with the calling Checker's own trust: a token
// one Checker cached doesn't satisfy another's binding, roots, policy
// or clock, and the first Checker's hits go on.
func TestCache_HitIsVerifiedAgain(t *testing.T) {
	s := newCacheServer(t)
	cache := NewCache(CacheOptions{Now: s.clock.Now})
	trusted := s.checker(cache)
	ref := StatusListRef{Idx: 1, URI: s.uri("/l")}
	ctx := context.Background()
	s.check(t, trusted, "/l", 1, false)

	otherCA, otherKey := testcert.CA(t, "other CA")
	otherRoots := x509.NewCertPool()
	otherRoots.AddCert(otherCA)
	refusing := func(*x509.Certificate, [][]*x509.Certificate) error { return fmt.Errorf("not this signer") }
	later := func() time.Time { return s.clock.Now().Add(2 * time.Hour) }
	for name, tc := range map[string]struct {
		edit func(*Checker)
		want string
	}{
		"another issuer's key": {func(c *Checker) { c.Options.IssuerKey = &otherKey.PublicKey }, "signs with another key"},
		"another issuer's name": {func(c *Checker) {
			c.Options.IssuerKey, c.Options.Issuer = nil, "https://other.example"
		}, "isn't the referenced token's issuer"},
		"other roots":       {func(c *Checker) { c.Roots = otherRoots }, "token signer"},
		"a refusing policy": {func(c *Checker) { c.Options.LeafPolicy = refusing }, "not this signer"},
		"past its exp":      {func(c *Checker) { c.Options.Now = later }, "expired"},
		"no binding":        {func(c *Checker) { c.Options.IssuerKey = nil }, "can't be bound"},
		"a smaller size": {func(c *Checker) {
			c.Fetcher.MaxBytes = 100
		}, "exceeds 100 bytes"},
	} {
		other := s.checker(cache)
		tc.edit(&other)
		status, _, err := other.Check(ctx, ref, false)
		if err == nil || status != StatusInvalid || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, %v; want refused with %q", name, status, err, tc.want)
		}
	}
	// The trusted Checker's entry is still there.
	before := s.fetches.Load()
	s.check(t, trusted, "/l", 1, false)
	s.wantFetches(t, before, "the trusted Checker, after the others")
}

// A memo is used only for the bytes it was made from, and even given
// one, a check verifies the token's signature: a changed token is
// refused.
func TestCache_MemoNeedsItsToken(t *testing.T) {
	s := newCacheServer(t)
	opts := VerifyOptions{IssuerKey: &s.leafKey.PublicKey, Now: s.clock.Now}
	for _, cwt := range []bool{false, true} {
		req, _ := http.NewRequest(http.MethodGet, s.uri("/l"), nil)
		if cwt {
			req.Header.Set("Accept", CWTTokenMediaType)
		}
		resp, err := s.srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var buf strings.Builder
		_, _ = io.Copy(&buf, resp.Body)
		_ = resp.Body.Close()
		token := []byte(buf.String())
		ref := StatusListRef{Idx: 1, URI: s.uri("/l")}
		check := func(token []byte, memo *tokenMemo) (StatusType, parsedClaims, error) {
			if cwt {
				o := opts
				o.RequireExp, o.X5ChainProtectedOnly = true, true
				return checkCWTX5Chain(context.Background(), token, s.roots, ref, o, memo)
			}
			return checkX5C(context.Background(), string(token), s.roots, ref, opts, memo)
		}
		status, parsed, err := check(token, nil)
		if err != nil || status != StatusInvalid {
			t.Fatalf("cwt=%v: %v, %v", cwt, status, err)
		}
		memo := newTokenMemo(token, parsed)
		if memo.of(token) != memo || memo.decoded == nil {
			t.Errorf("cwt=%v: the memo isn't its own token's, or has no list", cwt)
		}
		if status, _, err := check(token, memo); err != nil || status != StatusInvalid {
			t.Errorf("cwt=%v, with the memo: %v, %v", cwt, status, err)
		}
		tampered := append([]byte{}, token...)
		tampered[len(tampered)-2] ^= 1
		if memo.of(tampered) != nil {
			t.Errorf("cwt=%v: a memo matched other bytes", cwt)
		}
		if _, _, err := check(tampered, memo); err == nil {
			t.Errorf("cwt=%v: a tampered token passed given the original's memo", cwt)
		}
	}
}

// A failed fetch or a failed verification is never cached, and an
// expired token whose refetch fails fails the check.
func TestCache_FailuresNotCached(t *testing.T) {
	s := newCacheServer(t)
	cache := NewCache(CacheOptions{Now: s.clock.Now})
	c := s.checker(cache)
	ctx := context.Background()
	ref := StatusListRef{URI: s.uri("/l")}

	s.set(func(s *cacheServer) { s.failing = true })
	if _, _, err := c.Check(ctx, ref, false); err == nil {
		t.Fatal("a failed fetch passed")
	}
	untrusted := c
	untrusted.Roots = x509.NewCertPool()
	s.set(func(s *cacheServer) { s.failing = false })
	if _, _, err := untrusted.Check(ctx, ref, false); err == nil {
		t.Fatal("an untrusted token passed")
	}
	if n, _ := cache.engine.Len(); n != 0 {
		t.Errorf("%d entries after failures, want none", n)
	}
	s.check(t, c, "/l", 0, false)
	s.wantFetches(t, 3, "after two failures and a success")

	s.clock.Add(DefaultCacheMaxAge)
	s.set(func(s *cacheServer) { s.failing = true })
	if _, _, err := c.Check(ctx, ref, false); err == nil {
		t.Error("an expired entry was used when its refetch failed")
	}
}

// Concurrent misses share one fetch; each checker still verifies it.
func TestCache_SingleFlight(t *testing.T) {
	s := newCacheServer(t)
	gate := make(chan struct{})
	s.set(func(s *cacheServer) { s.gate = gate })
	cache := NewCache(CacheOptions{Now: s.clock.Now})
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		c := s.checker(cache)
		if i%2 == 1 {
			c.Roots = x509.NewCertPool() // shares the fetch, refuses the token
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := c.Check(context.Background(), StatusListRef{URI: s.uri("/l")}, false)
			if (err == nil) != (i%2 == 0) {
				errs <- fmt.Errorf("checker %d: %v", i, err)
			}
		}()
	}
	waitFor(t, func() bool { return s.fetches.Load() >= 1 })
	time.Sleep(50 * time.Millisecond) // let the rest join the fetch
	close(gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	s.wantFetches(t, 1, "concurrent misses")
}

// A caller whose context ends stops waiting, without failing the
// others sharing its fetch.
func TestCache_SingleFlightCancel(t *testing.T) {
	s := newCacheServer(t)
	gate := make(chan struct{})
	s.set(func(s *cacheServer) { s.gate = gate })
	c := s.checker(NewCache(CacheOptions{Now: s.clock.Now}))
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		_, _, err := c.Check(ctx, StatusListRef{URI: s.uri("/l")}, false)
		first <- err
	}()
	waitFor(t, func() bool { return s.fetches.Load() >= 1 })
	second := make(chan error, 1)
	go func() {
		_, _, err := c.Check(context.Background(), StatusListRef{URI: s.uri("/l")}, false)
		second <- err
	}()
	cancel()
	if err := <-first; err == nil {
		t.Error("a cancelled check passed")
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	if err := <-second; err != nil {
		t.Errorf("the other check: %v", err)
	}
}

// The cache holds at most MaxEntries tokens and MaxBytes, dropping the
// least recently used, and doesn't keep a token larger than MaxBytes.
func TestCache_Bounds(t *testing.T) {
	s := newCacheServer(t)
	cache := NewCache(CacheOptions{MaxEntries: 2, Now: s.clock.Now})
	c := s.checker(cache)
	s.check(t, c, "/a", 0, false)
	s.check(t, c, "/b", 0, false)
	s.check(t, c, "/a", 0, false) // a is now the most recent
	s.check(t, c, "/c", 0, false) // evicts b
	if n, _ := cache.engine.Len(); n != 2 {
		t.Errorf("%d entries, want 2", n)
	}
	s.wantFetches(t, 3, "three lists")
	s.check(t, c, "/a", 0, false)
	s.wantFetches(t, 3, "a, kept")
	s.check(t, c, "/b", 0, false)
	s.wantFetches(t, 4, "b, evicted")

	tiny := NewCache(CacheOptions{MaxBytes: 64, Now: s.clock.Now})
	c.Cache = tiny
	s.check(t, c, "/a", 0, false)
	if n, size := tiny.engine.Len(); n != 0 || size != 0 {
		t.Errorf("a cache of 64 bytes holds %d entries, %d bytes", n, size)
	}

	_, oneSize := func() (int, int64) {
		one := NewCache(CacheOptions{Now: s.clock.Now})
		c.Cache = one
		s.check(t, c, "/a", 0, false)
		return one.engine.Len()
	}()
	two := NewCache(CacheOptions{MaxBytes: oneSize + oneSize/2, Now: s.clock.Now})
	c.Cache = two
	s.check(t, c, "/a", 0, false)
	s.check(t, c, "/b", 0, false)
	if n, size := two.engine.Len(); n != 1 || size > oneSize+oneSize/2 {
		t.Errorf("a cache with room for one token holds %d, %d bytes", n, size)
	}

	// Purge drops everything; a cancelled check fails, cached or not.
	c.Cache = cache
	cache.Purge()
	if n, size := cache.engine.Len(); n != 0 || size != 0 {
		t.Errorf("after Purge: %d entries, %d bytes", n, size)
	}
	s.check(t, c, "/a", 0, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := c.Check(ctx, StatusListRef{URI: s.uri("/a")}, false); err == nil {
		t.Error("a cancelled check of a cached token passed")
	}
}

// Checkers sharing a Cache from many goroutines, some trusting the
// signer and some not, run clean under -race.
func TestCache_Concurrent(t *testing.T) {
	s := newCacheServer(t)
	cache := NewCache(CacheOptions{MaxEntries: 3, Now: s.clock.Now})
	_, otherKey := testcert.CA(t, "other issuer")
	var wg sync.WaitGroup
	for i := range 16 {
		c := s.checker(cache)
		trusted := i%4 != 3
		if !trusted {
			c.Options.IssuerKey = &otherKey.PublicKey
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 20 {
				path := fmt.Sprintf("/l%d", (i+j)%5)
				status, claims, err := c.Check(context.Background(), StatusListRef{Idx: uint64(j % 2), URI: s.uri(path)}, j%3 == 0)
				switch {
				case trusted && (err != nil || status != StatusType(j%2)):
					t.Errorf("checker %d, %s: %v, %v", i, path, status, err)
				case !trusted && err == nil:
					t.Errorf("checker %d, %s: an untrusted signer passed", i, path)
				}
				if claims.Exp != nil {
					*claims.Exp = 0 // a caller's change doesn't reach the cache
				}
				if j%7 == 0 {
					s.clock.Add(time.Second)
				}
			}
		}()
	}
	wg.Wait()
}

// waitFor waits up to 5 seconds for cond.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

// Fetches through one Fetcher configuration reuse its transport, and
// with it their connections: two fetches open one.
func TestFetcher_ReusesConnections(t *testing.T) {
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", TokenMediaType)
		_, _ = w.Write([]byte("token"))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	client := srv.Client()
	for range 3 {
		f := Fetcher{HTTP: client, AllowLoopback: true} // a fresh value each time
		if _, err := f.Fetch(context.Background(), srv.URL+"/l", TokenMediaType); err != nil {
			t.Fatal(err)
		}
	}
	if got := conns.Load(); got != 1 {
		t.Errorf("three fetches opened %d connections, want 1", got)
	}

	// A nil Transport shares one per policy; policies don't share.
	a, _ := Fetcher{}.transport(nil)
	b, _ := Fetcher{}.transport(nil)
	l, _ := Fetcher{AllowLoopback: true}.transport(nil)
	if a != b || a == l {
		t.Error("nil Transports: one per policy, not shared across policies")
	}
	base := client.Transport.(*http.Transport)
	d1, _ := Fetcher{AllowLoopback: true}.transport(base)
	d2, _ := Fetcher{AllowLoopback: true, AllowProxy: true}.transport(base)
	if d1 == d2 || d1 == base {
		t.Error("a caller's Transport: one derived copy per policy, never the caller's own")
	}
}

// A derived transport is dropped once the caller's is collected.
func TestFetcher_DerivedTransportsDropped(t *testing.T) {
	count := func() int {
		derivedMu.Lock()
		defer derivedMu.Unlock()
		return len(derived)
	}
	before := count()
	func() {
		tr := &http.Transport{}
		if _, err := (Fetcher{}).transport(tr); err != nil {
			t.Fatal(err)
		}
		if count() != before+1 {
			t.Fatal("no derived transport was kept")
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for count() > before {
		if time.Now().After(deadline) {
			t.Fatal("the derived transport outlived its base")
		}
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}

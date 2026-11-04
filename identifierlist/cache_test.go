package identifierlist

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A Checker with a Cache fetches a list once for many MSOs, verifies
// each hit against that MSO's own binding, and refetches once the
// list's ttl has passed.
func TestChecker_Cache(t *testing.T) {
	pki := newPKI(t)
	var fetches atomic.Int32
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		(&Publisher{
			URI: uri, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Minute, Now: clock,
			Identifiers: func(context.Context) ([][]byte, error) { return [][]byte{{0xcc}}, nil },
		}).ServeHTTP(w, r)
	}))
	defer srv.Close()
	uri = srv.URL + "/identifierlists/1"
	cache := statuslist.NewCache(statuslist.CacheOptions{Now: clock})
	c := Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: pki.roots, Options: VerifyOptions{Now: clock}, Cache: cache}
	ctx := context.Background()
	wantFetches := func(want int32, when string) {
		t.Helper()
		if got := fetches.Load(); got != want {
			t.Errorf("%s: %d fetches, want %d", when, got, want)
		}
	}

	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xcc}, URI: uri}, pki.dsPath); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked: %v", err)
	}
	_, claims, err := c.Check(ctx, Ref{ID: []byte{0xdd}, URI: uri}, pki.dsPath)
	if err != nil {
		t.Fatal(err)
	}
	wantFetches(1, "two MSOs")
	claims.Identifiers[0] = []byte{0xdd} // a caller's change doesn't reach the cache
	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xcc}, URI: uri}, pki.dsPath); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked, after a caller changed its claims: %v", err)
	}

	// An MSO from another IACA can't be decided by this IACA's list,
	// cached or not.
	otherCA, otherKey := testcert.CA(t, "other IACA")
	otherDS, _ := testcert.Leaf(t, "other document signer", otherCA, otherKey)
	if _, _, err := c.Check(ctx, Ref{ID: []byte{0xdd}, URI: uri}, []*x509.Certificate{otherDS}); err == nil {
		t.Error("a cached list decided another IACA's MSO")
	}
	before := fetches.Load()
	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xdd}, URI: uri}, pki.dsPath); err != nil {
		t.Errorf("after the refused check: %v", err)
	}
	wantFetches(before, "the bound MSO, after the refused one")

	mu.Lock()
	now = now.Add(time.Minute)
	mu.Unlock()
	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xdd}, URI: uri}, pki.dsPath); err != nil {
		t.Errorf("after the ttl: %v", err)
	}
	wantFetches(before+1, "after the ttl")

	// A Fetcher with a smaller limit refuses a list another fetched.
	small := c
	small.Fetcher.MaxBytes = 10
	if _, _, err := small.Check(ctx, Ref{ID: []byte{0xdd}, URI: uri}, pki.dsPath); err == nil {
		t.Error("a cached list over the Fetcher's MaxBytes passed")
	}
}

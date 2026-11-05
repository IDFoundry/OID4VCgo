package identifierlist

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A Checker's Cache revalidates a list past its MaxAge with
// If-None-Match, and keeps it on a 304.
func TestChecker_CacheRevalidates(t *testing.T) {
	pki := newPKI(t)
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	var uri string
	var token []byte
	var full, notModified atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if token == nil {
			rec := httptest.NewRecorder()
			(&Publisher{
				URI: uri, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Hour, Now: clock,
				Identifiers: func(context.Context) ([][]byte, error) { return [][]byte{{0xcc}}, nil },
			}).ServeHTTP(rec, r)
			token = rec.Body.Bytes()
		}
		w.Header().Set("ETag", `"v1"`)
		if r.Header.Get("If-None-Match") == `"v1"` {
			notModified.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		full.Add(1)
		w.Header().Set("Content-Type", MediaType)
		_, _ = w.Write(token)
	}))
	defer srv.Close()
	uri = srv.URL + "/identifierlists/1"
	cache := statuslist.NewCache(statuslist.CacheOptions{MaxAge: time.Minute, Now: clock})
	c := Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: pki.roots, Options: VerifyOptions{Now: clock}, Cache: cache}
	ctx := context.Background()
	for range 2 {
		if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xdd}, URI: uri}, pki.dsPath); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		now = now.Add(time.Minute)
		mu.Unlock()
	}
	if full.Load() != 1 || notModified.Load() != 1 {
		t.Errorf("%d full fetches and %d 304s, want 1 and 1", full.Load(), notModified.Load())
	}
}

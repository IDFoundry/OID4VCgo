package identifierlist

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// TestPublisher_CheckerRoundTrip: one Checker reads what a Publisher
// serves over https, for any credential, and wraps a fetch failure.
func TestPublisher_CheckerRoundTrip(t *testing.T) {
	pki := newPKI(t)
	var uri string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/identifierlists/1" {
			http.NotFound(w, r)
			return
		}
		(&Publisher{
			URI: uri, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Minute,
			Identifiers: func(context.Context) ([][]byte, error) { return [][]byte{{0xcc, 0xcc}}, nil },
		}).ServeHTTP(w, r)
	}))
	defer srv.Close()
	uri = srv.URL + "/identifierlists/1"
	c := Checker{Fetcher: statuslist.Fetcher{HTTP: srv.Client(), AllowLoopback: true}, Roots: pki.roots}
	ctx := context.Background()

	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xcc, 0xcd}, URI: uri}, pki.dsPath); err != nil {
		t.Errorf("not revoked: %v", err)
	}
	if err := c.RequireNotRevoked(ctx, Ref{ID: []byte{0xcc, 0xcc}, URI: uri}, pki.dsPath); !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked: %v, want ErrRevoked", err)
	}
	err := c.RequireNotRevoked(ctx, Ref{ID: []byte{1}, URI: srv.URL + "/elsewhere"}, pki.dsPath)
	wantErr(t, "fetch failure", err, "identifierlist: statuslist: fetch")
	_, _, err = c.Check(ctx, Ref{URI: uri}, pki.dsPath)
	wantErr(t, "no id", err, "needs an id and a uri")
}

// TestPublisher_ReportsErrors: a request ServeHTTP can't answer is a
// 500 whose error reaches OnError, and Token returns it.
func TestPublisher_ReportsErrors(t *testing.T) {
	pki := newPKI(t)
	chain := []*x509.Certificate{pki.leaf}
	ids := func(context.Context) ([][]byte, error) { return nil, nil }
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dbDown := errors.New("db down")
	for name, tc := range map[string]struct {
		p    *Publisher
		want string
	}{
		"no URI":              {&Publisher{Signer: pki.key, Chain: chain, Identifiers: ids}, "are required"},
		"identifiers error":   {&Publisher{URI: testURI, Signer: pki.key, Chain: chain, Identifiers: func(context.Context) ([][]byte, error) { return nil, dbDown }}, "db down"},
		"P-224 signer":        {&Publisher{URI: testURI, Signer: p224, Chain: chain, Identifiers: ids}, "an ECDSA key on P-224"},
		"unknown typ":         {&Publisher{URI: testURI, Signer: pki.key, Chain: chain, Identifiers: ids, Typ: "cwt"}, "IssueOptions.Typ"},
		"sub-second Lifetime": {&Publisher{URI: testURI, Signer: pki.key, Chain: chain, Identifiers: ids, Lifetime: time.Millisecond}, "Lifetime is 1ms"},
		"sub-second TTL":      {&Publisher{URI: testURI, Signer: pki.key, Chain: chain, Identifiers: ids, TTL: time.Millisecond}, "TTL is 1ms"},
		"TTL over Lifetime":   {&Publisher{URI: testURI, Signer: pki.key, Chain: chain, Identifiers: ids, TTL: 2 * time.Hour}, "longer than its Lifetime"},
	} {
		var reported error
		tc.p.OnError = func(_ *http.Request, err error) { reported = err }
		rec := httptest.NewRecorder()
		tc.p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want 500", name, rec.Code)
		}
		wantErr(t, name+", OnError", reported, tc.want)
		_, err := tc.p.Token(context.Background())
		wantErr(t, name+", Token", err, tc.want)
	}
	rec := httptest.NewRecorder()
	(&Publisher{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/l", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d, want 405", rec.Code)
	}
}

// TestPublisher_Caches: requests within the cache window share one
// signed token, whose Cache-Control max-age counts down; a new one is
// signed once it has passed or after Invalidate; a failed re-signing
// serves the unexpired cached token and reports the error; a negative
// CacheFor signs every request; and Token never caches.
func TestPublisher_Caches(t *testing.T) {
	pki := newPKI(t)
	now := time.Now()
	calls := 0
	var failWith error
	var reported error
	p := &Publisher{
		URI: testURI, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Minute, Lifetime: 4 * time.Minute,
		Identifiers: func(ctx context.Context) ([][]byte, error) {
			calls++
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, failWith
		},
		Now:     func() time.Time { return now },
		OnError: func(_ *http.Request, err error) { reported = err },
	}
	get := func(wantMaxAge string) func() {
		return func() {
			t.Helper()
			// A request already cancelled: the signature mustn't end with it.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil).WithContext(ctx))
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			if got := rec.Header().Get("Cache-Control"); got != "public, max-age="+wantMaxAge {
				t.Errorf("Cache-Control %q, want public, max-age=%s", got, wantMaxAge)
			}
		}
	}
	dbDown := errors.New("db down")
	steps := []struct {
		name string
		do   func()
		want int
	}{
		{"first request signs", get("60"), 1},
		{"second is cached, max-age counts down", func() { now = now.Add(20 * time.Second); get("40")() }, 1},
		{"after the TTL", func() { now = now.Add(40 * time.Second); get("60")() }, 2},
		{"after Invalidate", func() { p.Invalidate(); get("60")() }, 3},
		{"a failed re-signing serves the cached token", func() {
			failWith = dbDown
			now = now.Add(150 * time.Second)
			get("0")()
			if !errors.Is(reported, dbDown) {
				t.Errorf("reported %v, want the Identifiers error", reported)
			}
		}, 4},
		{"Token never caches", func() { failWith = nil; _, _ = p.Token(context.Background()) }, 5},
		{"negative CacheFor", func() { p.CacheFor = -1; get("60")(); get("60")() }, 7},
	}
	for _, s := range steps {
		s.do()
		if calls != s.want {
			t.Fatalf("%s: %d signatures, want %d", s.name, calls, s.want)
		}
	}

	// Once the cached token has expired, a failed re-signing is a 500.
	p.CacheFor, failWith = 0, dbDown
	now = now.Add(5 * time.Minute)
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expired cache, failed signing: status %d, want 500", rec.Code)
	}
}

// TestPublisher_ETag: a response carries a strong ETag, and a request
// naming it in If-None-Match is answered 304 without a body.
func TestPublisher_ETag(t *testing.T) {
	pki := newPKI(t)
	p := &Publisher{
		URI: testURI, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Minute,
		Identifiers: func(context.Context) ([][]byte, error) { return nil, nil },
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
	tag := rec.Header().Get("ETag")
	if rec.Code != http.StatusOK || tag == "" {
		t.Fatalf("status %d, ETag %q", rec.Code, tag)
	}
	r := httptest.NewRequest(http.MethodGet, "/l", nil)
	r.Header.Set("If-None-Match", tag)
	rec = httptest.NewRecorder()
	p.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 || rec.Header().Get("ETag") != tag {
		t.Errorf("If-None-Match its ETag: %d, headers %v; want 304", rec.Code, rec.Header())
	}
}

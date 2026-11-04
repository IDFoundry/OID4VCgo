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
// fail to answer 500 instead.
type statusServer struct {
	*httptest.Server
	requests    atomic.Int32
	fail        atomic.Bool
	contentType string
	body        []byte
}

func newStatusServer(t *testing.T) *statusServer {
	body, err := os.ReadFile("testdata/status.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &statusServer{contentType: "application/json; charset=utf-8", body: body}
	s.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
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

// source is a StatusSource for s, with a clock the test moves.
func (s *statusServer) source(t *testing.T, now *time.Time) *androidkey.StatusSource {
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
		Now: func() time.Time { return *now },
	}
}

// TestStatusSource_Caches: a list is fetched once, used for MaxAge,
// then fetched again; a failed fetch isn't retried for RetryAfter, and
// a list past MaxAge is never used.
func TestStatusSource_Caches(t *testing.T) {
	srv := newStatusServer(t)
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	src := srv.source(t, &now)
	ctx := context.Background()

	l, err := src.Current(ctx)
	if err != nil || l.Len() != 4 {
		t.Fatalf("first Current: %v, %v", l, err)
	}
	now = now.Add(androidkey.DefaultStatusMaxAge - time.Second)
	if _, err := src.Current(ctx); err != nil || srv.requests.Load() != 1 {
		t.Fatalf("within MaxAge: %v, %d requests", err, srv.requests.Load())
	}
	now = now.Add(time.Second)
	if _, err := src.Current(ctx); err != nil || srv.requests.Load() != 2 {
		t.Fatalf("at MaxAge: %v, %d requests", err, srv.requests.Load())
	}

	srv.fail.Store(true)
	now = now.Add(androidkey.DefaultStatusMaxAge)
	if _, err := src.Current(ctx); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("server failing, list aged out: %v", err)
	}
	now = now.Add(androidkey.DefaultStatusRetryAfter / 2)
	if _, err := src.Current(ctx); !errors.Is(err, androidkey.ErrStatusUnavailable) || srv.requests.Load() != 3 {
		t.Fatalf("within RetryAfter: %v, %d requests", err, srv.requests.Load())
	}
	srv.fail.Store(false)
	now = now.Add(androidkey.DefaultStatusRetryAfter)
	if _, err := src.Current(ctx); err != nil || srv.requests.Load() != 4 {
		t.Fatalf("after RetryAfter: %v, %d requests", err, srv.requests.Load())
	}

	// Refresh fetches whatever is held; a failed one keeps the held list.
	srv.fail.Store(true)
	if err := src.Refresh(ctx); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("failed Refresh: %v", err)
	}
	if _, err := src.Current(ctx); err != nil {
		t.Fatalf("after a failed Refresh, the held list: %v", err)
	}
}

// TestStatusSource_Verify: a Verifier with a StatusSource checks the
// chain against the fetched list, and refuses while none is current.
func TestStatusSource_Verify(t *testing.T) {
	srv := newStatusServer(t)
	now := time.Now()
	src := srv.source(t, &now)
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
	now = now.Add(25 * time.Hour)
	v.Now = time.Now
	if _, err := v.Verify(ctx, good.der, testChallenge); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("no current list: %v", err)
	}
	v.RevocationOptional = true
	if r, err := v.Verify(ctx, good.der, testChallenge); err != nil || r.RevocationChecked {
		t.Fatalf("no current list, optional: %+v, %v", r, err)
	}
}

// TestStatusSource_Refuses: fetches that don't give a list fail.
func TestStatusSource_Refuses(t *testing.T) {
	now := time.Now()
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
			src := srv.source(t, &now)
			tc.setup(srv, src)
			_, err := src.Current(context.Background())
			if !errors.Is(err, androidkey.ErrStatusUnavailable) || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want ErrStatusUnavailable mentioning %q", err, tc.want)
			}
		})
	}
}

// TestStatusSource_Set: a list handed over is used until it ages out.
func TestStatusSource_Set(t *testing.T) {
	now := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	src := &androidkey.StatusSource{URL: "https://127.0.0.1:1/status", MaxAge: time.Hour, RetryAfter: time.Hour, Now: func() time.Time { return now }}
	src.Set(statusFixture(t), now.Add(-30*time.Minute))
	if l, err := src.Current(context.Background()); err != nil || l.Len() != 4 {
		t.Fatalf("Current: %v, %v", l, err)
	}
	now = now.Add(time.Hour)
	if _, err := src.Current(context.Background()); !errors.Is(err, androidkey.ErrStatusUnavailable) {
		t.Fatalf("aged out: %v", err)
	}
}

// TestStatusSource_Concurrent: concurrent callers share the source
// safely.
func TestStatusSource_Concurrent(t *testing.T) {
	srv := newStatusServer(t)
	now := time.Now()
	src := srv.source(t, &now)
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

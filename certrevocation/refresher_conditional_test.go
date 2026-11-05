package certrevocation_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// validatorServer serves one list with an ETag and a Last-Modified,
// answering 304 to a request naming either, and records the
// conditional headers of each request.
type validatorServer struct {
	*httptest.Server
	mu            sync.Mutex
	list          []byte
	etag, lastMod string
	// unconditional304 answers 304 to every request.
	unconditional304 bool
	seen             []string
	fulls            int
}

func newValidatorServer(t *testing.T) *validatorServer {
	t.Helper()
	s := &validatorServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		inm, ims := req.Header.Get("If-None-Match"), req.Header.Get("If-Modified-Since")
		s.seen = append(s.seen, inm+"|"+ims)
		if s.etag != "" {
			w.Header().Set("ETag", s.etag)
		}
		if s.lastMod != "" {
			w.Header().Set("Last-Modified", s.lastMod)
		}
		if s.unconditional304 || (inm != "" && inm == s.etag) || (s.etag == "" && ims != "" && ims == s.lastMod) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		s.fulls++
		_, _ = w.Write(s.list)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *validatorServer) set(list *x509.RevocationList, etag, lastMod string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list, s.etag, s.lastMod = list.Raw, etag, lastMod
}

// Once a list is held, a refresh is conditional on its response's ETag
// or Last-Modified, a 304 keeps the held list, and a changed list is
// fetched in full and held with its new validators.
func TestRefresher_ConditionalFetch(t *testing.T) {
	for _, tc := range []struct {
		name, etag, lastMod, wantSeen string
	}{
		{"etag", `"v1"`, "", `"v1"|`},
		{"last-modified", "", "Wed, 04 Nov 2026 10:00:00 GMT", "|Wed, 04 Nov 2026 10:00:00 GMT"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPKI(t)
			srv := newValidatorServer(t)
			first := numbered(t, p.inter, p.interKey, 1, -time.Minute)
			srv.set(first, tc.etag, tc.lastMod)
			var accepted int
			r := newRefresher(t, certrevocation.RefresherConfig{
				URLs: []string{srv.URL}, Issuers: []*x509.Certificate{p.inter},
				OnAccept: func(string, *x509.RevocationList) { accepted++ },
			})
			for range 2 {
				if err := r.Refresh(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if srv.fulls != 1 || len(srv.seen) != 2 || srv.seen[0] != "|" || srv.seen[1] != tc.wantSeen {
				t.Fatalf("%d full responses, requests' conditions %q; want one full, then %q", srv.fulls, srv.seen, tc.wantSeen)
			}
			if got := heldList(t, r); got.Number.Int64() != 1 || accepted != 2 {
				t.Errorf("held list %v, OnAccept called %d times; want list 1, twice", got.Number, accepted)
			}

			second := numbered(t, p.inter, p.interKey, 2, 0)
			srv.set(second, strings.ReplaceAll(tc.etag, "1", "2"), strings.ReplaceAll(tc.lastMod, "10:", "11:"))
			if err := r.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := heldList(t, r); got.Number.Int64() != 2 || srv.fulls != 2 {
				t.Errorf("after a change: held list %v, %d full responses; want list 2, 2", got.Number, srv.fulls)
			}
		})
	}
}

// A 304 to a fetch that sent no validators is a failure, and a 304 for
// a held list past its nextUpdate fails as that list would.
func TestRefresher_NotModifiedRefusals(t *testing.T) {
	p := newPKI(t)
	srv := newValidatorServer(t)
	now := time.Now().Truncate(time.Second)
	clock := now
	srv.set(testcert.CRLFromTemplate(t, &x509.RevocationList{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, p.inter, p.interKey), `"v1"`, "")
	srv.mu.Lock()
	srv.unconditional304 = true
	srv.mu.Unlock()
	r := newRefresher(t, certrevocation.RefresherConfig{
		URLs: []string{srv.URL}, Issuers: []*x509.Certificate{p.inter},
		Clock: func() time.Time { return clock },
	})
	if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 304") {
		t.Fatalf("an unasked-for 304: %v, want HTTP 304", err)
	}
	srv.mu.Lock()
	srv.unconditional304 = false
	srv.mu.Unlock()
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	clock = now.Add(2 * time.Hour)
	if err := r.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("a 304 for an expired list: %v, want it refused as expired", err)
	}
}

// Run takes up to a fifth off the wait after a good pass, so that
// processes started together spread their fetches.
func TestRefresher_RunJitter(t *testing.T) {
	p := newPKI(t)
	srv := newCRLServer(t)
	now := time.Now().Truncate(time.Second)
	srv.serveCRL("/ca.crl", testcert.CRLFromTemplate(t, &x509.RevocationList{ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, p.inter, p.interKey))
	r := newRefresher(t, certrevocation.RefresherConfig{
		URLs: []string{srv.URL + "/ca.crl"}, Issuers: []*x509.Certificate{p.inter},
		Clock: func() time.Time { return now },
	})
	var waits []time.Duration
	r.SetScheduleForTest(func(_ context.Context, d time.Duration) bool {
		waits = append(waits, d)
		return false
	}, func(n time.Duration) time.Duration { return n })
	r.Run(context.Background())
	if len(waits) != 1 || waits[0] != 24*time.Minute {
		t.Errorf("waits = %v, want [24m]: 30m less a fifth", waits)
	}
}

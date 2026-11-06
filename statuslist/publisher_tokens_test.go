package statuslist_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/statuslist/statuslisttest"
)

// statuslisttest.MemoryTokenStore is a TokenStore.
func TestMemoryTokenStoreContract(t *testing.T) {
	statuslisttest.TestTokenStoreContract(t, func(*testing.T) (statuslist.TokenStore, func(*testing.T, string)) {
		s := statuslisttest.NewMemoryTokenStore()
		return s, func(_ *testing.T, uri string) { s.Bump(uri) }
	})
}

// replicas are Publishers of one list sharing a TokenStore, each
// counting its own reads of the statuses, on one clock.
type replicas struct {
	t     *testing.T
	store *statuslisttest.MemoryTokenStore
	now   time.Time
	pubs  []*statuslist.Publisher
	reads []*atomic.Int32
	errs  []error
}

const sharedListURI = "https://issuer.example/statuslists/1"

func newReplicas(t *testing.T, n int) *replicas {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	rs := &replicas{t: t, store: statuslisttest.NewMemoryTokenStore(), now: time.UnixMilli(time.Now().UnixMilli()), errs: make([]error, n)}
	for i := range n {
		reads := new(atomic.Int32)
		rs.reads = append(rs.reads, reads)
		rs.pubs = append(rs.pubs, &statuslist.Publisher{
			URI: sharedListURI, Signer: key, Chain: []*x509.Certificate{cert},
			TTL: time.Minute, Lifetime: 10 * time.Minute, Tokens: rs.store,
			Statuses: func(context.Context) ([]uint8, error) { reads.Add(1); return []uint8{0, 1}, nil },
			Now:      func() time.Time { return rs.now },
			OnError:  func(_ *http.Request, err error) { rs.errs[i] = err },
		})
	}
	return rs
}

// get serves a JWT request from replica i.
func (rs *replicas) get(i int) *httptest.ResponseRecorder {
	rs.t.Helper()
	rs.errs[i] = nil
	rec := httptest.NewRecorder()
	rs.pubs[i].ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
	return rec
}

// ok serves a JWT request from replica i, failing unless it's a 200,
// and returns the token.
func (rs *replicas) ok(i int) string {
	rs.t.Helper()
	rec := rs.get(i)
	if rec.Code != http.StatusOK {
		rs.t.Fatalf("replica %d: %d %s", i, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// expectReads checks how often each replica has read the statuses.
func (rs *replicas) expectReads(want ...int32) {
	rs.t.Helper()
	for i, w := range want {
		if got := rs.reads[i].Load(); got != w {
			rs.t.Fatalf("replica %d read the statuses %d times, want %d", i, got, w)
		}
	}
}

// One replica signs, the others serve its token, with the max-age left
// on it; a status change has one of them sign anew, within TokensCheck,
// and the others serve that token from their next check.
func TestPublisher_TokensShared(t *testing.T) {
	rs := newReplicas(t, 3)
	first := rs.ok(0)
	rs.expectReads(1, 0, 0)
	rs.now = rs.now.Add(10 * time.Second)
	for i := 1; i < 3; i++ {
		rec := rs.get(i)
		if rec.Body.String() != first || rec.Header().Get("Cache-Control") != "public, max-age=50" {
			t.Fatalf("replica %d: Cache-Control %q, same token %v; want replica 0's, max-age=50", i, rec.Header().Get("Cache-Control"), rec.Body.String() == first)
		}
	}
	rs.now = rs.now.Add(20 * time.Second) // past TokensCheck, within CacheFor
	for i := range 3 {
		if rs.ok(i) != first {
			t.Fatalf("replica %d signed anew within CacheFor", i)
		}
	}
	rs.expectReads(1, 0, 0)

	rs.store.Bump(sharedListURI)
	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	second := rs.ok(2)
	if second == first {
		t.Fatal("no new token after a status change")
	}
	rs.expectReads(1, 0, 1)
	for i := range 2 {
		if rs.ok(i) != second {
			t.Fatalf("replica %d: not replica 2's new token", i)
		}
	}
	rs.expectReads(1, 0, 1)

	// Once CacheFor has passed, one replica signs anew.
	rs.now = rs.now.Add(time.Minute)
	third := rs.ok(1)
	if third == second || rs.ok(0) != third || rs.ok(2) != third {
		t.Fatal("after CacheFor: not one new token for every replica")
	}
	rs.expectReads(1, 1, 1)
}

// While a replica holds the lease, the others serve the stored token,
// stale or not, until its exp, rather than sign; once a lease that its
// holder never ended runs out, another replica signs.
func TestPublisher_TokensLeaderFailover(t *testing.T) {
	rs := newReplicas(t, 2)
	first := rs.ok(0)
	ctx := context.Background()
	// A replica takes the lease and stops.
	if ok, err := rs.store.Claim(ctx, sharedListURI, statuslist.FormJWT, "gone", rs.now, rs.now.Add(35*time.Second)); !ok || err != nil {
		t.Fatalf("Claim: %v, %v", ok, err)
	}
	rs.store.Bump(sharedListURI)
	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	for i := range 2 {
		if rs.ok(i) != first {
			t.Fatalf("replica %d: not the stored token while the lease runs", i)
		}
	}
	rs.expectReads(1, 0)
	rs.now = rs.now.Add(30 * time.Second) // the lease has run out
	second := rs.ok(1)
	if second == first {
		t.Fatal("no new token after the lease ran out")
	}
	rs.expectReads(1, 1)
	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	if rs.ok(0) != second {
		t.Fatal("replica 0: not replica 1's token")
	}
}

// With no token stored and another replica's lease running, a replica
// signs its own rather than fail.
func TestPublisher_TokensColdStartSignsHere(t *testing.T) {
	rs := newReplicas(t, 1)
	if ok, err := rs.store.Claim(context.Background(), sharedListURI, statuslist.FormJWT, "other", rs.now, rs.now.Add(35*time.Second)); !ok || err != nil {
		t.Fatalf("Claim: %v, %v", ok, err)
	}
	rs.ok(0)
	rs.expectReads(1)
	if head, err := rs.store.Head(context.Background(), sharedListURI, statuslist.FormJWT); err != nil || !head.Stored {
		t.Fatalf("Head = %+v, %v; want the token stored", head, err)
	}
}

// Invalidate has its replica sign anew, whatever the store holds, and
// the others serve that token from their next check.
func TestPublisher_TokensInvalidate(t *testing.T) {
	rs := newReplicas(t, 2)
	first := rs.ok(0)
	rs.now = rs.now.Add(time.Second)
	rs.pubs[1].Invalidate()
	second := rs.ok(1)
	if second == first {
		t.Fatal("Invalidate: no new token")
	}
	rs.expectReads(1, 1)
	if rs.ok(0) != first {
		t.Fatal("replica 0 checked the store before TokensCheck")
	}
	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	if rs.ok(0) != second {
		t.Fatal("replica 0: not the token Invalidate had signed")
	}
	rs.expectReads(1, 1)
}

// While the store fails, a replica serves the token it has, until its
// exp, and reports the error; with none, it answers 500. Once the store
// is back, sharing resumes.
func TestPublisher_TokensStoreDown(t *testing.T) {
	rs := newReplicas(t, 2)
	first := rs.ok(0)
	down := errors.New("store down")
	rs.store.Fail(down)
	rs.now = rs.now.Add(time.Minute)
	if rs.ok(0) != first || !errors.Is(rs.errs[0], down) {
		t.Fatalf("store down: error %v; want the token served and the error reported", rs.errs[0])
	}
	if rec := rs.get(1); rec.Code != http.StatusInternalServerError || !errors.Is(rs.errs[1], down) {
		t.Fatalf("store down, no token: %d, %v; want 500 and the error", rec.Code, rs.errs[1])
	}
	rs.store.Fail(nil)
	second := rs.ok(1)
	if second == first || rs.errs[1] != nil {
		t.Fatalf("store back: error %v", rs.errs[1])
	}
	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	if rs.ok(0) != second {
		t.Fatal("store back: replica 0 doesn't serve replica 1's token")
	}
	rs.expectReads(1, 1)
}

// x5cLeaf is the leaf certificate in a JWT's x5c header.
func x5cLeaf(t *testing.T, jwt string) []byte {
	t.Helper()
	header, err := base64.RawURLEncoding.DecodeString(strings.SplitN(jwt, ".", 2)[0])
	if err != nil {
		t.Fatal(err)
	}
	var h struct {
		X5C []string `json:"x5c"`
	}
	if err := json.Unmarshal(header, &h); err != nil || len(h.X5C) == 0 {
		t.Fatalf("header %s: %v", header, err)
	}
	leaf, err := base64.StdEncoding.DecodeString(h.X5C[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// After a replica's signer changes — a new key and certificate for the
// list, as when a document signer is revoked — it signs its own token
// from the same version rather than serve the old signer's, and a
// replica still on the old signer, until it changes too, signs its
// own again: each serves only tokens its own certificate is in.
func TestPublisher_TokensRotatedSigner(t *testing.T) {
	rs := newReplicas(t, 2)
	oldLeaf := rs.pubs[0].Chain[0]
	old := rs.ok(0)
	if !bytes.Equal(x5cLeaf(t, old), oldLeaf.Raw) {
		t.Fatal("the first token isn't the old signer's")
	}
	ca, caKey := testcert.CA(t, "rotated status CA")
	newCert, newKey := testcert.Leaf(t, "status signer, rotated", ca, caKey)
	rs.pubs[1].Signer, rs.pubs[1].Chain = newKey, []*x509.Certificate{newCert}
	rs.now = rs.now.Add(time.Second)
	rotated := rs.ok(1)
	if rotated == old || !bytes.Equal(x5cLeaf(t, rotated), newCert.Raw) {
		t.Fatal("the rotated replica served the old signer's token")
	}
	rs.expectReads(1, 1)

	rs.now = rs.now.Add(statuslist.DefaultTokensCheck)
	if again := rs.ok(0); !bytes.Equal(x5cLeaf(t, again), oldLeaf.Raw) {
		t.Fatal("a replica on the old signer served the new signer's token")
	}
	rs.expectReads(2, 1)
}

// A replica that holds the lease but can't sign — its statuses can't be
// read, say — doesn't hold the others to the token signed before a
// revocation: they sign their own within CacheFor of it, rather than
// serve it until it expires an hour later.
func TestPublisher_TokensFailingHolder(t *testing.T) {
	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	store := statuslisttest.NewMemoryTokenStore()
	now := time.UnixMilli(time.Now().UnixMilli())
	var revoked, aBroken atomic.Bool
	publisher := func(broken *atomic.Bool) *statuslist.Publisher {
		return &statuslist.Publisher{
			URI: sharedListURI, Signer: key, Chain: []*x509.Certificate{cert},
			Lifetime: time.Hour, CacheFor: 30 * time.Second, Tokens: store,
			Statuses: func(context.Context) ([]uint8, error) {
				if broken.Load() {
					return nil, errors.New("this replica's statuses can't be read")
				}
				if revoked.Load() {
					return []uint8{0, 1}, nil
				}
				return []uint8{0, 0}, nil
			},
			Now: func() time.Time { return now },
		}
	}
	var bBroken atomic.Bool
	a, b := publisher(&aBroken), publisher(&bBroken)
	get := func(p *statuslist.Publisher) string {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, sharedListURI, nil))
		return rec.Body.String()
	}
	old := get(a)
	if get(b) != old {
		t.Fatal("b didn't serve a's token")
	}
	revoked.Store(true)
	store.Bump(sharedListURI)
	aBroken.Store(true)
	for elapsed := 10 * time.Second; elapsed <= 50*time.Minute; elapsed += 10 * time.Second {
		now = now.Add(10 * time.Second)
		get(a)
		if get(b) != old {
			if elapsed > 30*time.Second+statuslist.DefaultTokensCheck {
				t.Errorf("b served a new token only %v after the revocation", elapsed)
			}
			return
		}
	}
	t.Fatal("b served the token from before the revocation for 50 minutes")
}

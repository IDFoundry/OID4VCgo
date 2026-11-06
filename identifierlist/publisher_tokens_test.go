package identifierlist

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/listhttp"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// oneTokenStore is a statuslist.TokenStore for one list's CWT form:
// its token, and a lease that every Claim gets.
type oneTokenStore struct {
	mu    sync.Mutex
	token *statuslist.StoredToken
}

func (s *oneTokenStore) Head(context.Context, string, statuslist.Form) (statuslist.TokenHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == nil {
		return statuslist.TokenHead{}, nil
	}
	head := statuslist.TokenHead{Stored: true, Token: *s.token}
	head.Token.Bytes = nil
	return head, nil
}

func (s *oneTokenStore) Token(context.Context, string, statuslist.Form) (statuslist.StoredToken, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == nil {
		return statuslist.StoredToken{}, false, nil
	}
	return *s.token, true, nil
}

func (s *oneTokenStore) Claim(context.Context, string, statuslist.Form, string, time.Time, time.Time) (bool, error) {
	return true, nil
}

func (s *oneTokenStore) Put(_ context.Context, _ string, form statuslist.Form, _ string, token statuslist.StoredToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if form != statuslist.FormCWT {
		panic("an identifier list stored as " + form.String())
	}
	if s.token == nil || s.token.SignedAt.Before(token.SignedAt) {
		s.token = &token
	}
	return nil
}

// Two replicas sharing a TokenStore: one signs, the other serves its
// token; Invalidate has a replica sign anew, which the other serves
// from its next check.
func TestPublisher_TokensShared(t *testing.T) {
	pki := newPKI(t)
	store := &oneTokenStore{}
	now := time.UnixMilli(time.Now().UnixMilli())
	var reads [2]atomic.Int32
	pubs := make([]*Publisher, 2)
	for i := range pubs {
		pubs[i] = &Publisher{
			URI: testURI, Signer: pki.key, Chain: []*x509.Certificate{pki.leaf}, TTL: time.Minute, Tokens: store,
			Identifiers: func(context.Context) ([][]byte, error) { reads[i].Add(1); return [][]byte{{0xcc}}, nil },
			Now:         func() time.Time { return now },
		}
	}
	serve := func(i int) string {
		t.Helper()
		rec := httptest.NewRecorder()
		pubs[i].ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("replica %d: %d %s", i, rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	first := serve(0)
	if serve(1) != first || reads[1].Load() != 0 {
		t.Fatal("replica 1 didn't serve replica 0's token")
	}
	now = now.Add(time.Second)
	pubs[1].Invalidate()
	second := serve(1)
	now = now.Add(statuslist.DefaultTokensCheck)
	if second == first || serve(0) != second || reads[0].Load() != 1 || reads[1].Load() != 1 {
		t.Fatal("after Invalidate: not one new token for both replicas")
	}
}

// A replica whose signer changed — a new certificate for the list —
// signs its own token rather than serve the one the old signer stored,
// and stores it under its own signer.
func TestPublisher_TokensRotatedSigner(t *testing.T) {
	pki := newPKI(t)
	newLeaf, newKey := testcert.Leaf(t, "identifier list signer, rotated", pki.ca, pki.caKey)
	store := &oneTokenStore{}
	now := time.UnixMilli(time.Now().UnixMilli())
	var reads atomic.Int32
	publisher := func(key crypto.Signer, leaf *x509.Certificate) *Publisher {
		return &Publisher{
			URI: testURI, Signer: key, Chain: []*x509.Certificate{leaf}, TTL: time.Minute, Tokens: store,
			Identifiers: func(context.Context) ([][]byte, error) { reads.Add(1); return [][]byte{{0xcc}}, nil },
			Now:         func() time.Time { return now },
		}
	}
	serve := func(p *Publisher) string {
		t.Helper()
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		return rec.Body.String()
	}
	old := serve(publisher(pki.key, pki.leaf))
	now = now.Add(time.Second)
	if serve(publisher(newKey, newLeaf)) == old || reads.Load() != 2 {
		t.Fatalf("the rotated replica served the old signer's token (%d reads)", reads.Load())
	}
	if !bytes.Equal(store.token.Signer, listhttp.SignerOf(newLeaf.Raw)) {
		t.Fatalf("stored token's signer %x, want the new certificate's", store.token.Signer)
	}
}

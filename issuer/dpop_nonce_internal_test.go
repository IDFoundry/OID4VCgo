package issuer

import (
	"context"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// blockingDPoPNonceStore is a DPoPNonceStore whose Issue waits for
// release once block is set, as a slow store's write does.
type blockingDPoPNonceStore struct {
	mu      sync.Mutex
	block   bool
	entered chan struct{}
	release chan struct{}
	issued  int
}

func (s *blockingDPoPNonceStore) Issue(context.Context, DPoPNonceIssuance) error {
	s.mu.Lock()
	block := s.block
	s.issued++
	s.mu.Unlock()
	if block {
		s.entered <- struct{}{}
		<-s.release
	}
	return nil
}

func (s *blockingDPoPNonceStore) Lookup(context.Context, DPoPNonceLookup) (DPoPNonceRecord, error) {
	return DPoPNonceRecord{}, ErrDPoPNonceUnknown
}

// TestCurrentDPoPNonce_SlowStoreDoesntStallOthers: while one call
// persists the next DPoP nonce in a slow store, others hand out the
// previous one, still valid, rather than waiting on the Issuer's lock
// (audit I-11); once the write completes, the new nonce is current.
func TestCurrentDPoPNonce_SlowStoreDoesntStallOthers(t *testing.T) {
	const lifetime = 10 * time.Minute
	store := &blockingDPoPNonceStore{entered: make(chan struct{}), release: make(chan struct{})}
	iss := &Issuer{cfg: Config{Limits: Limits{DPoPNonceLifetime: lifetime}}, deps: Dependencies{DPoPNonces: store, Random: rand.Reader}}
	ctx := context.Background()
	start := time.Unix(1_700_000_000, 0)

	first, err := iss.currentDPoPNonce(ctx, start)
	if err != nil {
		t.Fatal(err)
	}

	// Past half the lifetime: the next call rotates, and blocks in the store.
	rotateAt := start.Add(lifetime/2 + time.Second)
	store.mu.Lock()
	store.block = true
	store.mu.Unlock()
	rotated := make(chan string)
	go func() {
		nonce, err := iss.currentDPoPNonce(ctx, rotateAt)
		if err != nil {
			t.Error(err)
		}
		rotated <- nonce
	}()
	<-store.entered

	done := make(chan string)
	go func() {
		nonce, _ := iss.currentDPoPNonce(ctx, rotateAt)
		done <- nonce
	}()
	select {
	case got := <-done:
		if got != first {
			t.Errorf("during the rotation, got nonce %q, want the previous %q", got, first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a call waited on the slow store's write")
	}

	close(store.release)
	next := <-rotated
	if next == first {
		t.Fatal("the rotation returned the previous nonce")
	}
	if got, err := iss.currentDPoPNonce(ctx, rotateAt); err != nil || got != next {
		t.Errorf("after the rotation, nonce = %q, %v; want the new %q", got, err, next)
	}
	if store.issued != 2 {
		t.Errorf("store.Issue called %d times, want 2", store.issued)
	}
}

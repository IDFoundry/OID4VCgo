package walletflow

import (
	"context"
	"sync"
	"testing"
)

// A grant's lock goes once no refresh holds or waits for it.
func TestLockGrant_Pruned(t *testing.T) {
	w, err := New(Config{Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.lockGrant("g")()
		}()
	}
	wg.Wait()
	if n := len(w.grantLocks); n != 0 {
		t.Errorf("%d grant locks kept, want none", n)
	}
}

// A settled deferred credential's mark goes once it has left the store
// and no listing that may have begun before then is in flight; until
// then a listing skips it.
func TestSettled_Pruned(t *testing.T) {
	store := NewMemoryDeferredStore()
	w, err := New(Config{Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(), Deferred: store})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	w.markSettled("a")
	w.markDeleted("a")
	if len(w.settled) != 0 {
		t.Errorf("a mark kept with no listing in flight: %v", w.settled)
	}

	// A listing in flight while "b" settles keeps its mark until it ends.
	if err := store.PutDeferred(ctx, PendingDeferred{ID: "b"}); err != nil {
		t.Fatal(err)
	}
	w.mu.Lock()
	w.listings++
	w.mu.Unlock()
	w.markSettled("b")
	w.markDeleted("b")
	if deleted, ok := w.settled["b"]; !ok || !deleted {
		t.Fatalf("mark %v, %v during a listing, want kept", deleted, ok)
	}
	w.mu.Lock()
	w.endListing()
	w.mu.Unlock()
	if len(w.settled) != 0 {
		t.Errorf("a mark kept after the listing ended: %v", w.settled)
	}

	// One still in the store keeps its mark, and isn't listed.
	w.markSettled("b")
	listed, err := w.Deferred(ctx)
	if err != nil || len(listed) != 0 {
		t.Errorf("Deferred = %v, %v; want the settling one skipped", listed, err)
	}
	if _, ok := w.settled["b"]; !ok {
		t.Error("the mark of one not yet deleted went")
	}
}

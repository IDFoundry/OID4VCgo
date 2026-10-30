package verifiertest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// This file is a reusable contract test for verifier.TransactionStore,
// the issuertest store contracts' twin: it checks what
// verifier.NewTransactions can't observe of a store it's given — that
// it gives back every Transaction field as it was saved, through
// Create and Update alike (a store that loses SameDevice, say, turns a
// same-device request into a cross-device one); that Update is atomic
// per transaction, which is what lets a transaction complete at most
// once and a response_code be redeemed at most once; and that the
// KeyID and ResponseCodeHash lookups follow the latest saved
// transaction. Like those, it doesn't check a real backend's
// durability, or that Update is atomic across instances sharing the
// store (StoreCapabilities.AtomicUpdate): only within this process.

// contractConcurrentUpdates is how many concurrent Updates the
// one-winner checks below fan out.
const contractConcurrentUpdates = 20

// TestTransactionStoreContract exercises factory()'s behavior against
// TransactionStore's own documented guarantees. factory must return a
// fresh, empty store each call — its subtests share nothing.
func TestTransactionStoreContract(t *testing.T, factory func() verifier.TransactionStore) {
	t.Helper()
	t.Run("CreateAndGet", func(t *testing.T) { testTxStoreCreateAndGet(t, factory()) })
	t.Run("CreateKeepsEveryField", func(t *testing.T) { testTxStoreCreateKeepsEveryField(t, factory()) })
	t.Run("UpdateKeepsEveryField", func(t *testing.T) { testTxStoreUpdateKeepsEveryField(t, factory()) })
	t.Run("CreateRefusesUsedID", func(t *testing.T) { testTxStoreCreateRefusesUsedID(t, factory()) })
	t.Run("UnknownIDIsErrTransactionUnknown", func(t *testing.T) { testTxStoreUnknown(t, factory()) })
	t.Run("UpdateErrorSavesNothing", func(t *testing.T) { testTxStoreUpdateErrorSavesNothing(t, factory()) })
	t.Run("ConcurrentUpdatesSerialize", func(t *testing.T) { testTxStoreConcurrentUpdatesSerialize(t, factory()) })
	t.Run("ConcurrentCompletionHasExactlyOneWinner", func(t *testing.T) { testTxStoreOneCompletion(t, factory()) })
	t.Run("ResponseCodeRedeemsOnce", func(t *testing.T) { testTxStoreResponseCodeRedeemsOnce(t, factory()) })
}

// contractTransaction is a pending transaction with id, its KeyID
// derived from it.
func contractTransaction(id string) verifier.Transaction {
	return verifier.Transaction{
		ID: id, KeyID: "kid-" + id, State: "state-" + id, Nonce: "nonce-" + id,
		RequestObject: "request-object-" + id, BrowserBindingHash: []byte("binding-hash-" + id), Owner: "owner-" + id,
		ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second), Status: verifier.TransactionPending,
	}
}

func mustCreate(t *testing.T, store verifier.TransactionStore, tx verifier.Transaction) {
	t.Helper()
	if err := store.Create(context.Background(), tx); err != nil {
		t.Fatalf("Create: %v", err)
	}
}

func testTxStoreCreateAndGet(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	want := contractTransaction("tx-1")
	mustCreate(t, store, want)
	got, err := store.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.KeyID != want.KeyID || got.State != want.State || got.Nonce != want.Nonce ||
		got.RequestObject != want.RequestObject || string(got.BrowserBindingHash) != string(want.BrowserBindingHash) ||
		!got.ExpiresAt.Equal(want.ExpiresAt) || got.Status != want.Status || got.Owner != want.Owner {
		t.Errorf("Get = %+v, want %+v", got, want)
	}
	if id, err := store.IDByKeyID(ctx, want.KeyID); err != nil || id != want.ID {
		t.Errorf("IDByKeyID = %q, %v; want %q", id, err, want.ID)
	}
}

func testTxStoreCreateRefusesUsedID(t *testing.T, store verifier.TransactionStore) {
	tx := contractTransaction("tx-1")
	mustCreate(t, store, tx)
	tx.KeyID = "another-kid"
	if err := store.Create(context.Background(), tx); err == nil {
		t.Error("Create with a used ID = nil error, want an error")
	}
}

func testTxStoreUnknown(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	if _, err := store.Get(ctx, "unknown"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Get: %v, want ErrTransactionUnknown", err)
	}
	if err := store.Update(ctx, "unknown", func(*verifier.Transaction) error { return nil }); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Update: %v, want ErrTransactionUnknown", err)
	}
	if _, err := store.IDByKeyID(ctx, "unknown"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("IDByKeyID: %v, want ErrTransactionUnknown", err)
	}
	if _, err := store.IDByResponseCode(ctx, "unknown"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("IDByResponseCode: %v, want ErrTransactionUnknown", err)
	}
}

func testTxStoreUpdateErrorSavesNothing(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	tx := contractTransaction("tx-1")
	mustCreate(t, store, tx)
	refused := errors.New("refused")
	err := store.Update(ctx, tx.ID, func(cur *verifier.Transaction) error {
		cur.Status, cur.ResponseCodeHash = verifier.TransactionAwaitingRedirect, "code-hash"
		return refused
	})
	if !errors.Is(err, refused) {
		t.Errorf("Update = %v, want fn's own error", err)
	}
	got, err := store.Get(ctx, tx.ID)
	if err != nil || got.Status != verifier.TransactionPending || got.ResponseCodeHash != "" {
		t.Errorf("Get after a refused Update = %+v, %v; want it unchanged", got, err)
	}
	if _, err := store.IDByResponseCode(ctx, "code-hash"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("IDByResponseCode after a refused Update: %v, want ErrTransactionUnknown", err)
	}
}

// testTxStoreConcurrentUpdatesSerialize: each concurrent Update sees
// the one before it, so none is lost.
func testTxStoreConcurrentUpdatesSerialize(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	tx := contractTransaction("tx-1")
	mustCreate(t, store, tx)
	runUpdates(contractConcurrentUpdates, func() bool {
		return store.Update(ctx, tx.ID, func(cur *verifier.Transaction) error {
			cur.LastError += "x"
			return nil
		}) == nil
	})
	got, err := store.Get(ctx, tx.ID)
	if err != nil || len(got.LastError) != contractConcurrentUpdates {
		t.Errorf("after %d concurrent Updates, each appending one byte: %d bytes, %v; want every Update seeing the previous one's result",
			contractConcurrentUpdates, len(got.LastError), err)
	}
}

// testTxStoreOneCompletion: of concurrent Updates that each complete a
// still-pending transaction, as Transactions.HandleResponse does, one
// wins.
func testTxStoreOneCompletion(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	tx := contractTransaction("tx-1")
	mustCreate(t, store, tx)
	wins := runUpdates(contractConcurrentUpdates, func() bool {
		return store.Update(ctx, tx.ID, func(cur *verifier.Transaction) error {
			if cur.Status != verifier.TransactionPending {
				return verifier.ErrTransactionAnswered
			}
			cur.Status = verifier.TransactionDone
			return nil
		}) == nil
	})
	if wins != 1 {
		t.Errorf("concurrent completions: %d winners, want exactly 1", wins)
	}
	if got, err := store.Get(ctx, tx.ID); err != nil || got.Status != verifier.TransactionDone {
		t.Errorf("Get after the completions = %+v, %v; want done", got, err)
	}
}

// testTxStoreResponseCodeRedeemsOnce: a response_code is found by its
// hash while set, redeemed by one of concurrent Updates that clear it,
// as Transactions.Redeem does, and not found after.
func testTxStoreResponseCodeRedeemsOnce(t *testing.T, store verifier.TransactionStore) {
	ctx := context.Background()
	tx := contractTransaction("tx-1")
	mustCreate(t, store, tx)
	const codeHash = "code-hash"
	err := store.Update(ctx, tx.ID, func(cur *verifier.Transaction) error {
		cur.Status, cur.ResponseCodeHash = verifier.TransactionAwaitingRedirect, codeHash
		return nil
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if id, err := store.IDByResponseCode(ctx, codeHash); err != nil || id != tx.ID {
		t.Fatalf("IDByResponseCode = %q, %v; want %q", id, err, tx.ID)
	}
	wins := runUpdates(contractConcurrentUpdates, func() bool {
		return store.Update(ctx, tx.ID, func(cur *verifier.Transaction) error {
			if cur.ResponseCodeHash != codeHash {
				return verifier.ErrTransactionUnknown
			}
			cur.Status, cur.ResponseCodeHash = verifier.TransactionDone, ""
			return nil
		}) == nil
	})
	if wins != 1 {
		t.Errorf("concurrent redeems: %d winners, want exactly 1", wins)
	}
	if _, err := store.IDByResponseCode(ctx, codeHash); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("IDByResponseCode after the redeem: %v, want ErrTransactionUnknown", err)
	}
}

// runUpdates calls fn attempts times in parallel and returns how many
// calls returned true.
func runUpdates(attempts int, fn func() bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(attempts)
	for range attempts {
		go func() {
			defer wg.Done()
			if fn() {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return successes
}

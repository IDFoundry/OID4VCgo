package verifiertest

import (
	"context"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// sameDeviceDroppingStore keeps every field but SameDevice, as a store
// whose schema lacks the column would.
type sameDeviceDroppingStore struct {
	*storage.VerifierTransactionStore
}

func (s sameDeviceDroppingStore) Create(ctx context.Context, tx verifier.Transaction) error {
	tx.SameDevice = false
	return s.VerifierTransactionStore.Create(ctx, tx)
}

func (s sameDeviceDroppingStore) Update(ctx context.Context, id string, fn func(*verifier.Transaction) error) error {
	return s.VerifierTransactionStore.Update(ctx, id, func(tx *verifier.Transaction) error {
		err := fn(tx)
		tx.SameDevice = false
		return err
	})
}

// TestFieldChecksCatchALossyStore: the checks
// CreateKeepsEveryField and UpdateKeepsEveryField make find a store
// that drops SameDevice, which the contract once passed.
func TestFieldChecksCatchALossyStore(t *testing.T) {
	ctx := context.Background()
	store := sameDeviceDroppingStore{storage.NewVerifierTransactionStore()}
	want := populatedTransaction(t, "tx-1")
	mustCreate(t, store, want)
	got, err := store.Get(ctx, want.ID)
	if err != nil {
		t.Fatal(err)
	}
	if lost := differingFields(want, got); !slices.Equal(lost, []string{"SameDevice"}) {
		t.Errorf("after Create: differing fields %v, want [SameDevice]", lost)
	}
	if err := store.Update(ctx, want.ID, func(cur *verifier.Transaction) error {
		*cur = want
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if got, _ = store.Get(ctx, want.ID); !slices.Equal(differingFields(want, got), []string{"SameDevice"}) {
		t.Errorf("after Update: differing fields %v, want [SameDevice]", differingFields(want, got))
	}
	if lost := differingFields(want, want); len(lost) > 0 {
		t.Errorf("a transaction differs from itself in %v", lost)
	}
}

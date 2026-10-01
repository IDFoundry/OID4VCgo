package issuer

import (
	"context"
	"errors"
	"testing"
)

// mapDeferredStore is the least DeferredTransactionStore abandonDeferral
// needs.
type mapDeferredStore map[string]DeferredTransactionRecord

func (s mapDeferredStore) Get(_ context.Context, id string) (DeferredTransactionRecord, error) {
	r, ok := s[id]
	if !ok {
		return r, errors.New("unknown")
	}
	return r, nil
}
func (s mapDeferredStore) Create(_ context.Context, id string, r DeferredTransactionRecord) error {
	s[id] = r
	return nil
}
func (s mapDeferredStore) Update(_ context.Context, id string, fn func(*DeferredTransactionRecord) error) error {
	r, ok := s[id]
	if !ok {
		return errors.New("unknown")
	}
	if err := fn(&r); err != nil {
		return err
	}
	s[id] = r
	return nil
}
func (s mapDeferredStore) Invalidate(context.Context, string) error { return nil }

// TestAbandonDeferral: a transaction whose Credential Response never
// reached the Wallet is denied, so the deployment can't issue for it;
// one already resolved is left as it is.
func TestAbandonDeferral(t *testing.T) {
	store := mapDeferredStore{
		"pending": {Status: DeferredTransactionPending},
		"issued":  {Status: DeferredTransactionIssued},
	}
	iss := &Issuer{deps: Dependencies{DeferredTransactions: store}}
	iss.abandonDeferral(context.Background(), "pending")
	iss.abandonDeferral(context.Background(), "issued")
	iss.abandonDeferral(context.Background(), "unknown")
	if store["pending"].Status != DeferredTransactionDenied || store["issued"].Status != DeferredTransactionIssued {
		t.Errorf("statuses = %v / %v, want denied / issued", store["pending"].Status, store["issued"].Status)
	}
}

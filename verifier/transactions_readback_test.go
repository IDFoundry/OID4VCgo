package verifier_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// lossyStore is a TransactionStore whose schema lacks a column: every
// field round-trips except the one drop clears.
type lossyStore struct {
	*storage.VerifierTransactionStore
	drop func(*verifier.Transaction)
}

func (s lossyStore) Create(ctx context.Context, tx verifier.Transaction) error {
	s.drop(&tx)
	return s.VerifierTransactionStore.Create(ctx, tx)
}

// TestTransactions_RefusesALossyStore: a store that loses SameDevice
// would answer a same-device request as a cross-device one — no
// redirect_uri, its result released to whichever browser polls
// (OpenID4VP §14.2, HAIP 1.0 §5.1) — and one that loses Origin would
// take a Digital Credentials API request for a redirect-flow one, so
// Begin and BeginDCAPI refuse each, on every request of that kind.
func TestTransactions_RefusesALossyStore(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	newTxs := func(drop func(*verifier.Transaction)) *verifier.Transactions {
		t.Helper()
		txs, err := verifier.NewTransactions(f.v, lossyStore{storage.NewVerifierTransactionStore(), drop}, verifier.TransactionsConfig{
			RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue", Verify: f.verify,
		})
		if err != nil {
			t.Fatal(err)
		}
		return txs
	}

	noSameDevice := newTxs(func(tx *verifier.Transaction) { tx.SameDevice = false })
	if _, err := noSameDevice.Begin(ctx, f.query, "browser-binding-cross-01", false); err != nil {
		t.Errorf("a cross-device Begin, which the store keeps whole: %v", err)
	}
	for range 2 {
		if _, err := noSameDevice.Begin(ctx, f.query, "attacker-browser-binding-01", true); err == nil || !strings.Contains(err.Error(), "SameDevice") {
			t.Errorf("a same-device Begin on a store that drops SameDevice: %v, want refused for it", err)
		}
	}

	noOrigin := newTxs(func(tx *verifier.Transaction) { tx.Origin = "" })
	if _, err := noOrigin.BeginDCAPI(ctx, f.query, "browser-binding-dcapi-01", dcapiOrigin); err == nil || !strings.Contains(err.Error(), "Origin") {
		t.Errorf("BeginDCAPI on a store that drops Origin: %v, want refused for it", err)
	}
}

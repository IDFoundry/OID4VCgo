package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An unauthenticated caller can make an issuer issue nonces, or a
// verifier begin transactions, it never redeems: the stores drop the
// expired ones as they grow, and keep the live ones.
func TestStoresPruneExpiredEntries(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	const n = 5000

	nonces := NewNonceStore()
	nonces.prune.now = func() time.Time { return now }
	for i := range n {
		_ = nonces.Issue(ctx, issuer.NonceIssuance{Nonce: fmt.Sprint("old-", i), ExpiresAt: past})
	}
	_ = nonces.Issue(ctx, issuer.NonceIssuance{Nonce: "live", ExpiresAt: future})
	if len(nonces.issued) >= minPruneAt*2 {
		t.Errorf("nonce store holds %d after %d expired nonces", len(nonces.issued), n)
	}
	if _, err := nonces.Consume(ctx, issuer.NonceConsumption{Nonce: "live"}); err != nil {
		t.Errorf("the live nonce: %v", err)
	}

	replay := NewDPoPReplayChecker()
	replay.prune.now = func() time.Time { return now }
	_ = replay.UseOnce(ctx, "live", future)
	for i := range n {
		_ = replay.UseOnce(ctx, fmt.Sprint("old-", i), past)
	}
	if len(replay.seen) >= minPruneAt*2 {
		t.Errorf("replay checker holds %d after %d expired proofs", len(replay.seen), n)
	}
	if err := replay.UseOnce(ctx, "live", future); err == nil {
		t.Error("a live jti was forgotten: its replay was accepted")
	}

	txs := NewVerifierTransactionStore()
	txs.prune.now = func() time.Time { return now }
	_ = txs.Create(ctx, verifier.Transaction{ID: "live", KeyID: "k-live", ExpiresAt: past})
	for i := range n {
		_ = txs.Create(ctx, verifier.Transaction{ID: fmt.Sprint("old-", i), KeyID: fmt.Sprint("k-", i), ExpiresAt: now.Add(-expiryGrace - time.Second)})
	}
	if len(txs.byID) >= minPruneAt*2 || len(txs.byKey) != len(txs.byID) {
		t.Errorf("transaction store holds %d (%d keys) after %d expired transactions", len(txs.byID), len(txs.byKey), n)
	}
	// Expired, but within the grace: a late poll still finds it.
	if _, err := txs.Get(ctx, "live"); err != nil {
		t.Errorf("a transaction within the grace: %v", err)
	}
}

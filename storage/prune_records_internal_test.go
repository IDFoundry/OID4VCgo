package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// The stores of issuer records the issuer creates per issuance —
// notification_ids, pre-authorized codes, Credential Offers, deferred
// transactions — drop the expired ones as they grow, and keep the live
// ones and those with no expiry.
func TestIssuerRecordStoresPruneExpiredEntries(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Minute), now.Add(time.Minute)
	clock := func() time.Time { return now }
	const n = 5000

	notifications := NewNotificationStore()
	notifications.prune.now = clock
	_ = notifications.Issue(ctx, "live", issuer.NotificationRecord{ExpiresAt: future})
	_ = notifications.Issue(ctx, "forever", issuer.NotificationRecord{})
	for i := range n {
		_ = notifications.Issue(ctx, fmt.Sprint("old-", i), issuer.NotificationRecord{ExpiresAt: past})
	}
	if len(notifications.records) >= minPruneAt*2 {
		t.Errorf("notification store holds %d after %d expired records", len(notifications.records), n)
	}
	for _, id := range []string{"live", "forever"} {
		if _, err := notifications.Get(ctx, id); err != nil {
			t.Errorf("notification %q: %v", id, err)
		}
	}

	codes := NewPreAuthorizedCodeStore()
	codes.prune.now = clock
	_ = codes.Issue(ctx, "live", issuer.PreAuthorizedCodeRecord{TxCodeHash: "123456", ExpiresAt: future})
	for i := range n {
		code := fmt.Sprint("old-", i)
		_ = codes.Issue(ctx, code, issuer.PreAuthorizedCodeRecord{TxCodeHash: "123456", ExpiresAt: past})
		_, _, _ = codes.Consume(ctx, code, "000000", 3, nil)
	}
	if len(codes.issued) >= minPruneAt*2 || len(codes.attempts) >= minPruneAt*2 {
		t.Errorf("pre-authorized code store holds %d codes, %d attempt counts after %d expired codes", len(codes.issued), len(codes.attempts), n)
	}
	if _, _, err := codes.Consume(ctx, "live", "123456", 3, nil); err != nil {
		t.Errorf("the live code: %v", err)
	}

	offers := NewCredentialOfferStore()
	offers.prune.now = clock
	_ = offers.Store(ctx, issuer.CredentialOfferRecord{Reference: "live", ExpiresAt: future})
	for i := range n {
		_ = offers.Store(ctx, issuer.CredentialOfferRecord{Reference: fmt.Sprint("old-", i), ExpiresAt: past})
	}
	if len(offers.records) >= minPruneAt*2 {
		t.Errorf("credential offer store holds %d after %d expired offers", len(offers.records), n)
	}
	if _, err := offers.Get(ctx, "live"); err != nil {
		t.Errorf("the live offer: %v", err)
	}

	txs := NewDeferredTransactionStore()
	txs.prune.now = clock
	_ = txs.Create(ctx, "live", issuer.DeferredTransactionRecord{ExpiresAt: future})
	_ = txs.Create(ctx, "forever", issuer.DeferredTransactionRecord{})
	for i := range n {
		id := fmt.Sprint("old-", i)
		_ = txs.Create(ctx, id, issuer.DeferredTransactionRecord{ExpiresAt: past})
		_ = txs.Invalidate(ctx, id)
	}
	if len(txs.records) >= minPruneAt*2 || len(txs.invalidated) >= minPruneAt*2 {
		t.Errorf("deferred transaction store holds %d records, %d invalidated after %d expired transactions", len(txs.records), len(txs.invalidated), n)
	}
	for _, id := range []string{"live", "forever"} {
		if _, err := txs.Get(ctx, id); err != nil {
			t.Errorf("transaction %q: %v", id, err)
		}
	}
}

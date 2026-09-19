package issuer

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// This file is a reusable contract test suite, not a _test.go file,
// specifically so a caller's own store implementation can import it
// and run it against its own factory — the same "ship the test, not
// just the interface" pattern FAPIgo's own storage.TestGrantStoreContract
// establishes (storage/contract.go there), extended here since this
// package's own store interfaces (NonceStore, PreAuthorizedCodeStore,
// DPoPReplayChecker, CredentialOfferStore, DeferredTransactionStore,
// NotificationStore, DPoPNonceStore) have no FAPIgo equivalent to
// reuse. This does not verify a real backend's actual durability —
// storage.DPoPReplayChecker and friends pass every check here despite
// being explicitly documented as development/testing only (see
// storage/doc.go) — only the in-process behavior New's own
// AssuranceProduction check can't itself observe: atomicity,
// single-use semantics, and faithful field round-tripping.

// contractConcurrentAttempts bounds how many concurrent calls the
// *IsSingleUse/*HasExactlyOneWinner checks below fan out — enough to
// make a non-atomic implementation (e.g. a naive
// check-then-write with no locking) fail reliably, without making the
// suite slow.
const contractConcurrentAttempts = 20

// runConcurrently calls fn attempts times in parallel and returns how
// many calls returned true.
func runConcurrently(attempts int, fn func() bool) int {
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
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

// TestNonceStoreContract exercises factory()'s behavior against
// NonceStore's own documented guarantees: Consume atomically retrieves
// and retires a nonce, an unknown or already-consumed nonce is
// rejected, and exactly one winner exists under concurrent Consume of
// the same nonce. factory must return a fresh, empty NonceStore each
// call — its subtests share nothing between them.
func TestNonceStoreContract(t *testing.T, factory func() NonceStore) {
	t.Helper()
	testAtomicNonceContract(t, func() (issue func(nonce string, expiresAt time.Time) error, consume func(nonce string) (time.Time, error)) {
		store := factory()
		ctx := context.Background()
		return func(nonce string, exp time.Time) error {
				return store.Issue(ctx, NonceIssuance{Nonce: nonce, ExpiresAt: exp})
			}, func(nonce string) (time.Time, error) {
				r, err := store.Consume(ctx, NonceConsumption{Nonce: nonce})
				return r.ExpiresAt, err
			}
	})
}

// TestDPoPNonceStoreContract is TestNonceStoreContract's own twin for
// DPoPNonceStore — see that function's doc comment; the two stores
// share an identical contract shape (Issue once, Consume atomically
// retires), differing only in the concrete Issuance/Consumption/Record
// types wrapping an identical Nonce/ExpiresAt pair.
func TestDPoPNonceStoreContract(t *testing.T, factory func() DPoPNonceStore) {
	t.Helper()
	testAtomicNonceContract(t, func() (issue func(nonce string, expiresAt time.Time) error, consume func(nonce string) (time.Time, error)) {
		store := factory()
		ctx := context.Background()
		return func(nonce string, exp time.Time) error {
				return store.Issue(ctx, DPoPNonceIssuance{Nonce: nonce, ExpiresAt: exp})
			}, func(nonce string) (time.Time, error) {
				r, err := store.Consume(ctx, DPoPNonceConsumption{Nonce: nonce})
				return r.ExpiresAt, err
			}
	})
}

// testAtomicNonceContract runs the shared checks TestNonceStoreContract
// and TestDPoPNonceStoreContract both need against newAdapter, which
// must build a fresh issue/consume pair (backed by a fresh, empty
// store) each time it's called.
func testAtomicNonceContract(t *testing.T, newAdapter func() (issue func(nonce string, expiresAt time.Time) error, consume func(nonce string) (time.Time, error))) {
	t.Helper()

	t.Run("IssueAndConsume", func(t *testing.T) {
		issue, consume := newAdapter()
		exp := time.Now().Add(time.Minute).Truncate(time.Second)
		if err := issue("n1", exp); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		got, err := consume("n1")
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if !got.Equal(exp) {
			t.Errorf("ExpiresAt = %v, want %v", got, exp)
		}
	})

	t.Run("ConsumeIsSingleUse", func(t *testing.T) {
		issue, consume := newAdapter()
		if err := issue("n1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, err := consume("n1"); err != nil {
			t.Fatalf("first Consume: %v", err)
		}
		if _, err := consume("n1"); err == nil {
			t.Error("second Consume = nil error, want error (nonce already consumed)")
		}
	})

	t.Run("ConsumeUnknownFails", func(t *testing.T) {
		_, consume := newAdapter()
		if _, err := consume("never-issued"); err == nil {
			t.Error("Consume = nil error, want error (unknown nonce)")
		}
	})

	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) {
		issue, consume := newAdapter()
		if err := issue("n1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		wins := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := consume("n1")
			return err == nil
		})
		if wins != 1 {
			t.Errorf("concurrent Consume: %d winners, want exactly 1", wins)
		}
	})
}

// TestPreAuthorizedCodeStoreContract exercises factory()'s behavior
// against PreAuthorizedCodeStore's own documented guarantees —
// including the one genuinely security-relevant rule beyond plain
// atomicity: a wrong TxCode must leave the code consumable (not
// invalidate it), so a mistyped PIN doesn't permanently destroy a
// legitimate holder's only redemption path (see Consume's own doc
// comment; this was a real finding in a past security review of an
// earlier implementation that got this backwards). factory must
// return a fresh, empty PreAuthorizedCodeStore each call.
func TestPreAuthorizedCodeStoreContract(t *testing.T, factory func() PreAuthorizedCodeStore) {
	t.Helper()

	t.Run("IssueAndConsumeNoTxCode", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		want := PreAuthorizedCodeRecord{
			Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"cfg1"},
			ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second),
		}
		if err := store.Issue(ctx, "code1", want); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		got, _, err := store.Consume(ctx, "code1", "")
		if err != nil {
			t.Fatalf("Consume: %v", err)
		}
		if len(got.Scopes) != 1 || got.Scopes[0] != "identity_credential" {
			t.Errorf("Scopes = %v", got.Scopes)
		}
		if len(got.CredentialConfigurationIDs) != 1 || got.CredentialConfigurationIDs[0] != "cfg1" {
			t.Errorf("CredentialConfigurationIDs = %v", got.CredentialConfigurationIDs)
		}
		if !got.ExpiresAt.Equal(want.ExpiresAt) {
			t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
		}
	})

	t.Run("ConsumeIsSingleUse", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, _, err := store.Consume(ctx, "code1", ""); err != nil {
			t.Fatalf("first Consume: %v", err)
		}
		if _, _, err := store.Consume(ctx, "code1", ""); err == nil {
			t.Error("second Consume = nil error, want error (code already consumed)")
		}
	})

	t.Run("ConsumeUnknownFails", func(t *testing.T) {
		store := factory()
		if _, _, err := store.Consume(context.Background(), "never-issued", ""); err == nil {
			t.Error("Consume = nil error, want error (unknown code)")
		}
	})

	t.Run("WrongTxCodeLeavesCodeConsumable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{TxCode: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, _, err := store.Consume(ctx, "code1", "0000"); !errors.Is(err, ErrWrongTxCode) {
			t.Fatalf("Consume with wrong tx_code: err = %v, want ErrWrongTxCode", err)
		}
		// The code must still be redeemable with the correct TxCode —
		// a wrong guess must not have invalidated it.
		if _, _, err := store.Consume(ctx, "code1", "1234"); err != nil {
			t.Fatalf("Consume with correct tx_code after a wrong guess: %v", err)
		}
	})

	t.Run("CorrectTxCodeConsumes", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{TxCode: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if _, _, err := store.Consume(ctx, "code1", "1234"); err != nil {
			t.Fatalf("Consume: %v", err)
		}
	})

	t.Run("WrongTxCodeIncrementsAttempts", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{TxCode: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		for want := 1; want <= 3; want++ {
			_, attempts, err := store.Consume(ctx, "code1", "0000")
			if !errors.Is(err, ErrWrongTxCode) {
				t.Fatalf("Consume with wrong tx_code (attempt %d): err = %v, want ErrWrongTxCode", want, err)
			}
			if attempts != want {
				t.Errorf("wrongAttempts = %d, want %d", attempts, want)
			}
		}
	})

	t.Run("InvalidateThenConsumeFails", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if err := store.Invalidate(ctx, "code1"); err != nil {
			t.Fatalf("Invalidate: %v", err)
		}
		if _, _, err := store.Consume(ctx, "code1", ""); err == nil {
			t.Error("Consume after Invalidate = nil error, want error")
		}
	})

	t.Run("InvalidateUnknownCodeIsNoop", func(t *testing.T) {
		store := factory()
		if err := store.Invalidate(context.Background(), "never-issued"); err != nil {
			t.Errorf("Invalidate on an unknown code: %v, want nil (no-op)", err)
		}
	})

	t.Run("ConcurrentWrongAttemptsAreCountedExactly", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{TxCode: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		var mu sync.Mutex
		seen := make(map[int]int, contractConcurrentAttempts)
		runConcurrently(contractConcurrentAttempts, func() bool {
			_, attempts, err := store.Consume(ctx, "code1", "0000")
			if !errors.Is(err, ErrWrongTxCode) {
				return false
			}
			mu.Lock()
			seen[attempts]++
			mu.Unlock()
			return true
		})
		// Every concurrent wrong guess must have observed a distinct
		// count — a lost update (two goroutines both incrementing from
		// the same stale value) would show up as a duplicate.
		for attempts, count := range seen {
			if count != 1 {
				t.Errorf("wrongAttempts=%d was observed %d times, want exactly 1 (lost update under concurrency)", attempts, count)
			}
		}
		if len(seen) != contractConcurrentAttempts {
			t.Errorf("observed %d distinct wrongAttempts values, want %d", len(seen), contractConcurrentAttempts)
		}
	})

	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "code1", PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		wins := runConcurrently(contractConcurrentAttempts, func() bool {
			_, _, err := store.Consume(ctx, "code1", "")
			return err == nil
		})
		if wins != 1 {
			t.Errorf("concurrent Consume: %d winners, want exactly 1", wins)
		}
	})
}

// TestDPoPReplayCheckerContract exercises factory()'s behavior against
// DPoPReplayChecker's own documented guarantee (RFC 9449 §11.1): a
// "jti" is accepted the first time UseOnce sees it and rejected every
// time after, with exactly one winner under concurrent use of the same
// jti. factory must return a fresh, empty DPoPReplayChecker each call.
func TestDPoPReplayCheckerContract(t *testing.T, factory func() DPoPReplayChecker) {
	t.Helper()

	t.Run("FirstUseSucceeds", func(t *testing.T) {
		store := factory()
		if err := store.UseOnce(context.Background(), "jti1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf("UseOnce: %v", err)
		}
	})

	t.Run("SecondUseFails", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute)
		if err := store.UseOnce(ctx, "jti1", exp); err != nil {
			t.Fatalf("first UseOnce: %v", err)
		}
		if err := store.UseOnce(ctx, "jti1", exp); err == nil {
			t.Error("second UseOnce = nil error, want error (jti already used)")
		}
	})

	t.Run("DifferentJTIsAreIndependent", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute)
		if err := store.UseOnce(ctx, "jti1", exp); err != nil {
			t.Fatalf("UseOnce(jti1): %v", err)
		}
		if err := store.UseOnce(ctx, "jti2", exp); err != nil {
			t.Fatalf("UseOnce(jti2): %v", err)
		}
	})

	t.Run("ConcurrentUseOnceHasExactlyOneWinner", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute)
		wins := runConcurrently(contractConcurrentAttempts, func() bool {
			return store.UseOnce(ctx, "jti1", exp) == nil
		})
		if wins != 1 {
			t.Errorf("concurrent UseOnce: %d winners, want exactly 1", wins)
		}
	})
}

// testGetIsRepeatable runs the shared "seed a record, then Get it
// twice" check TestCredentialOfferStoreContract and
// TestNotificationStoreContract both need — unlike NonceStore's own
// Consume, Get is explicitly NOT single-use for either interface.
func testGetIsRepeatable(t *testing.T, seed func() error, get func() error, why string) {
	t.Helper()
	if err := seed(); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := get(); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if err := get(); err != nil {
		t.Errorf("second Get: %v, want a repeated Get to still succeed (%s)", err, why)
	}
}

// testGetUnknownFails runs the shared "Get an unseeded key fails"
// check several contract tests in this file need.
func testGetUnknownFails(t *testing.T, get func() error, why string) {
	t.Helper()
	if err := get(); err == nil {
		t.Errorf("Get = nil error, want error (%s)", why)
	}
}

// TestCredentialOfferStoreContract exercises factory()'s behavior
// against CredentialOfferStore's own documented guarantee — unlike
// NonceStore, Get is explicitly NOT single-use (a Wallet's retried GET
// of the same by-reference Credential Offer must not fail just because
// an earlier fetch already succeeded); this is the one property most
// worth a caller verifying, since it's easy to accidentally copy a
// consume-once implementation from a sibling store. factory must
// return a fresh, empty CredentialOfferStore each call.
func TestCredentialOfferStoreContract(t *testing.T, factory func() CredentialOfferStore) {
	t.Helper()

	t.Run("StoreAndGet", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute).Truncate(time.Second)
		want := CredentialOfferRecord{Reference: "ref1", ExpiresAt: exp}
		if err := store.Store(ctx, want); err != nil {
			t.Fatalf("Store: %v", err)
		}
		got, err := store.Get(ctx, "ref1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Reference != "ref1" {
			t.Errorf("Reference = %q, want ref1", got.Reference)
		}
		if !got.ExpiresAt.Equal(exp) {
			t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, exp)
		}
	})

	t.Run("GetIsRepeatable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		testGetIsRepeatable(t,
			func() error {
				return store.Store(ctx, CredentialOfferRecord{Reference: "ref1", ExpiresAt: time.Now().Add(time.Minute)})
			},
			func() error { _, err := store.Get(ctx, "ref1"); return err },
			"not single-use")
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := factory()
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), "never-stored"); return err }, "unknown reference")
	})
}

// TestNotificationStoreContract exercises factory()'s behavior against
// NotificationStore's own documented guarantee — like
// CredentialOfferStore, and unlike NonceStore, Get is explicitly NOT
// single-use: §11's own idempotency requirement means a
// notification_id must keep validating after the first Notification
// Request that presents it. factory must return a fresh, empty
// NotificationStore each call.
func TestNotificationStoreContract(t *testing.T, factory func() NotificationStore) {
	t.Helper()

	t.Run("IssueAndGet", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "notif1", NotificationRecord{ClientID: "client-1"}); err != nil {
			t.Fatalf("Issue: %v", err)
		}
		got, err := store.Get(ctx, "notif1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ClientID != "client-1" {
			t.Errorf("ClientID = %q, want client-1", got.ClientID)
		}
	})

	t.Run("GetIsRepeatable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		testGetIsRepeatable(t,
			func() error { return store.Issue(ctx, "notif1", NotificationRecord{ClientID: "client-1"}) },
			func() error { _, err := store.Get(ctx, "notif1"); return err },
			"§11 idempotency")
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := factory()
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), "never-issued"); return err }, "unknown notification_id")
	})
}

// TestDeferredTransactionStoreContract exercises seed()'s behavior
// against DeferredTransactionStore's own documented guarantee. Unlike
// every other contract test in this file, this one takes a seed
// function rather than an empty-store factory: DeferredTransactionStore
// deliberately has no Create/Store method at all (see its own doc
// comment — creating a transaction is entirely the caller's own
// business process, outside this interface's scope), so there is no
// interface method this test could use to populate one itself. seed
// must return a store containing exactly one record, keyed by
// transactionID, equal to record.
func TestDeferredTransactionStoreContract(t *testing.T, seed func(t *testing.T, transactionID string, record DeferredTransactionRecord) DeferredTransactionStore) {
	t.Helper()

	t.Run("Get", func(t *testing.T) {
		want := DeferredTransactionRecord{ClientID: "client-1", Status: DeferredTransactionPending}
		store := seed(t, "txn1", want)
		got, err := store.Get(context.Background(), "txn1")
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.ClientID != want.ClientID {
			t.Errorf("ClientID = %q, want %q", got.ClientID, want.ClientID)
		}
		if got.Status != want.Status {
			t.Errorf("Status = %v, want %v", got.Status, want.Status)
		}
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := seed(t, "txn1", DeferredTransactionRecord{})
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), "never-seeded"); return err }, "unknown transaction_id")
	})

	t.Run("InvalidateThenGetFails", func(t *testing.T) {
		store := seed(t, "txn1", DeferredTransactionRecord{Status: DeferredTransactionIssued})
		ctx := context.Background()
		if err := store.Invalidate(ctx, "txn1"); err != nil {
			t.Fatalf("Invalidate: %v", err)
		}
		if _, err := store.Get(ctx, "txn1"); err == nil {
			t.Error("Get after Invalidate = nil error, want error (transaction_id no longer valid)")
		}
	})
}

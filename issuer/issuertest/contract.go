// Package issuertest holds reusable contract tests for issuer's store
// interfaces, for a caller testing its own store implementation. It
// imports "testing": import it only from _test.go files.
package issuertest

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
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
// single-use semantics (or, for DPoPNonceStore, repeatable lookups),
// and faithful field round-tripping, the Owner that keeps the records
// of Credential Issuers sharing a store apart included.

// contractConcurrentAttempts bounds how many concurrent calls the
// *IsSingleUse/*HasExactlyOneWinner checks below fan out — enough to
// make a non-atomic implementation (e.g. a naive
// check-then-write with no locking) fail reliably, without making the
// suite slow.
const contractConcurrentAttempts = 20

// Repeated t.Fatalf/t.Errorf format strings and fixture values shared
// across this file's own contract checks.
const (
	msgIssueFailed       = "Issue: %v"
	msgConsumeFailed     = "Consume: %v"
	msgLookupFailed      = "Lookup: %v"
	msgGetFailed         = "Get: %v"
	msgExpiresAtMismatch = "ExpiresAt = %v, want %v"
	nonceNeverIssued     = "never-issued"
	contractClientID     = "client-1"
	contractOwner        = "https://issuer-a.example.com"
	msgOwnerMismatch     = "Owner = %q, want %q: the store must keep every record field, or Credential Issuers sharing it can't be kept apart"
)

// canceledContext is a context already canceled, for the
// CanceledContextIsNotUnknown checks.
func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// requireNotUnknown fails the test if err, from a store asked about a
// record it holds with a canceled context, wraps unknown: a store may
// still answer, or fail with the context's error, but mustn't report a
// record it holds as unknown — the issuer answers that as the Wallet's
// error, where a store that couldn't answer is a 500.
func requireNotUnknown(t *testing.T, err, unknown error) {
	t.Helper()
	if errors.Is(err, unknown) {
		t.Errorf("with a canceled context: %v, want a result or another error (the record exists; %v is for one that doesn't)", err, unknown)
	}
}

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
func TestNonceStoreContract(t *testing.T, factory func() issuer.NonceStore) {
	t.Helper()
	t.Run("CanceledContextIsNotUnknown", func(t *testing.T) {
		store := factory()
		if err := store.Issue(context.Background(), issuer.NonceIssuance{Nonce: "n1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		_, err := store.Consume(canceledContext(), issuer.NonceConsumption{Nonce: "n1"})
		requireNotUnknown(t, err, issuer.ErrNonceUnknown)
	})
	t.Run("OwnerRoundTrips", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, issuer.NonceIssuance{Nonce: "n1", Owner: contractOwner, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		got, err := store.Consume(ctx, issuer.NonceConsumption{Nonce: "n1", Owner: contractOwner})
		if err != nil {
			t.Fatalf(msgConsumeFailed, err)
		}
		if got.Owner != contractOwner {
			t.Errorf(msgOwnerMismatch, got.Owner, contractOwner)
		}
	})
	t.Run("AnotherOwnerCantConsume", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, issuer.NonceIssuance{Nonce: "n1", Owner: contractOwner, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		if _, err := store.Consume(ctx, issuer.NonceConsumption{Nonce: "n1", Owner: "https://issuer-b.example.com"}); !errors.Is(err, issuer.ErrNonceUnknown) {
			t.Errorf("Consume by another Owner = %v, want issuer.ErrNonceUnknown", err)
		}
		if _, err := store.Consume(ctx, issuer.NonceConsumption{Nonce: "n1", Owner: contractOwner}); err != nil {
			t.Errorf("Consume by its Owner after another's attempt: %v, want the nonce left in place", err)
		}
	})
	testAtomicNonceContract(t, func() (issue func(nonce string, expiresAt time.Time) error, consume func(nonce string) (time.Time, error)) {
		store := factory()
		ctx := context.Background()
		return func(nonce string, exp time.Time) error {
				return store.Issue(ctx, issuer.NonceIssuance{Nonce: nonce, ExpiresAt: exp})
			}, func(nonce string) (time.Time, error) {
				r, err := store.Consume(ctx, issuer.NonceConsumption{Nonce: nonce})
				return r.ExpiresAt, err
			}
	})
}

// TestDPoPNonceStoreContract exercises factory()'s behavior against
// DPoPNonceStore's own documented guarantees. Unlike NonceStore's
// c_nonce, a DPoP nonce is valid for a time window, not for one use
// (RFC 9449 §8): Lookup returns the record Issue persisted and leaves
// it in place, so repeated and concurrent Lookups of one nonce all
// succeed; several issued nonces are valid side by side (the current
// one and the previous, during a rotation); and an unknown nonce is
// ErrDPoPNonceUnknown, which the issuer answers with a use_dpop_nonce
// challenge rather than a 500. factory must return a fresh, empty
// DPoPNonceStore each call.
func TestDPoPNonceStoreContract(t *testing.T, factory func() issuer.DPoPNonceStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("IssueAndLookup", func(t *testing.T) {
		store := factory()
		exp := time.Now().Add(time.Minute).Truncate(time.Second)
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "n1", ExpiresAt: exp}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		got, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "n1"})
		if err != nil {
			t.Fatalf(msgLookupFailed, err)
		}
		if !got.ExpiresAt.Equal(exp) {
			t.Errorf(msgExpiresAtMismatch, got.ExpiresAt, exp)
		}
	})

	t.Run("LookupIsRepeatable", func(t *testing.T) {
		store := factory()
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "n1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		for i := range 3 {
			if _, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "n1"}); err != nil {
				t.Fatalf("Lookup %d: %v", i+1, err)
			}
		}
	})

	t.Run("ConcurrentLookupsAllSucceed", func(t *testing.T) {
		store := factory()
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "n1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		wins := runConcurrently(contractConcurrentAttempts, func() bool {
			_, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "n1"})
			return err == nil
		})
		if wins != contractConcurrentAttempts {
			t.Errorf("concurrent Lookup: %d of %d succeeded, want all", wins, contractConcurrentAttempts)
		}
	})

	t.Run("SeveralNoncesAreValidTogether", func(t *testing.T) {
		store := factory()
		previous, current := time.Now().Add(time.Minute).Truncate(time.Second), time.Now().Add(2*time.Minute).Truncate(time.Second)
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "previous", ExpiresAt: previous}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "current", ExpiresAt: current}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		for nonce, want := range map[string]time.Time{"previous": previous, "current": current} {
			got, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: nonce})
			if err != nil {
				t.Fatalf("Lookup %s: %v", nonce, err)
			}
			if !got.ExpiresAt.Equal(want) {
				t.Errorf(msgExpiresAtMismatch, got.ExpiresAt, want)
			}
		}
	})

	t.Run("LookupUnknownIsErrDPoPNonceUnknown", func(t *testing.T) {
		store := factory()
		if _, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: nonceNeverIssued}); !errors.Is(err, issuer.ErrDPoPNonceUnknown) {
			t.Errorf("Lookup = %v, want an error wrapping issuer.ErrDPoPNonceUnknown", err)
		}
	})

	// A store may drop a record after its ExpiresAt, so a Lookup of an
	// expired nonce either finds it (the caller then refuses it by its
	// ExpiresAt) or reports it unknown — never a store failure.
	t.Run("LookupExpiredIsFoundOrUnknown", func(t *testing.T) {
		store := factory()
		exp := time.Now().Add(-time.Minute).Truncate(time.Second)
		if err := store.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "n1", ExpiresAt: exp}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		got, err := store.Lookup(ctx, issuer.DPoPNonceLookup{Nonce: "n1"})
		switch {
		case err == nil && !got.ExpiresAt.Equal(exp):
			t.Errorf(msgExpiresAtMismatch, got.ExpiresAt, exp)
		case err != nil && !errors.Is(err, issuer.ErrDPoPNonceUnknown):
			t.Errorf("Lookup of an expired nonce = %v, want its record or issuer.ErrDPoPNonceUnknown", err)
		}
	})
}

// testAtomicNonceContract runs TestNonceStoreContract's checks against
// newAdapter, which must build a fresh issue/consume pair (backed by a
// fresh, empty store) each time it's called.
func testAtomicNonceContract(t *testing.T, newAdapter func() (issue func(nonce string, expiresAt time.Time) error, consume func(nonce string) (time.Time, error))) {
	t.Helper()

	t.Run("IssueAndConsume", func(t *testing.T) {
		issue, consume := newAdapter()
		exp := time.Now().Add(time.Minute).Truncate(time.Second)
		if err := issue("n1", exp); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		got, err := consume("n1")
		if err != nil {
			t.Fatalf(msgConsumeFailed, err)
		}
		if !got.Equal(exp) {
			t.Errorf(msgExpiresAtMismatch, got, exp)
		}
	})

	t.Run("ConsumeIsSingleUse", func(t *testing.T) {
		issue, consume := newAdapter()
		if err := issue("n1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		if _, err := consume("n1"); err != nil {
			t.Fatalf("first Consume: %v", err)
		}
		if _, err := consume("n1"); !errors.Is(err, issuer.ErrNonceUnknown) {
			t.Errorf("second Consume = %v, want issuer.ErrNonceUnknown (nonce already consumed)", err)
		}
	})

	t.Run("ConsumeUnknownFails", func(t *testing.T) {
		_, consume := newAdapter()
		if _, err := consume(nonceNeverIssued); !errors.Is(err, issuer.ErrNonceUnknown) {
			t.Errorf("Consume = %v, want issuer.ErrNonceUnknown (unknown nonce)", err)
		}
	})

	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) {
		issue, consume := newAdapter()
		if err := issue("n1", time.Now().Add(time.Minute)); err != nil {
			t.Fatalf(msgIssueFailed, err)
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
// atomicity: a wrong TxCodeHash must leave the code consumable (not
// invalidate it), so a mistyped PIN doesn't permanently destroy a
// legitimate holder's only redemption path (see Consume's own doc
// comment; this was a real finding in a past security review of an
// earlier implementation that got this backwards). factory must
// return a fresh, empty PreAuthorizedCodeStore each call.
func TestPreAuthorizedCodeStoreContract(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()

	t.Run("IssueAndConsumeNoTxCode", func(t *testing.T) { testPACIssueAndConsumeNoTxCode(t, factory) })
	t.Run("ConsumeIsSingleUse", func(t *testing.T) { testPACConsumeIsSingleUse(t, factory) })
	t.Run("ConsumeUnknownFails", func(t *testing.T) { testPACConsumeUnknownFails(t, factory) })
	t.Run("CanceledContextIsNotUnknown", func(t *testing.T) { testPACCanceledContextIsNotUnknown(t, factory) })
	t.Run("WrongTxCodeLeavesCodeConsumable", func(t *testing.T) { testPACWrongTxCodeLeavesCodeConsumable(t, factory) })
	t.Run("CorrectTxCodeConsumes", func(t *testing.T) { testPACCorrectTxCodeConsumes(t, factory) })
	t.Run("WrongTxCodeIncrementsAttempts", func(t *testing.T) { testPACWrongTxCodeIncrementsAttempts(t, factory) })
	t.Run("InvalidateThenConsumeFails", func(t *testing.T) { testPACInvalidateThenConsumeFails(t, factory) })
	t.Run("InvalidateUnknownCodeIsNoop", func(t *testing.T) { testPACInvalidateUnknownCodeIsNoop(t, factory) })
	t.Run("ConcurrentWrongAttemptsAreCountedExactly", func(t *testing.T) { testPACConcurrentWrongAttemptsAreCountedExactly(t, factory) })
	t.Run("ConcurrentConsumeHasExactlyOneWinner", func(t *testing.T) { testPACConcurrentConsumeHasExactlyOneWinner(t, factory) })
	t.Run("ConcurrentGuessesAreBoundedByMaxAttempts", func(t *testing.T) { testPACConcurrentGuessesAreBounded(t, factory) })
	t.Run("MissingTxCodeIsNotAGuess", func(t *testing.T) { testPACMissingTxCodeIsNotAGuess(t, factory) })
	t.Run("UnexpectedTxCodeLeavesCodeConsumable", func(t *testing.T) { testPACUnexpectedTxCode(t, factory) })
	t.Run("AcceptSeesTheRecord", func(t *testing.T) { testPACAcceptSeesTheRecord(t, factory) })
	t.Run("AcceptRefusalLeavesCodeConsumable", func(t *testing.T) { testPACAcceptRefusalLeavesCodeConsumable(t, factory) })
	t.Run("AcceptRunsOnlyAfterTxCodeCheck", func(t *testing.T) { testPACAcceptRunsOnlyAfterTxCodeCheck(t, factory) })
	t.Run("ConcurrentRefusalsLeaveCodeConsumable", func(t *testing.T) { testPACConcurrentRefusalsLeaveCodeConsumable(t, factory) })
	t.Run("ConcurrentConsumeWithRefusalsHasExactlyOneWinner", func(t *testing.T) { testPACConcurrentConsumeWithRefusals(t, factory) })
}

// errContractRefused is the error the accept callbacks below refuse a
// record with.
var errContractRefused = errors.New("issuertest: refused by accept")

// refuse is an accept callback that refuses every record.
func refuse(issuer.PreAuthorizedCodeRecord) error { return errContractRefused }

// testPACAcceptSeesTheRecord: accept is given the stored record, and
// Consume returns it once accept accepts it.
func testPACAcceptSeesTheRecord(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	want := issuer.PreAuthorizedCodeRecord{
		Owner: contractOwner, TxCodeHash: "1234", Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"cfg1"},
		ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second), Subject: "subject-1",
	}
	if err := store.Issue(ctx, "code1", want); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	var seen []issuer.PreAuthorizedCodeRecord
	got, _, err := store.Consume(ctx, "code1", "1234", 0, func(r issuer.PreAuthorizedCodeRecord) error {
		seen = append(seen, r)
		return nil
	})
	if err != nil {
		t.Fatalf(msgConsumeFailed, err)
	}
	if len(seen) == 0 {
		t.Fatal("Consume succeeded without calling accept")
	}
	for _, r := range append(seen, got) {
		if r.Owner != want.Owner {
			t.Errorf(msgOwnerMismatch, r.Owner, want.Owner)
		}
		if r.Subject != want.Subject || len(r.Scopes) != 1 || r.Scopes[0] != "identity_credential" ||
			len(r.CredentialConfigurationIDs) != 1 || r.CredentialConfigurationIDs[0] != "cfg1" || !r.ExpiresAt.Equal(want.ExpiresAt) {
			t.Errorf("record = %+v, want %+v", r, want)
		}
	}
}

// testPACAcceptRefusalLeavesCodeConsumable: a record accept refuses is
// left in place, with accept's error returned and no wrong attempt
// counted.
func testPACAcceptRefusalLeavesCodeConsumable(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	for range 3 {
		if _, _, err := store.Consume(ctx, "code1", "1234", 2, refuse); !errors.Is(err, errContractRefused) {
			t.Fatalf("Consume refused by accept: err = %v, want accept's error", err)
		}
	}
	// No wrong attempt was counted: the next wrong guess is the first.
	if _, attempts, err := store.Consume(ctx, "code1", "0000", 2, nil); !errors.Is(err, issuer.ErrWrongTxCode) || attempts != 1 {
		t.Fatalf("wrong guess after refusals: wrongAttempts %d, err %v; want 1, ErrWrongTxCode", attempts, err)
	}
	if _, _, err := store.Consume(ctx, "code1", "1234", 2, func(issuer.PreAuthorizedCodeRecord) error { return nil }); err != nil {
		t.Fatalf("Consume accepted after refusals: %v", err)
	}
}

// testPACAcceptRunsOnlyAfterTxCodeCheck: accept isn't called for an
// unknown code or a missing, unexpected or wrong tx_code, so it can't
// turn a failed guess into something else.
func testPACAcceptRunsOnlyAfterTxCodeCheck(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	if err := store.Issue(ctx, "with-tx", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: exp}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if err := store.Issue(ctx, "without-tx", issuer.PreAuthorizedCodeRecord{ExpiresAt: exp}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	called := false
	accept := func(issuer.PreAuthorizedCodeRecord) error {
		called = true
		return errContractRefused
	}
	for _, c := range []struct{ name, code, txCode string }{
		{"unknown code", nonceNeverIssued, ""},
		{"missing tx_code", "with-tx", ""},
		{"wrong tx_code", "with-tx", "0000"},
		{"unexpected tx_code", "without-tx", "1234"},
	} {
		called = false
		if _, _, err := store.Consume(ctx, c.code, c.txCode, 0, accept); err == nil || errors.Is(err, errContractRefused) {
			t.Errorf("%s: err = %v, want the store's own error", c.name, err)
		}
		if called {
			t.Errorf("%s: accept was called", c.name)
		}
	}
}

// testPACConcurrentRefusalsLeaveCodeConsumable: concurrent redemptions
// accept refuses all fail, and leave the code for one it accepts.
func testPACConcurrentRefusalsLeaveCodeConsumable(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	wins := runConcurrently(contractConcurrentAttempts, func() bool {
		_, _, err := store.Consume(ctx, "code1", "", 0, refuse)
		return err == nil
	})
	if wins != 0 {
		t.Errorf("%d redemptions accept refused succeeded, want none", wins)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); err != nil {
		t.Fatalf("Consume after concurrent refusals: %v", err)
	}
}

// testPACConcurrentConsumeWithRefusals: with accept refusing some
// concurrent redemptions and accepting the others, exactly one
// accepted redemption consumes the code — accept and the consumption
// are one atomic step.
func testPACConcurrentConsumeWithRefusals(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	var mu sync.Mutex
	next := 0
	refusedWins := 0
	wins := runConcurrently(contractConcurrentAttempts, func() bool {
		mu.Lock()
		refusing := next%2 == 0
		next++
		mu.Unlock()
		accept := func(issuer.PreAuthorizedCodeRecord) error { return nil }
		if refusing {
			accept = refuse
		}
		_, _, err := store.Consume(ctx, "code1", "", 0, accept)
		if err == nil && refusing {
			mu.Lock()
			refusedWins++
			mu.Unlock()
		}
		return err == nil
	})
	if wins != 1 || refusedWins != 0 {
		t.Errorf("concurrent Consume: %d winners (%d of them refused by accept), want exactly 1 accepted", wins, refusedWins)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); err == nil {
		t.Error("the code was still consumable after a redemption succeeded")
	}
}

// The testPAC* helpers below are TestPreAuthorizedCodeStoreContract's
// own subtest bodies, split into top-level functions purely to keep
// that function under the linter's own cognitive complexity ceiling —
// cognitive complexity attributes everything nested inside a t.Run
// closure to its enclosing named function, so ten subtests' worth of
// checks were all counting against the one parent function.

func testPACIssueAndConsumeNoTxCode(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	want := issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"cfg1"},
		ExpiresAt: time.Now().Add(time.Minute).Truncate(time.Second),
	}
	if err := store.Issue(ctx, "code1", want); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	got, _, err := store.Consume(ctx, "code1", "", 0, nil)
	if err != nil {
		t.Fatalf(msgConsumeFailed, err)
	}
	if len(got.Scopes) != 1 || got.Scopes[0] != "identity_credential" {
		t.Errorf("Scopes = %v", got.Scopes)
	}
	if len(got.CredentialConfigurationIDs) != 1 || got.CredentialConfigurationIDs[0] != "cfg1" {
		t.Errorf("CredentialConfigurationIDs = %v", got.CredentialConfigurationIDs)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf(msgExpiresAtMismatch, got.ExpiresAt, want.ExpiresAt)
	}
}

func testPACConsumeIsSingleUse(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); !errors.Is(err, issuer.ErrPreAuthorizedCodeUnknown) {
		t.Errorf("second Consume = %v, want issuer.ErrPreAuthorizedCodeUnknown (code already consumed)", err)
	}
}

func testPACConsumeUnknownFails(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	if _, _, err := store.Consume(context.Background(), nonceNeverIssued, "", 0, nil); !errors.Is(err, issuer.ErrPreAuthorizedCodeUnknown) {
		t.Errorf("Consume = %v, want issuer.ErrPreAuthorizedCodeUnknown (unknown code)", err)
	}
}

func testPACCanceledContextIsNotUnknown(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	if err := store.Issue(context.Background(), "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	_, _, err := store.Consume(canceledContext(), "code1", "", 0, nil)
	requireNotUnknown(t, err, issuer.ErrPreAuthorizedCodeUnknown)
}

func testPACWrongTxCodeLeavesCodeConsumable(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if _, _, err := store.Consume(ctx, "code1", "0000", 0, nil); !errors.Is(err, issuer.ErrWrongTxCode) {
		t.Fatalf("Consume with wrong tx_code: err = %v, want ErrWrongTxCode", err)
	}
	// The code must still be redeemable with the correct TxCodeHash — a
	// wrong guess must not have invalidated it.
	if _, _, err := store.Consume(ctx, "code1", "1234", 0, nil); err != nil {
		t.Fatalf("Consume with correct tx_code after a wrong guess: %v", err)
	}
}

func testPACMissingTxCodeIsNotAGuess(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	for range 3 {
		if _, _, err := store.Consume(ctx, "code1", "", 1, nil); !errors.Is(err, issuer.ErrTxCodeRequired) {
			t.Fatalf("Consume without a tx_code: err = %v, want ErrTxCodeRequired", err)
		}
	}
	// No attempt was counted: with maxAttempts 1, the right tx_code
	// still redeems the code.
	if _, _, err := store.Consume(ctx, "code1", "1234", 1, nil); err != nil {
		t.Fatalf("Consume with the tx_code after requests without one: %v", err)
	}
}

func testPACUnexpectedTxCode(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if _, _, err := store.Consume(ctx, "code1", "1234", 0, nil); !errors.Is(err, issuer.ErrTxCodeUnexpected) {
		t.Fatalf("Consume with a tx_code the record doesn't have: err = %v, want ErrTxCodeUnexpected", err)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); err != nil {
		t.Fatalf("Consume without a tx_code after an unexpected one: %v", err)
	}
}

func testPACCorrectTxCodeConsumes(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if _, _, err := store.Consume(ctx, "code1", "1234", 0, nil); err != nil {
		t.Fatalf(msgConsumeFailed, err)
	}
}

func testPACWrongTxCodeIncrementsAttempts(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	for want := 1; want <= 3; want++ {
		_, attempts, err := store.Consume(ctx, "code1", "0000", 0, nil)
		if !errors.Is(err, issuer.ErrWrongTxCode) {
			t.Fatalf("Consume with wrong tx_code (attempt %d): err = %v, want ErrWrongTxCode", want, err)
		}
		if attempts != want {
			t.Errorf("wrongAttempts = %d, want %d", attempts, want)
		}
	}
}

func testPACInvalidateThenConsumeFails(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	if err := store.Invalidate(ctx, "code1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if _, _, err := store.Consume(ctx, "code1", "", 0, nil); !errors.Is(err, issuer.ErrPreAuthorizedCodeUnknown) {
		t.Errorf("Consume after Invalidate = %v, want issuer.ErrPreAuthorizedCodeUnknown", err)
	}
}

func testPACInvalidateUnknownCodeIsNoop(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	if err := store.Invalidate(context.Background(), nonceNeverIssued); err != nil {
		t.Errorf("Invalidate on an unknown code: %v, want nil (no-op)", err)
	}
}

func testPACConcurrentWrongAttemptsAreCountedExactly(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	var mu sync.Mutex
	seen := make(map[int]int, contractConcurrentAttempts)
	runConcurrently(contractConcurrentAttempts, func() bool {
		_, attempts, err := store.Consume(ctx, "code1", "0000", 0, nil)
		if !errors.Is(err, issuer.ErrWrongTxCode) {
			return false
		}
		mu.Lock()
		seen[attempts]++
		mu.Unlock()
		return true
	})
	// Every concurrent wrong guess must have observed a distinct count
	// — a lost update (two goroutines both incrementing from the same
	// stale value) would show up as a duplicate.
	for attempts, count := range seen {
		if count != 1 {
			t.Errorf("wrongAttempts=%d was observed %d times, want exactly 1 (lost update under concurrency)", attempts, count)
		}
	}
	if len(seen) != contractConcurrentAttempts {
		t.Errorf("observed %d distinct wrongAttempts values, want %d", len(seen), contractConcurrentAttempts)
	}
}

// testPACConcurrentGuessesAreBounded: with maxAttempts set, at most
// that many concurrent wrong guesses are compared — the rest are
// refused as ErrTooManyTxCodeAttempts or find the code gone — and the
// code is invalidated, so even the right tx_code then fails.
func testPACConcurrentGuessesAreBounded(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	const maxAttempts = 3
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{TxCodeHash: "1234", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	var mu sync.Mutex
	compared := 0
	runConcurrently(contractConcurrentAttempts, func() bool {
		_, _, err := store.Consume(ctx, "code1", "0000", maxAttempts, nil)
		if errors.Is(err, issuer.ErrWrongTxCode) {
			mu.Lock()
			compared++
			mu.Unlock()
		}
		return err != nil
	})
	if compared > maxAttempts {
		t.Errorf("%d concurrent wrong guesses were compared, want at most %d", compared, maxAttempts)
	}
	if _, _, err := store.Consume(ctx, "code1", "1234", maxAttempts, nil); err == nil {
		t.Error("the right tx_code redeemed the code after too many wrong guesses")
	}
}

func testPACConcurrentConsumeHasExactlyOneWinner(t *testing.T, factory func() issuer.PreAuthorizedCodeStore) {
	t.Helper()
	store := factory()
	ctx := context.Background()
	if err := store.Issue(ctx, "code1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf(msgIssueFailed, err)
	}
	wins := runConcurrently(contractConcurrentAttempts, func() bool {
		_, _, err := store.Consume(ctx, "code1", "", 0, nil)
		return err == nil
	})
	if wins != 1 {
		t.Errorf("concurrent Consume: %d winners, want exactly 1", wins)
	}
}

// TestDPoPReplayCheckerContract exercises factory()'s behavior against
// DPoPReplayChecker's own documented guarantee (RFC 9449 §11.1): a
// "jti" is accepted the first time UseOnce sees it and rejected every
// time after, with exactly one winner under concurrent use of the same
// jti. factory must return a fresh, empty DPoPReplayChecker each call.
func TestDPoPReplayCheckerContract(t *testing.T, factory func() issuer.DPoPReplayChecker) {
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
// check several contract tests in this file need: with an error
// wrapping unknown, when the store's interface defines one.
func testGetUnknownFails(t *testing.T, get func() error, unknown error, why string) {
	t.Helper()
	err := get()
	switch {
	case err == nil:
		t.Errorf("Get = nil error, want error (%s)", why)
	case unknown != nil && !errors.Is(err, unknown):
		t.Errorf("Get = %v, want %v (%s)", err, unknown, why)
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
func TestCredentialOfferStoreContract(t *testing.T, factory func() issuer.CredentialOfferStore) {
	t.Helper()

	t.Run("StoreAndGet", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		exp := time.Now().Add(time.Minute).Truncate(time.Second)
		want := issuer.CredentialOfferRecord{Reference: "ref1", ExpiresAt: exp}
		if err := store.Store(ctx, want); err != nil {
			t.Fatalf("Store: %v", err)
		}
		got, err := store.Get(ctx, "ref1")
		if err != nil {
			t.Fatalf(msgGetFailed, err)
		}
		if got.Reference != "ref1" {
			t.Errorf("Reference = %q, want ref1", got.Reference)
		}
		if !got.ExpiresAt.Equal(exp) {
			t.Errorf(msgExpiresAtMismatch, got.ExpiresAt, exp)
		}
	})

	t.Run("GetIsRepeatable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		testGetIsRepeatable(t,
			func() error {
				return store.Store(ctx, issuer.CredentialOfferRecord{Reference: "ref1", ExpiresAt: time.Now().Add(time.Minute)})
			},
			func() error { _, err := store.Get(ctx, "ref1"); return err },
			"not single-use")
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := factory()
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), "never-stored"); return err }, nil, "unknown reference")
	})
}

// TestNotificationStoreContract exercises factory()'s behavior against
// NotificationStore's own documented guarantee — like
// CredentialOfferStore, and unlike NonceStore, Get is explicitly NOT
// single-use: §11's own idempotency requirement means a
// notification_id must keep validating after the first Notification
// Request that presents it. factory must return a fresh, empty
// NotificationStore each call.
func TestNotificationStoreContract(t *testing.T, factory func() issuer.NotificationStore) {
	t.Helper()

	t.Run("IssueAndGet", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		if err := store.Issue(ctx, "notif1", issuer.NotificationRecord{Owner: contractOwner, ClientID: contractClientID}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		got, err := store.Get(ctx, "notif1")
		if err != nil {
			t.Fatalf(msgGetFailed, err)
		}
		if got.ClientID != contractClientID {
			t.Errorf("ClientID = %q, want client-1", got.ClientID)
		}
		if got.Owner != contractOwner {
			t.Errorf(msgOwnerMismatch, got.Owner, contractOwner)
		}
	})

	t.Run("GetIsRepeatable", func(t *testing.T) {
		store := factory()
		ctx := context.Background()
		testGetIsRepeatable(t,
			func() error { return store.Issue(ctx, "notif1", issuer.NotificationRecord{ClientID: contractClientID}) },
			func() error { _, err := store.Get(ctx, "notif1"); return err },
			"§11 idempotency")
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := factory()
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), nonceNeverIssued); return err }, issuer.ErrNotificationIDUnknown, "unknown notification_id")
	})

	t.Run("CanceledContextIsNotUnknown", func(t *testing.T) {
		store := factory()
		if err := store.Issue(context.Background(), "notif1", issuer.NotificationRecord{ClientID: contractClientID}); err != nil {
			t.Fatalf(msgIssueFailed, err)
		}
		_, err := store.Get(canceledContext(), "notif1")
		requireNotUnknown(t, err, issuer.ErrNotificationIDUnknown)
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
func TestDeferredTransactionStoreContract(t *testing.T, seed func(t *testing.T, transactionID string, record issuer.DeferredTransactionRecord) issuer.DeferredTransactionStore) {
	t.Helper()

	t.Run("Get", func(t *testing.T) {
		want := issuer.DeferredTransactionRecord{Owner: contractOwner, ClientID: contractClientID, Subject: "holder-1", Status: issuer.DeferredTransactionPending}
		store := seed(t, "txn1", want)
		got, err := store.Get(context.Background(), "txn1")
		if err != nil {
			t.Fatalf(msgGetFailed, err)
		}
		if got.ClientID != want.ClientID {
			t.Errorf("ClientID = %q, want %q", got.ClientID, want.ClientID)
		}
		if got.Subject != want.Subject {
			t.Errorf("Subject = %q, want %q", got.Subject, want.Subject)
		}
		if got.Status != want.Status {
			t.Errorf("Status = %v, want %v", got.Status, want.Status)
		}
		if got.Owner != want.Owner {
			t.Errorf(msgOwnerMismatch, got.Owner, want.Owner)
		}
	})

	t.Run("GetUnknownFails", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{})
		testGetUnknownFails(t, func() error { _, err := store.Get(context.Background(), "never-seeded"); return err }, issuer.ErrDeferredTransactionUnknown, "unknown transaction_id")
	})

	t.Run("CanceledContextIsNotUnknown", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})
		_, err := store.Get(canceledContext(), "txn1")
		requireNotUnknown(t, err, issuer.ErrDeferredTransactionUnknown)
		err = store.Update(canceledContext(), "txn1", func(*issuer.DeferredTransactionRecord) error { return nil })
		requireNotUnknown(t, err, issuer.ErrDeferredTransactionUnknown)
	})

	t.Run("InvalidateThenGetFails", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionIssued})
		ctx := context.Background()
		if err := store.Invalidate(ctx, "txn1"); err != nil {
			t.Fatalf("Invalidate: %v", err)
		}
		if _, err := store.Get(ctx, "txn1"); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("Get after Invalidate = %v, want issuer.ErrDeferredTransactionUnknown (transaction_id no longer valid)", err)
		}
		if err := store.Update(ctx, "txn1", func(*issuer.DeferredTransactionRecord) error { return nil }); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("Update after Invalidate = %v, want issuer.ErrDeferredTransactionUnknown", err)
		}
		if err := store.Invalidate(ctx, "txn1"); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("second Invalidate = %v, want issuer.ErrDeferredTransactionUnknown (only one request may get the Credentials)", err)
		}
		if err := store.Invalidate(ctx, "never-seeded"); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("Invalidate of an unknown transaction = %v, want issuer.ErrDeferredTransactionUnknown", err)
		}
	})

	// Invalidate is RequestDeferredCredential's single-use gate: of
	// concurrent requests for one transaction_id, exactly one gets the
	// Credentials. (That Invalidate also drops the stored Credentials
	// isn't observable through the interface; check it in the store's
	// own tests.)
	t.Run("InvalidateIsAtomic", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{
			Status: issuer.DeferredTransactionIssued, Credentials: []oid4vci.IssuedCredential{{Credential: "c"}},
		})
		wins := runConcurrently(contractConcurrentAttempts, func() bool {
			return store.Invalidate(context.Background(), "txn1") == nil
		})
		if wins != 1 {
			t.Errorf("%d concurrent Invalidates succeeded, want exactly 1", wins)
		}
	})

	t.Run("CreateThenGet", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{})
		ctx := context.Background()
		want := issuer.DeferredTransactionRecord{
			Owner: contractOwner, ClientID: contractClientID, Status: issuer.DeferredTransactionPending, CredentialConfigurationID: "pid",
			BindingKeys: []json.RawMessage{json.RawMessage(`{"kty":"EC"}`)}, Reference: "ref-1",
			KeyAttestations: []string{"key-attestation-1"},
			ProofKeyHeaders: []json.RawMessage{json.RawMessage(`{"x5c":["AAAA"]}`)},
		}
		if err := store.Create(ctx, "txn2", want); err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, err := store.Get(ctx, "txn2")
		if err != nil {
			t.Fatalf(msgGetFailed, err)
		}
		if got.CredentialConfigurationID != "pid" || got.Reference != "ref-1" || len(got.BindingKeys) != 1 || string(got.BindingKeys[0]) != `{"kty":"EC"}` ||
			len(got.KeyAttestations) != 1 || got.KeyAttestations[0] != "key-attestation-1" ||
			len(got.ProofKeyHeaders) != 1 || string(got.ProofKeyHeaders[0]) != `{"x5c":["AAAA"]}` {
			t.Errorf("Get after Create = %+v, want %+v", got, want)
		}
		if got.Owner != want.Owner {
			t.Errorf(msgOwnerMismatch, got.Owner, want.Owner)
		}
		if err := store.Create(ctx, "txn2", want); err == nil {
			t.Error("Create reused a transaction_id")
		}
	})

	t.Run("Update", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})
		ctx := context.Background()
		if err := store.Update(ctx, "txn1", func(r *issuer.DeferredTransactionRecord) error {
			r.Status = issuer.DeferredTransactionDenied
			return nil
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		refused := errors.New("refused")
		if err := store.Update(ctx, "txn1", func(r *issuer.DeferredTransactionRecord) error {
			r.Status = issuer.DeferredTransactionIssued
			return refused
		}); !errors.Is(err, refused) {
			t.Errorf("Update whose fn fails = %v, want fn's error", err)
		}
		if got, err := store.Get(ctx, "txn1"); err != nil || got.Status != issuer.DeferredTransactionDenied {
			t.Errorf("after Updates: %+v, %v; want Denied (the failed Update saved nothing)", got, err)
		}
		if err := store.Update(ctx, "never-seeded", func(*issuer.DeferredTransactionRecord) error { return nil }); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("Update of an unknown transaction = %v, want issuer.ErrDeferredTransactionUnknown", err)
		}
	})

	t.Run("UpdateIsAtomic", func(t *testing.T) {
		store := seed(t, "txn1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})
		const n = 20
		var wg sync.WaitGroup
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = store.Update(context.Background(), "txn1", func(r *issuer.DeferredTransactionRecord) error {
					r.Credentials = append(r.Credentials, oid4vci.IssuedCredential{Credential: "c"})
					return nil
				})
			}()
		}
		wg.Wait()
		if got, err := store.Get(context.Background(), "txn1"); err != nil || len(got.Credentials) != n {
			t.Errorf("after %d concurrent Updates: %d credentials, %v; want %d (an Update was lost)", n, len(got.Credentials), err, n)
		}
	})
}

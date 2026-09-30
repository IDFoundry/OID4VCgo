package storage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestCredentialOfferStoreDoesNotAliasCallerOrInternalState covers both
// directions: mutating the caller's own record (including its Grants
// pointer chain) after Store must not reach what's stored, and
// mutating a returned CredentialOfferRecord must not corrupt what a
// later Get returns for the same reference.
func TestCredentialOfferStoreDoesNotAliasCallerOrInternalState(t *testing.T) {
	s := storage.NewCredentialOfferStore()
	ctx := context.Background()

	record := testCredentialOfferRecord()
	if err := s.Store(ctx, record); err != nil {
		t.Fatalf("Store: %v", err)
	}
	record.Offer.CredentialConfigurationIDs[0] = "tampered-by-caller-after-store"
	record.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode = "tampered-by-caller-after-store"

	first, err := s.Get(ctx, "ref-1")
	if err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if first.Offer.CredentialConfigurationIDs[0] != "IdentityCredential" {
		t.Fatalf("CredentialConfigurationIDs[0] = %q, want %q (Store aliased the caller's slice)",
			first.Offer.CredentialConfigurationIDs[0], "IdentityCredential")
	}
	if first.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode != "abc123" {
		t.Fatalf("PreAuthorizedCode = %q, want %q (Store aliased the caller's Grants)",
			first.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode, "abc123")
	}

	first.Offer.CredentialConfigurationIDs[0] = "tampered-by-caller-after-get"
	first.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode = "tampered-by-caller-after-get"

	second, err := s.Get(ctx, "ref-1")
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if second.Offer.CredentialConfigurationIDs[0] != "IdentityCredential" {
		t.Fatalf("CredentialConfigurationIDs[0] = %q, want %q (Get calls shared an aliased slice)",
			second.Offer.CredentialConfigurationIDs[0], "IdentityCredential")
	}
	if second.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode != "abc123" {
		t.Fatalf("PreAuthorizedCode = %q, want %q (Get calls shared an aliased Grants)",
			second.Offer.Grants.PreAuthorizedCode.PreAuthorizedCode, "abc123")
	}
}

// TestDeferredTransactionStoreDoesNotAliasCallerOrInternalState covers
// the same two directions as above for DeferredTransactionStore's own
// Credentials slice.
func TestDeferredTransactionStoreDoesNotAliasCallerOrInternalState(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	ctx := context.Background()

	credentials := []oid4vci.IssuedCredential{{Credential: "signed-credential"}}
	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{
		Status: issuer.DeferredTransactionIssued, Credentials: credentials,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	credentials[0].Credential = "tampered-by-caller-after-put"

	first, err := s.Get(ctx, "txn-1")
	if err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if first.Credentials[0].Credential != "signed-credential" {
		t.Fatalf("Credentials[0] = %q, want %q (Put aliased the caller's slice)", first.Credentials[0].Credential, "signed-credential")
	}

	first.Credentials[0].Credential = "tampered-by-caller-after-get"

	second, err := s.Get(ctx, "txn-1")
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if second.Credentials[0].Credential != "signed-credential" {
		t.Fatalf("Credentials[0] = %q, want %q (Get calls shared an aliased slice)", second.Credentials[0].Credential, "signed-credential")
	}
}

// TestNoStoreRacesUnderConcurrentAccess runs many concurrent
// operations against each store, each mutating its own returned value
// — under -race, this fails if any two calls actually share the same
// backing array or struct.
func TestNoStoreRacesUnderConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	offers := storage.NewCredentialOfferStore()
	if err := offers.Store(ctx, testCredentialOfferRecord()); err != nil {
		t.Fatalf("Store: %v", err)
	}
	deferredTxns := storage.NewDeferredTransactionStore()
	if err := deferredTxns.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{
		Status: issuer.DeferredTransactionIssued, Credentials: []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	done := make(chan struct{})
	for i := 0; i < 25; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			got, err := offers.Get(ctx, "ref-1")
			if err != nil {
				t.Errorf("Get (offer): %v", err)
				return
			}
			got.Offer.CredentialConfigurationIDs[0] = "mutated"
		}()
		go func() {
			defer func() { done <- struct{}{} }()
			got, err := deferredTxns.Get(ctx, "txn-1")
			if err != nil {
				t.Errorf("Get (deferred): %v", err)
				return
			}
			got.Credentials[0].Credential = "mutated"
		}()
	}
	for i := 0; i < 50; i++ {
		<-done
	}
}

// TestVerifierTransactionStoreDoesNotAliasCallerOrInternalState covers
// Create's input, Get's output, and an Update whose fn changes the
// transaction in place and then fails.
func TestVerifierTransactionStoreDoesNotAliasCallerOrInternalState(t *testing.T) {
	s := storage.NewVerifierTransactionStore()
	ctx := context.Background()
	holderBinding := true
	tx := verifier.Transaction{
		ID: "t1", KeyID: "k1", BrowserBindingHash: []byte{1, 2, 3},
		Query: dcql.Query{Credentials: []dcql.CredentialQuery{{
			ID: "pid", Format: "dc+sd-jwt", Meta: []byte(`{"vct_values":["pid"]}`),
			TrustedAuthorities:                []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"aki"}}},
			RequireCryptographicHolderBinding: &holderBinding,
			Claims:                            []dcql.ClaimsQuery{{ID: "c", Path: dcql.Path{dcql.PathKey("age_over_18")}, Values: []any{true}}},
			ClaimSets:                         [][]string{{"c"}},
		}}},
	}
	if err := s.Create(ctx, tx); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tamper := func(tx *verifier.Transaction) {
		c := &tx.Query.Credentials[0]
		c.ID, c.Meta[0] = "tampered", 'x'
		c.TrustedAuthorities[0].Values[0] = "tampered"
		*c.RequireCryptographicHolderBinding = false
		c.Claims[0].Path[0], c.Claims[0].Values[0] = dcql.PathKey("tampered"), false
		c.ClaimSets[0][0] = "tampered"
		tx.BrowserBindingHash[0] = 9
	}
	check := func(when string) {
		t.Helper()
		got, err := s.Get(ctx, "t1")
		if err != nil {
			t.Fatalf("Get %s: %v", when, err)
		}
		c := got.Query.Credentials[0]
		if c.ID != "pid" || c.Meta[0] != '{' || c.TrustedAuthorities[0].Values[0] != "aki" ||
			!*c.RequireCryptographicHolderBinding || c.Claims[0].Path[0] != dcql.PathKey("age_over_18") ||
			c.Claims[0].Values[0] != true || c.ClaimSets[0][0] != "c" || got.BrowserBindingHash[0] != 1 {
			t.Fatalf("stored transaction changed %s: %+v", when, got)
		}
	}

	tamper(&tx)
	check("after the caller changed what it created")

	got, err := s.Get(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	tamper(&got)
	check("after the caller changed what Get returned")

	failed := errors.New("fn failed")
	if err := s.Update(ctx, "t1", func(tx *verifier.Transaction) error { tamper(tx); return failed }); !errors.Is(err, failed) {
		t.Fatalf("Update = %v, want %v", err, failed)
	}
	check("after a failed Update")
}

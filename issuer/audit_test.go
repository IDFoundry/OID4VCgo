package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func TestAudit_RequestDeferredCredential(t *testing.T) {
	store := newFakeDeferredTransactionStore()
	sink := newFakeAuditSink()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	deps.Audit = sink
	iss := newTestIssuer(t, cfg, deps)

	store.put("txn-1", issuer.DeferredTransactionRecord{
		ClientID: "client-a", Status: issuer.DeferredTransactionIssued,
		Credentials: []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
	})
	if _, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientID: "client-a"},
		issuer.DeferredCredentialRequest{TransactionID: "txn-1"},
	); err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].Type != issuer.AuditEventRequestDeferredCredential {
		t.Errorf("Type = %v, want AuditEventRequestDeferredCredential", events[0].Type)
	}
	if events[0].Outcome != issuer.AuditOutcomeSuccess {
		t.Errorf("Outcome = %v, want AuditOutcomeSuccess", events[0].Outcome)
	}
	if events[0].ClientID != "client-a" {
		t.Errorf("ClientID = %q, want client-a", events[0].ClientID)
	}

	// A second attempt against the now-invalidated transaction must
	// still record exactly one more event, this time a failure.
	if _, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientID: "client-a"},
		issuer.DeferredCredentialRequest{TransactionID: "txn-1"},
	); err == nil {
		t.Fatal("second RequestDeferredCredential = nil error, want error (transaction already invalidated)")
	}
	events = sink.recorded()
	if len(events) != 2 {
		t.Fatalf("got %d audit events, want 2", len(events))
	}
	if events[1].Outcome != issuer.AuditOutcomeFailure {
		t.Errorf("Outcome = %v, want AuditOutcomeFailure", events[1].Outcome)
	}
	if events[1].Description == "" {
		t.Error("Description is empty, want a safe error-code summary")
	}
}

func TestAudit_RequestCredential(t *testing.T) {
	sink := newFakeAuditSink()
	f := newCredentialEndpointFixture(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Audit = sink
	})
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)

	if _, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientID: "client-b", Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	}); err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].Type != issuer.AuditEventRequestCredential {
		t.Errorf("Type = %v, want AuditEventRequestCredential", events[0].Type)
	}
	if events[0].Outcome != issuer.AuditOutcomeSuccess {
		t.Errorf("Outcome = %v, want AuditOutcomeSuccess", events[0].Outcome)
	}
	if events[0].ClientID != "client-b" {
		t.Errorf("ClientID = %q, want client-b", events[0].ClientID)
	}

	// A second, unrelated failure must still record exactly one more
	// event.
	if _, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientID: "client-b", Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: "NoSuchConfig",
	}); err == nil {
		t.Fatal("second RequestCredential = nil error, want error (unknown credential_configuration_id)")
	}
	events = sink.recorded()
	if len(events) != 2 {
		t.Fatalf("got %d audit events, want 2", len(events))
	}
	if events[1].Outcome != issuer.AuditOutcomeFailure {
		t.Errorf("Outcome = %v, want AuditOutcomeFailure", events[1].Outcome)
	}
	if events[1].Description != string(issuer.ErrorUnknownCredentialConfig) {
		t.Errorf("Description = %q, want %q", events[1].Description, issuer.ErrorUnknownCredentialConfig)
	}
}

func TestAudit_ExchangePreAuthorizedCode(t *testing.T) {
	sink := newFakeAuditSink()
	f := newPreAuthorizedCodeFixtureWith(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.Audit = sink
	})
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	proof := f.validProof(t)

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: proof, TokenEndpoint: testTokenEndpointURL(t),
	}); err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}

	events := sink.recorded()
	if len(events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(events))
	}
	if events[0].Type != issuer.AuditEventExchangePreAuthorizedCode {
		t.Errorf("Type = %v, want AuditEventExchangePreAuthorizedCode", events[0].Type)
	}
	if events[0].Outcome != issuer.AuditOutcomeSuccess {
		t.Errorf("Outcome = %v, want AuditOutcomeSuccess", events[0].Outcome)
	}
	if events[0].ClientID != "" {
		t.Errorf("ClientID = %q, want empty (the pre-authorized_code grant never authenticates the client)", events[0].ClientID)
	}

	// Re-using the now-consumed code must still record exactly one
	// more event, this time a failure.
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	}); err == nil {
		t.Fatal("second ExchangePreAuthorizedCode = nil error, want error (code already consumed)")
	}
	events = sink.recorded()
	if len(events) != 2 {
		t.Fatalf("got %d audit events, want 2", len(events))
	}
	if events[1].Outcome != issuer.AuditOutcomeFailure {
		t.Errorf("Outcome = %v, want AuditOutcomeFailure", events[1].Outcome)
	}
}

func TestAudit_DisabledWhenNil(t *testing.T) {
	// deps.Audit deliberately left nil (validDependencies's own
	// default) — every operation must still work, exactly as before
	// this feature existed.
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	if _, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	}); err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
}

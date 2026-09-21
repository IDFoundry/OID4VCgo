package issuer_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestRequestCredential_RejectsNilClientIdentity proves an
// AuthorizedRequest with a nil ClientIdentity is rejected before
// anything else about the request is even inspected — the
// CredentialRequest here is otherwise empty and would fail
// differently if the ClientIdentity check ran later or not at all.
func TestRequestCredential_RejectsNilClientIdentity(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Errorf("error = %v (an *issuer.Error), want a plain error — a nil ClientIdentity is a caller/deployment mistake, not a malformed request", err)
	}
}

// TestRequestCredential_AcceptsNoClientIdentity proves the opt-out
// lets a request with no client identity through to the rest of
// RequestCredential — resolveJWTProofKeys's own iss-claim check
// included, since that proof here carries no "iss" claim at all.
func TestRequestCredential_AcceptsNoClientIdentity(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	walletKey := testP256Key(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, walletKey, testIssuer, nonce)

	resp, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{
		ClientIdentity: issuer.NoClientIdentity{},
		Scopes:         []string{"identity_credential"},
	}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {proof}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(resp.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(resp.Credentials))
	}
}

func TestRequestDeferredCredential_RejectsNilClientIdentity(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	_, err := iss.RequestDeferredCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.DeferredCredentialRequest{TransactionID: "anything"})
	if err == nil {
		t.Fatalf("RequestDeferredCredential = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Errorf("error = %v (an *issuer.Error), want a plain error", err)
	}
}

func TestRequestDeferredCredential_AcceptsNoClientIdentity(t *testing.T) {
	deps := validDependencies(t)
	store := newFakeDeferredTransactionStore()
	store.put("txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})
	deps.DeferredTransactions = store
	iss := newTestIssuer(t, validConfig(t), deps)

	result, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.NoClientIdentity{}},
		issuer.DeferredCredentialRequest{TransactionID: "txn-1"},
	)
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}
	if result.TransactionID != "txn-1" {
		t.Errorf("TransactionID = %q, want %q", result.TransactionID, "txn-1")
	}
}

func TestIssueNotificationID_RejectsNilClientIdentity(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	_, err := iss.IssueNotificationID(context.Background(), issuer.AuthorizedRequest{})
	if err == nil {
		t.Fatalf("IssueNotificationID = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Errorf("error = %v (an *issuer.Error), want a plain error", err)
	}
}

func TestIssueNotificationID_AcceptsNoClientIdentity(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	id, err := iss.IssueNotificationID(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.NoClientIdentity{}})
	if err != nil {
		t.Fatalf("IssueNotificationID: %v", err)
	}
	if id == "" {
		t.Fatalf("notification id is empty")
	}
}

func TestRequestNotification_RejectsNilClientIdentity(t *testing.T) {
	deps := validDependencies(t)
	store := newFakeNotificationStore()
	store.put("notif-1", issuer.NotificationRecord{})
	deps.Notifications = store
	iss := newTestIssuer(t, validConfig(t), deps)

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{}, issuer.NotificationRequest{
		NotificationID: "notif-1",
		Event:          oid4vci.NotificationEventCredentialAccepted,
	})
	if err == nil {
		t.Fatalf("RequestNotification = nil error, want error")
	}
	var ierr *issuer.Error
	if errors.As(err, &ierr) {
		t.Errorf("error = %v (an *issuer.Error), want a plain error", err)
	}
}

func TestRequestNotification_AcceptsNoClientIdentity(t *testing.T) {
	deps := validDependencies(t)
	store := newFakeNotificationStore()
	store.put("notif-1", issuer.NotificationRecord{})
	deps.Notifications = store
	iss := newTestIssuer(t, validConfig(t), deps)

	err := iss.RequestNotification(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.NoClientIdentity{}}, issuer.NotificationRequest{
		NotificationID: "notif-1",
		Event:          oid4vci.NotificationEventCredentialAccepted,
	})
	if err != nil {
		t.Fatalf("RequestNotification: %v", err)
	}
}

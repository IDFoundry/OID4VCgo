package issuer_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func TestRequestDeferredCredential_ReturnsCredentialsWhenIssued(t *testing.T) {
	store := newFakeDeferredTransactionStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("txn-1", issuer.DeferredTransactionRecord{
		ClientID:       "client-a",
		Status:         issuer.DeferredTransactionIssued,
		Credentials:    []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
		NotificationID: "notif-1",
	})

	result, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")},
		issuer.DeferredCredentialRequest{TransactionID: "txn-1"},
	)
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].Credential != "signed-credential" {
		t.Errorf("Credentials = %v", result.Credentials)
	}
	if result.NotificationID != "notif-1" {
		t.Errorf("NotificationID = %q, want %q", result.NotificationID, "notif-1")
	}
	if result.TransactionID != "" {
		t.Errorf("TransactionID = %q, want empty on the issued path", result.TransactionID)
	}

	// §9.1: the transaction_id must be invalidated once obtained.
	if _, err := store.Get(context.Background(), "txn-1"); err == nil {
		t.Errorf("Get after issuance = nil error, want error (transaction should be invalidated)")
	}
}

func TestRequestDeferredCredential_ReturnsPendingWithInterval(t *testing.T) {
	store := newFakeDeferredTransactionStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("txn-2", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending})

	result, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")},
		issuer.DeferredCredentialRequest{TransactionID: "txn-2"},
	)
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}
	if len(result.Credentials) != 0 {
		t.Errorf("Credentials = %v, want empty on the pending path", result.Credentials)
	}
	if result.TransactionID != "txn-2" {
		t.Errorf("TransactionID = %q, want %q", result.TransactionID, "txn-2")
	}
	if result.Interval != cfg.Limits.DeferredIssuancePollInterval {
		t.Errorf("Interval = %v, want %v", result.Interval, cfg.Limits.DeferredIssuancePollInterval)
	}

	// A pending transaction must not be invalidated by merely polling it.
	if _, err := store.Get(context.Background(), "txn-2"); err != nil {
		t.Errorf("Get after pending poll: %v, want the transaction to remain available", err)
	}
}

func TestRequestDeferredCredential_RejectsDeniedTransaction(t *testing.T) {
	store := newFakeDeferredTransactionStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("txn-3", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionDenied})

	_, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")},
		issuer.DeferredCredentialRequest{TransactionID: "txn-3"},
	)
	assertIssuerError(t, err, issuer.ErrorCredentialRequestDenied)
}

func TestRequestDeferredCredential_RejectsMissingTransactionID(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	_, err := iss.RequestDeferredCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.DeferredCredentialRequest{})
	assertIssuerError(t, err, issuer.ErrorInvalidCredentialRequest)
}

func TestRequestDeferredCredential_RejectsUnknownTransactionID(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	_, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.DeferredCredentialRequest{TransactionID: "no-such-transaction"},
	)
	assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
}

func TestRequestDeferredCredential_RejectsMismatchedClient(t *testing.T) {
	store := newFakeDeferredTransactionStore()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	iss := newTestIssuer(t, cfg, deps)

	store.put("txn-4", issuer.DeferredTransactionRecord{
		ClientID: "client-a",
		Status:   issuer.DeferredTransactionIssued,
		Credentials: []oid4vci.IssuedCredential{
			{Credential: "signed-credential"},
		},
	})

	_, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-b")},
		issuer.DeferredCredentialRequest{TransactionID: "txn-4"},
	)
	assertIssuerError(t, err, issuer.ErrorInvalidTransactionID)
}

func TestRequestDeferredCredential_RejectsWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.DeferredCredential = fapi.URL{}
	cfg.Limits.DeferredIssuancePollInterval = 0
	deps := validDependencies(t)
	deps.DeferredTransactions = nil
	iss := newTestIssuer(t, cfg, deps)

	_, err := iss.RequestDeferredCredential(context.Background(),
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.DeferredCredentialRequest{TransactionID: "anything"},
	)
	if err == nil {
		t.Fatalf("RequestDeferredCredential = nil error, want error")
	}
}

func TestDeferredCredentialResult_WriteJSON_Issued(t *testing.T) {
	result := issuer.DeferredCredentialResult{
		Credentials:    []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
		NotificationID: "notif-1",
	}
	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if rec.Code != 200 {
		t.Errorf("HTTP status = %d, want 200", rec.Code)
	}
	var body struct {
		Credentials []struct {
			Credential string `json:"credential"`
		} `json:"credentials"`
		NotificationID string `json:"notification_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Credentials) != 1 || body.Credentials[0].Credential != "signed-credential" {
		t.Errorf("credentials = %v", body.Credentials)
	}
	if body.NotificationID != "notif-1" {
		t.Errorf("notification_id = %q", body.NotificationID)
	}
}

func TestDeferredCredentialResult_WriteJSON_Pending(t *testing.T) {
	result := issuer.DeferredCredentialResult{
		TransactionID: "txn-2",
		Interval:      30 * time.Second,
	}
	rec := httptest.NewRecorder()
	result.WriteJSON(rec)

	if rec.Code != 202 {
		t.Errorf("HTTP status = %d, want 202", rec.Code)
	}
	var body struct {
		TransactionID string `json:"transaction_id"`
		Interval      int64  `json:"interval"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.TransactionID != "txn-2" {
		t.Errorf("transaction_id = %q, want %q", body.TransactionID, "txn-2")
	}
	if body.Interval != 30 {
		t.Errorf("interval = %d, want 30", body.Interval)
	}
}

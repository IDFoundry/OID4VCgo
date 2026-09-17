package wallet_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/wallet"
)

func testDeferredCredentialEndpoint(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/deferred_credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestRequestDeferredCredential_ReturnsCredentialsWhenIssued(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return jsonResponse([]byte(`{"credentials":[{"credential":"signed-credential"}],"notification_id":"notif-1"}`)), nil
		},
	}

	result, err := w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID: "txn-1",
	})
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].Credential != "signed-credential" {
		t.Errorf("Credentials = %v", result.Credentials)
	}
	if result.NotificationID != "notif-1" {
		t.Errorf("NotificationID = %q", result.NotificationID)
	}
	if result.TransactionID != "" {
		t.Errorf("TransactionID = %q, want empty on the issued path", result.TransactionID)
	}

	var sentBody struct {
		TransactionID string `json:"transaction_id"`
	}
	if err := json.Unmarshal(resource.lastBody, &sentBody); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if sentBody.TransactionID != "txn-1" {
		t.Errorf("sent transaction_id = %q, want %q", sentBody.TransactionID, "txn-1")
	}
}

func TestRequestDeferredCredential_ReturnsPendingWithInterval(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse([]byte(`{"transaction_id":"txn-1","interval":5}`))
			res.StatusCode = http.StatusAccepted
			return res, nil
		},
	}

	result, err := w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID: "txn-1",
	})
	if err != nil {
		t.Fatalf("RequestDeferredCredential: %v", err)
	}
	if len(result.Credentials) != 0 {
		t.Errorf("Credentials = %v, want empty on the pending path", result.Credentials)
	}
	if result.TransactionID != "txn-1" {
		t.Errorf("TransactionID = %q, want %q", result.TransactionID, "txn-1")
	}
	if result.Interval != 5*time.Second {
		t.Errorf("Interval = %v, want 5s", result.Interval)
	}
}

func TestRequestDeferredCredential_RejectsMissingTransactionID(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	_, err = w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{})
	if err == nil {
		t.Fatalf("RequestDeferredCredential = nil error, want error")
	}
}

func TestRequestDeferredCredential_ParsesErrorResponse(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse([]byte(`{"error":"invalid_transaction_id","error_description":"unknown transaction"}`))
			res.StatusCode = http.StatusBadRequest
			return res, nil
		},
	}
	_, err = w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID: "txn-unknown",
	})
	var werr *wallet.Error
	if !errors.As(err, &werr) {
		t.Fatalf("error = %v, want *wallet.Error", err)
	}
	if werr.Code != "invalid_transaction_id" {
		t.Errorf("Code = %q, want invalid_transaction_id", werr.Code)
	}
}

func TestRequestDeferredCredential_PropagatesTransportError(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("simulated network failure")
		},
	}
	_, err = w.RequestDeferredCredential(context.Background(), resource, testDeferredCredentialEndpoint(t), wallet.DeferredCredentialRequest{
		TransactionID: "txn-1",
	})
	if err == nil {
		t.Fatalf("RequestDeferredCredential = nil error, want error")
	}
}

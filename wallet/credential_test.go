package wallet_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/wallet"
)

// fakeProtectedResourceClient is a minimal wallet.ProtectedResourceClient
// for tests, recording the last request it received.
type fakeProtectedResourceClient struct {
	do          func(ctx context.Context, req *http.Request) (*http.Response, error)
	lastRequest *http.Request
	lastBody    []byte
}

func (f *fakeProtectedResourceClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	f.lastRequest = req
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		f.lastBody = body
	}
	return f.do(ctx, req)
}

func testCredentialEndpoint(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/credential", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestRequestCredential_Success(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return jsonResponse([]byte(`{"credentials":[{"credential":"signed-credential"}],"notification_id":"notif-1"}`)), nil
		},
	}

	result, err := w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{key},
		CredentialIssuer:          "https://issuer.example.com",
		Nonce:                     "test-nonce",
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(result.Credentials) != 1 || result.Credentials[0].Credential != "signed-credential" {
		t.Errorf("Credentials = %v", result.Credentials)
	}
	if result.NotificationID != "notif-1" {
		t.Errorf("NotificationID = %q", result.NotificationID)
	}

	if resource.lastRequest.Method != http.MethodPost {
		t.Errorf("method = %q, want POST", resource.lastRequest.Method)
	}
	var sentBody struct {
		CredentialConfigurationID string              `json:"credential_configuration_id"`
		Proofs                    map[string][]string `json:"proofs"`
	}
	if err := json.Unmarshal(resource.lastBody, &sentBody); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if sentBody.CredentialConfigurationID != "IdentityCredential" {
		t.Errorf("credential_configuration_id = %q", sentBody.CredentialConfigurationID)
	}
	if len(sentBody.Proofs["jwt"]) != 1 {
		t.Errorf("proofs[jwt] = %v, want exactly one proof", sentBody.Proofs["jwt"])
	}
}

func TestRequestCredential_Batch(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key1, key2 := testP256Key(t), testP256Key(t)
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return jsonResponse([]byte(`{"credentials":[{"credential":"c1"},{"credential":"c2"}]}`)), nil
		},
	}

	result, err := w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{key1, key2},
		CredentialIssuer:          "https://issuer.example.com",
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(result.Credentials) != 2 {
		t.Fatalf("got %d credentials, want 2", len(result.Credentials))
	}

	var sentBody struct {
		Proofs map[string][]string `json:"proofs"`
	}
	if err := json.Unmarshal(resource.lastBody, &sentBody); err != nil {
		t.Fatalf("unmarshal sent body: %v", err)
	}
	if len(sentBody.Proofs["jwt"]) != 2 {
		t.Errorf("proofs[jwt] has %d entries, want 2", len(sentBody.Proofs["jwt"]))
	}
	if sentBody.Proofs["jwt"][0] == sentBody.Proofs["jwt"][1] {
		t.Errorf("both proofs are identical, want distinct (one per key)")
	}
}

func TestRequestCredential_ReturnsPendingWhenIssuerDefersImmediately(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse([]byte(`{"transaction_id":"txn-1","interval":86400}`))
			res.StatusCode = http.StatusAccepted
			return res, nil
		},
	}

	result, err := w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(result.Credentials) != 0 {
		t.Errorf("Credentials = %v, want empty on the deferred-at-first-response path", result.Credentials)
	}
	if result.TransactionID != "txn-1" {
		t.Errorf("TransactionID = %q, want %q", result.TransactionID, "txn-1")
	}
	if result.Interval != 24*time.Hour {
		t.Errorf("Interval = %v, want 24h", result.Interval)
	}
}

func TestRequestCredential_RejectsMissingConfigID(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		Keys: []crypto.Signer{testP256Key(t)},
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error")
	}
}

func TestRequestCredential_RejectsNoKeys(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{do: func(context.Context, *http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error")
	}
}

func TestRequestCredential_ParsesErrorResponse(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			res := jsonResponse([]byte(`{"error":"invalid_proof","error_description":"proof is expired"}`))
			res.StatusCode = http.StatusBadRequest
			return res, nil
		},
	}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
	})
	var werr *wallet.Error
	if !errors.As(err, &werr) {
		t.Fatalf("error = %v, want *wallet.Error", err)
	}
	if werr.Code != "invalid_proof" {
		t.Errorf("Code = %q, want invalid_proof", werr.Code)
	}
	if werr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("HTTPStatus = %d, want 400", werr.HTTPStatus)
	}
	if werr.Description != "proof is expired" {
		t.Errorf("Description = %q", werr.Description)
	}
}

func TestRequestCredential_PropagatesTransportError(t *testing.T) {
	w, err := wallet.New(validConfig(), validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resource := &fakeProtectedResourceClient{
		do: func(context.Context, *http.Request) (*http.Response, error) {
			return nil, fmt.Errorf("simulated network failure")
		},
	}
	_, err = w.RequestCredential(context.Background(), resource, testCredentialEndpoint(t), wallet.CredentialRequest{
		CredentialConfigurationID: "IdentityCredential",
		Keys:                      []crypto.Signer{testP256Key(t)},
		CredentialIssuer:          "https://issuer.example.com",
	})
	if err == nil {
		t.Fatalf("RequestCredential = nil error, want error")
	}
}

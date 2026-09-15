package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	fapi "github.com/idfoundry/fapigo"
)

// DeferredCredentialRequest is a Deferred Credential Request (§9.1) —
// its own wire shape, marshaled directly.
type DeferredCredentialRequest struct {
	// TransactionID is REQUIRED: a value previously returned as a
	// Credential Response's or an earlier Deferred Credential
	// Response's own transaction_id.
	TransactionID string `json:"transaction_id"`
}

// RequestDeferredCredential implements the Deferred Credential
// Endpoint's own client side (§9.1/§9.2): it POSTs req to endpoint as
// a sender-constrained request via resource — the same already-
// obtained access token used at the Credential Endpoint (§9: "The
// Wallet MUST present to the Deferred Endpoint an Access Token that is
// valid for the issuance of the Credential(s) previously requested at
// the Credential Endpoint") — and parses either a completed (HTTP 200)
// or still-pending (HTTP 202) Deferred Credential Response. A
// non-200, non-202 response is returned as a *Error.
func (w *Wallet) RequestDeferredCredential(
	ctx context.Context, resource ProtectedResourceClient, endpoint fapi.URL, req DeferredCredentialRequest,
) (CredentialResult, error) {
	if req.TransactionID == "" {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: transaction_id is required")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: marshal request: %w", err)
	}

	target := endpoint.URL()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := resource.Do(ctx, httpReq)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: read response: %w", err)
	}

	result, err := parseCredentialResult(res.StatusCode, respBody)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: %w", err)
	}
	return result, nil
}

package wallet

import (
	"context"
	"encoding/json"
	"fmt"

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
	return w.postCredentialResult(ctx, resource, endpoint, body, "request deferred credential")
}

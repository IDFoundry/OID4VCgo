package wallet

import (
	"context"
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// DeferredCredentialRequest is a Deferred Credential Request (§9.1).
type DeferredCredentialRequest struct {
	// TransactionID is REQUIRED: a value previously returned as a
	// Credential Response's or an earlier Deferred Credential
	// Response's own transaction_id.
	TransactionID string

	// RequestEncryption, if set, encrypts this Deferred Credential
	// Request's own outbound body (§10) — see RequestEncryption's own
	// doc comment. §9.1-6/§9.1-7's own text: the same
	// credential_request_encryption support governs both endpoints.
	RequestEncryption *RequestEncryption

	// ResponseEncryption, if set, requests an encrypted Deferred
	// Credential Response (§10) — see CredentialRequest's own field of
	// the same name; §9.1-11's own "this object will be used for
	// encrypting the response, regardless of what was sent in the
	// initial Credential Request" means this is independent of whatever
	// the original Credential Request carried.
	ResponseEncryption *ResponseEncryption
}

// deferredCredentialRequestBody is the Deferred Credential Request's
// own wire shape (§9.1) — DeferredCredentialRequest itself carries
// Go-only encryption config, so this stays a private type
// RequestDeferredCredential builds internally, the same split
// CredentialRequest/credentialRequestBody already draws.
type deferredCredentialRequestBody struct {
	TransactionID      string                         `json:"transaction_id"`
	ResponseEncryption *wireResponseEncryptionRequest `json:"credential_response_encryption,omitempty"`
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
	if req.ResponseEncryption != nil && req.RequestEncryption == nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: response_encryption requires request_encryption to also be set")
	}

	respEncWire, respDecryptKey, err := prepareResponseEncryption(req.ResponseEncryption)
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: %w", err)
	}

	body, err := json.Marshal(deferredCredentialRequestBody{
		TransactionID:      req.TransactionID,
		ResponseEncryption: respEncWire,
	})
	if err != nil {
		return CredentialResult{}, fmt.Errorf("wallet: request deferred credential: marshal request: %w", err)
	}
	return w.postCredentialResult(ctx, resource, endpoint, body, req.RequestEncryption, respDecryptKey, "request deferred credential")
}

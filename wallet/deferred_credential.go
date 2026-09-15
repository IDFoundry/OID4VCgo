package wallet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
)

// DeferredCredentialRequest is a Deferred Credential Request (§9.1) —
// its own wire shape, marshaled directly.
type DeferredCredentialRequest struct {
	// TransactionID is REQUIRED: a value previously returned as a
	// Credential Response's or an earlier Deferred Credential
	// Response's own transaction_id.
	TransactionID string `json:"transaction_id"`
}

// DeferredCredentialResult is returned by a successful
// RequestDeferredCredential — either the completed Credentials (HTTP
// 200) or a fresh polling hint (HTTP 202, §9.2).
type DeferredCredentialResult struct {
	// Credentials is set (and non-empty) exactly when the transaction
	// has completed: HTTP 200, reusing the immediate Credential
	// Response's own "credentials" parameter (§8.3, via §9.2's own MUST
	// clause).
	Credentials []oid4vci.IssuedCredential

	// NotificationID is OPTIONAL, and only ever set alongside
	// Credentials.
	NotificationID string

	// TransactionID and Interval are set exactly when the transaction
	// is still pending: HTTP 202. TransactionID echoes the same value
	// the request carried; Interval is the minimum time to wait before
	// polling again (§9.2's own "interval" member, REQUIRED when
	// transaction_id is present).
	TransactionID string
	Interval      time.Duration
}

// deferredCredentialResponseBody is the Deferred Credential Response's
// own wire shape (§9.2) — covers both the completed and still-pending
// cases in one struct, since a caller must inspect the HTTP status to
// know which one actually applies; interval arrives as a plain JSON
// number of seconds, not RFC 3339 duration text.
type deferredCredentialResponseBody struct {
	Credentials    []oid4vci.IssuedCredential `json:"credentials"`
	NotificationID string                     `json:"notification_id,omitempty"`
	TransactionID  string                     `json:"transaction_id,omitempty"`
	Interval       int64                      `json:"interval,omitempty"`
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
) (DeferredCredentialResult, error) {
	if req.TransactionID == "" {
		return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: transaction_id is required")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: marshal request: %w", err)
	}

	target := endpoint.URL()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
	if err != nil {
		return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	res, err := resource.Do(ctx, httpReq)
	if err != nil {
		return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: read response: %w", err)
	}

	switch res.StatusCode {
	case http.StatusOK, http.StatusAccepted:
		var wire deferredCredentialResponseBody
		if err := json.Unmarshal(respBody, &wire); err != nil {
			return DeferredCredentialResult{}, fmt.Errorf("wallet: request deferred credential: decode response: %w", err)
		}
		return DeferredCredentialResult{
			Credentials:    wire.Credentials,
			NotificationID: wire.NotificationID,
			TransactionID:  wire.TransactionID,
			Interval:       time.Duration(wire.Interval) * time.Second,
		}, nil
	default:
		return DeferredCredentialResult{}, parseError(res.StatusCode, respBody)
	}
}

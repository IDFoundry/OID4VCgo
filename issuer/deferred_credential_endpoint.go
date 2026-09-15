package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcigo"
)

// DeferredCredentialRequest is a Deferred Credential Request (§9.1).
type DeferredCredentialRequest struct {
	// TransactionID is REQUIRED: identifies a Deferred Issuance
	// transaction previously returned by a Credential Response (§8.3)
	// or an earlier Deferred Credential Response (§9.2). This package
	// never issues one itself — see DeferredTransactionRecord's own
	// doc comment.
	TransactionID string

	// ResponseEncryption is this request's own optional
	// "credential_response_encryption" object (§9.1) — §9.1-11's own
	// "this object will be used for encrypting the response, regardless
	// of what was sent in the initial Credential Request," so this is
	// independent of whatever the original Credential Request carried.
	// Set this from the decrypted request body's own JSON. Nil means
	// the Deferred Credential Response isn't encrypted.
	ResponseEncryption *ResponseEncryptionRequest

	// RequestWasEncrypted reports whether this Deferred Credential
	// Request itself arrived as a JWE (§10) — set this from
	// DecryptRequestBody's own second return value.
	// RequestDeferredCredential rejects ResponseEncryption being set
	// unless this is also true (§9.1-11).
	RequestWasEncrypted bool
}

// DeferredCredentialResult is returned by a successful
// RequestDeferredCredential — either HTTP 200 with completed
// Credentials, or HTTP 202 with a fresh polling hint (§9.2).
type DeferredCredentialResult struct {
	// Credentials is set (and non-empty) exactly when the transaction
	// has completed: HTTP 200, reusing the immediate Credential
	// Response's own "credentials" parameter (§8.3, via §9.2's own MUST
	// clause).
	Credentials []oid4vci.IssuedCredential

	// NotificationID is OPTIONAL, and only ever set alongside
	// Credentials — a pass-through of whatever
	// DeferredTransactionRecord.NotificationID carried; see its own
	// doc comment for how one comes to exist.
	NotificationID string

	// TransactionID and Interval are set exactly when the transaction
	// is still pending: HTTP 202. TransactionID echoes the same value
	// the request carried (§9.2: "The value of transaction_id MUST be
	// same as the value of transaction_id in the Deferred Credential
	// Request"); Interval is this issuer's own polling hint
	// (Config.Limits.DeferredIssuancePollInterval).
	TransactionID string
	Interval      time.Duration
}

// WriteJSON writes r as a complete Deferred Credential Response to w
// (§9.2): HTTP 200 with "credentials" (and "notification_id" if set)
// when r.Credentials is non-empty, or HTTP 202 with "transaction_id"
// and "interval" (whole seconds) otherwise. Must be called before
// anything else writes to w.
func (r DeferredCredentialResult) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	if len(r.Credentials) > 0 {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(struct {
			Credentials    []oid4vci.IssuedCredential `json:"credentials"`
			NotificationID string                     `json:"notification_id,omitempty"`
		}{Credentials: r.Credentials, NotificationID: r.NotificationID})
		return
	}
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(struct {
		TransactionID string `json:"transaction_id"`
		Interval      int64  `json:"interval"`
	}{TransactionID: r.TransactionID, Interval: int64(r.Interval.Seconds())})
}

// RequestDeferredCredential implements the Deferred Credential
// Endpoint (§9): it retrieves the Deferred Issuance transaction
// req.TransactionID identifies, checks it's bound to auth's client,
// and either returns the completed Credentials (invalidating the
// transaction per §9.1), reports it's still pending with a polling
// hint, or reports this issuer can no longer issue it
// (credential_request_denied, §9.3).
//
// This package never creates a Deferred Issuance transaction itself —
// RequestCredential always issues immediately or fails outright, since
// deciding a Credential isn't ready yet is entirely a deployment's own
// business process; see DeferredTransactionRecord's own doc comment.
// Request/response encryption (§10) is supported the same way
// RequestCredential's own is — see DecryptRequestBody/EncryptResponseBody
// and DeferredCredentialRequest's own ResponseEncryption/RequestWasEncrypted
// fields.
func (iss *Issuer) RequestDeferredCredential(ctx context.Context, auth AuthorizedRequest, req DeferredCredentialRequest) (DeferredCredentialResult, error) {
	if iss.deps.DeferredTransactions == nil {
		return DeferredCredentialResult{}, fmt.Errorf("issuer: request deferred credential: deferred issuance is not configured")
	}
	if req.TransactionID == "" {
		return DeferredCredentialResult{}, newError(ErrorInvalidCredentialRequest, 400, "transaction_id is required", nil)
	}
	if req.ResponseEncryption != nil && !req.RequestWasEncrypted {
		return DeferredCredentialResult{}, newError(ErrorInvalidCredentialRequest, 400,
			"credential_response_encryption requires the request itself to be encrypted", nil)
	}

	record, err := iss.deps.DeferredTransactions.Get(ctx, req.TransactionID)
	if err != nil {
		return DeferredCredentialResult{}, newError(ErrorInvalidTransactionID, 400, "unknown or already-used transaction_id", err)
	}
	if record.ClientID != "" && auth.ClientID != "" && record.ClientID != auth.ClientID {
		return DeferredCredentialResult{}, newError(ErrorInvalidTransactionID, 400, "transaction_id was not issued to this client", nil)
	}

	switch record.Status {
	case DeferredTransactionPending:
		return DeferredCredentialResult{
			TransactionID: req.TransactionID,
			Interval:      iss.cfg.Limits.DeferredIssuancePollInterval,
		}, nil
	case DeferredTransactionDenied:
		return DeferredCredentialResult{}, newError(ErrorCredentialRequestDenied, 400,
			"this issuer can no longer issue the requested credential(s)", nil)
	case DeferredTransactionIssued:
		if err := iss.deps.DeferredTransactions.Invalidate(ctx, req.TransactionID); err != nil {
			return DeferredCredentialResult{}, fmt.Errorf("issuer: request deferred credential: invalidate transaction: %w", err)
		}
		return DeferredCredentialResult{Credentials: record.Credentials, NotificationID: record.NotificationID}, nil
	default:
		return DeferredCredentialResult{}, fmt.Errorf("issuer: request deferred credential: unknown transaction status %v", record.Status)
	}
}

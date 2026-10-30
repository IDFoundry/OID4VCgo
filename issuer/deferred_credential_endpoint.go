package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcgo"
)

// unknownTransactionID describes a transaction_id the issuer has no
// pending deferral for, whatever the reason, so as not to say which.
const unknownTransactionID = "unknown or already-used transaction_id"

// DeferredCredentialRequest is a Deferred Credential Request (§9.1).
type DeferredCredentialRequest struct {
	// TransactionID is REQUIRED: identifies a Deferred Issuance
	// transaction previously returned by a Credential Response (§8.3)
	// or an earlier Deferred Credential Response (§9.2).
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
	status, body := r.wire()
	w.Header().Set("Content-Type", "application/json")
	// It carries a credential, or a transaction still pending.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// wire returns r's HTTP status and JSON body (§9.2).
func (r DeferredCredentialResult) wire() (int, any) {
	if len(r.Credentials) > 0 {
		return http.StatusOK, struct {
			Credentials    []oid4vci.IssuedCredential `json:"credentials"`
			NotificationID string                     `json:"notification_id,omitempty"`
		}{Credentials: r.Credentials, NotificationID: r.NotificationID}
	}
	return http.StatusAccepted, struct {
		TransactionID string `json:"transaction_id"`
		Interval      int64  `json:"interval"`
	}{TransactionID: r.TransactionID, Interval: pollIntervalSeconds(r.Interval)}
}

// checkDeferredCredentialRequest checks what a Deferred Credential
// Request must satisfy before its transaction is looked up.
func (iss *Issuer) checkDeferredCredentialRequest(auth AuthorizedRequest, req DeferredCredentialRequest) error {
	if iss.deps.DeferredTransactions == nil {
		return fmt.Errorf("issuer: request deferred credential: deferred issuance is not configured")
	}
	if err := requireClientIdentityDecision(auth); err != nil {
		return err
	}
	if req.TransactionID == "" {
		return newError(ErrorInvalidCredentialRequest, 400, "transaction_id is required", nil)
	}
	if err := iss.requireRequestEncryption(req.RequestWasEncrypted, req.ResponseEncryption != nil); err != nil {
		return err
	}
	return iss.requireResponseEncryption(req.ResponseEncryption)
}

// RequestDeferredCredential implements the Deferred Credential
// Endpoint (§9): it retrieves the Deferred Issuance transaction
// req.TransactionID identifies, checks it's bound to auth's client,
// and either returns the completed Credentials (invalidating the
// transaction per §9.1), reports it's still pending with a polling
// hint, or reports this issuer can no longer issue it
// (credential_request_denied, §9.3).
//
// It answers only the client and access token Subject the transaction
// was created for (DeferredTransactionRecord's ClientID and Subject);
// anyone else gets invalid_transaction_id, as for an unknown one.
// RequestCredential creates the transaction when a request defers
// (CredentialRequest.Defer). Request/response encryption (§10) is supported the same way
// RequestCredential's own is — see DecryptRequestBody/EncryptResponseBody
// and DeferredCredentialRequest's own ResponseEncryption/RequestWasEncrypted
// fields.
func (iss *Issuer) RequestDeferredCredential(ctx context.Context, auth AuthorizedRequest, req DeferredCredentialRequest) (DeferredCredentialResult, error) {
	result, err := iss.requestDeferredCredential(ctx, auth, req)
	iss.audit(ctx, AuditEventRequestDeferredCredential, auth.ClientID(), err)
	return result, err
}

func (iss *Issuer) requestDeferredCredential(ctx context.Context, auth AuthorizedRequest, req DeferredCredentialRequest) (DeferredCredentialResult, error) {
	if err := iss.checkDeferredCredentialRequest(auth, req); err != nil {
		return DeferredCredentialResult{}, err
	}

	record, err := iss.deps.DeferredTransactions.Get(ctx, req.TransactionID)
	if err != nil {
		return DeferredCredentialResult{}, deferredStoreError(err)
	}
	if iss.deferredExpired(record) {
		return DeferredCredentialResult{}, newError(ErrorInvalidTransactionID, 400, unknownTransactionID, nil)
	}
	if !iss.deferredAuthorized(record, auth) {
		// As for an unknown one: whether another holder's transaction
		// exists is none of this one's business. The same client and
		// subject aren't enough either, if the token doesn't grant the
		// transaction's configuration (a narrower refreshed token, or
		// one from another grant).
		return DeferredCredentialResult{}, newError(ErrorInvalidTransactionID, 400, unknownTransactionID,
			errors.New("transaction_id was not issued to this access token's client and subject, or the token doesn't grant its credential configuration"))
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
		// Invalidate is the single-use gate: only the request whose
		// Invalidate succeeds gets the Credentials.
		if err := iss.deps.DeferredTransactions.Invalidate(ctx, req.TransactionID); err != nil {
			return DeferredCredentialResult{}, deferredStoreError(err)
		}
		return DeferredCredentialResult{Credentials: record.Credentials, NotificationID: record.NotificationID}, nil
	default:
		return DeferredCredentialResult{}, fmt.Errorf("issuer: request deferred credential: unknown transaction status %v", record.Status)
	}
}

// deferredStoreError answers a DeferredTransactionStore error at the
// Deferred Credential Endpoint: invalid_transaction_id for an unknown
// or invalidated transaction (ErrDeferredTransactionUnknown), and a
// plain error, a 500, for a store that couldn't answer.
func deferredStoreError(err error) error {
	if errors.Is(err, ErrDeferredTransactionUnknown) {
		return newError(ErrorInvalidTransactionID, 400, unknownTransactionID, err)
	}
	return fmt.Errorf("issuer: request deferred credential: dependencies.deferred_transactions: %w", err)
}

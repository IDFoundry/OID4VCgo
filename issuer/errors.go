package issuer

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorCode is the closed set of error codes this package's endpoints
// return: §8.3.1.2's own Credential Request/Response codes, §9.3's
// additional invalid_transaction_id, §11.3's own separate Notification
// Request error codes, and RFC 6749 §5.2's own Token Error Response
// codes for ExchangePreAuthorizedCode.
type ErrorCode string

const (
	ErrorInvalidCredentialRequest    ErrorCode = "invalid_credential_request" //nolint:gosec // an OID4VCI error code, not a credential
	ErrorUnknownCredentialConfig     ErrorCode = "unknown_credential_configuration"
	ErrorUnknownCredentialIdentifier ErrorCode = "unknown_credential_identifier"
	ErrorInvalidProof                ErrorCode = "invalid_proof"
	ErrorInvalidNonce                ErrorCode = "invalid_nonce"
	ErrorCredentialRequestDenied     ErrorCode = "credential_request_denied" //nolint:gosec // an OID4VCI error code, not a credential

	// ErrorInvalidEncryptionParameters is §8.3.1.2's own dedicated code
	// for §10 encryption failures — "the encryption parameters in the
	// Credential Request are either invalid or missing," including the
	// case where this issuer requires an encrypted Response but the
	// Request didn't arrive encrypted. Confirmed live against the real
	// OIDF conformance suite's own fail-unsupported-encryption-algorithm
	// module: it specifically checks for this code, not the more
	// generic ErrorInvalidCredentialRequest every encryption failure in
	// this package used before this fix.
	ErrorInvalidEncryptionParameters ErrorCode = "invalid_encryption_parameters"

	// ErrorInvalidTransactionID is the Deferred Credential Endpoint's
	// own additional error code (§9.3): the request's transaction_id
	// was not issued by this Credential Issuer, or was already used to
	// obtain a Credential.
	ErrorInvalidTransactionID ErrorCode = "invalid_transaction_id"

	// ErrorInvalidNotificationID and ErrorInvalidNotificationRequest
	// are the Notification Endpoint's own, separate error code set
	// (§11.3) — distinct from the codes above, which are all
	// Credential/Deferred Credential Endpoint errors (§8.3.1.2/§9.3).
	ErrorInvalidNotificationID      ErrorCode = "invalid_notification_id"
	ErrorInvalidNotificationRequest ErrorCode = "invalid_notification_request"

	// ErrorInvalidTokenRequest and ErrorInvalidGrant are
	// ExchangePreAuthorizedCode's own error codes — RFC 6749 §5.2's own
	// Token Error Response vocabulary ("invalid_request"/"invalid_grant"),
	// a third, separate code set from the two above (the Pre-Authorized
	// Code Flow's own Token Request/Response, §6.1/§6.2, isn't a
	// Credential Request/Response or a Notification Request). The Go
	// constant name for "invalid_request" is disambiguated from
	// ErrorInvalidCredentialRequest above, whose own wire value is the
	// different string "invalid_credential_request".
	ErrorInvalidTokenRequest ErrorCode = "invalid_request"
	ErrorInvalidGrant        ErrorCode = "invalid_grant"

	// ErrorUseDPoPNonce indicates a DPoP proof presented to
	// ExchangePreAuthorizedCode was otherwise valid but carried no
	// nonce, or one this issuer didn't just issue (unknown, already
	// consumed, or expired) — RFC 9449 §8's own error value for an
	// Authorization Server's nonce-challenge (a plain 400 JSON error
	// body plus a DPoP-Nonce response header, not the 401
	// WWW-Authenticate challenge RFC 9449 §9 defines for a resource
	// server). Only ever returned when Dependencies.DPoPNonces is
	// configured; see its own doc comment. Mirrors
	// fapigo/server.ErrorUseDPoPNonce's own value and semantics for the
	// Authorization Code Flow's Token Endpoint.
	ErrorUseDPoPNonce ErrorCode = "use_dpop_nonce"
)

// Error is the error type RequestCredential returns for a Credential
// Request/Response error (§8.3.1.2 — every code above uses HTTP 400).
// Code and PublicDescription are safe to put directly into a Credential
// Error Response body; the underlying cause (Unwrap) is for logs only
// and must never be copied into a public response. A failure
// RequestCredential can't attribute to the request itself (e.g. an
// unexpected error from a Dependencies collaborator) is returned as a
// plain error instead — see WriteError.
type Error struct {
	code        ErrorCode
	httpStatus  int
	description string
	cause       error
	nonce       string
}

func newError(code ErrorCode, httpStatus int, description string, cause error) *Error {
	return &Error{code: code, httpStatus: httpStatus, description: description, cause: cause}
}

// Code returns the error code.
func (e *Error) Code() ErrorCode { return e.code }

// PublicDescription returns a short, safe-to-expose description.
func (e *Error) PublicDescription() string { return e.description }

// HTTPStatus returns the HTTP status code an adapter should respond with.
func (e *Error) HTTPStatus() int { return e.httpStatus }

// Nonce returns the nonce a caller should present on retry, alongside
// this error's own DPoP challenge — non-empty only when Code is
// ErrorUseDPoPNonce, in which case WriteJSON already puts it in the
// response's own DPoP-Nonce header; exposed separately only for a
// caller building its own response by hand.
func (e *Error) Nonce() string { return e.nonce }

// Error implements the error interface. Its output includes the
// internal cause and is meant for logs, not for a public response.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("issuer: %s: %s: %v", e.code, e.description, e.cause)
	}
	return fmt.Sprintf("issuer: %s: %s", e.code, e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

// WriteJSON writes e as a complete error response — a Credential Error
// Response (§8.3.1.2) for a Credential/Deferred Credential Endpoint
// error, or a Token Error Response (RFC 6749 §5.2) for an
// ExchangePreAuthorizedCode error — to w: the DPoP-Nonce header when
// Nonce is non-empty (RFC 9449 §8 — see Nonce's own doc comment for
// when that is), the "application/json" Content-Type, e's own
// HTTPStatus, and a {"error": ..., "error_description": ...} body
// built from Code and PublicDescription — never Unwrap's cause. Must
// be called before anything else writes to w.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	if e.nonce != "" {
		w.Header().Set("DPoP-Nonce", e.nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.httpStatus)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: string(e.code), ErrorDescription: e.description})
}

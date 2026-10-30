package issuer

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

	// ErrorInvalidAuthorizationDetails refuses a Token Request's
	// authorization_details (RFC 9396 §5).
	ErrorInvalidAuthorizationDetails ErrorCode = "invalid_authorization_details"

	// ErrorInsufficientScope is the Credential Endpoint's answer to an
	// access token that doesn't authorize the requested Credential
	// Configuration: OpenID4VCI §8.3.1.1 has it return "an
	// authorization error response such as defined in Section 3 of
	// [RFC6750]", which is 403 insufficient_scope with a
	// WWW-Authenticate challenge (RFC 6750 §3.1; RFC 9449 §7.1 for DPoP).
	ErrorInsufficientScope ErrorCode = "insufficient_scope"
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
}

// NewError builds an error response for a failure the caller decides —
// most often ErrorCredentialRequestDenied, when the issuer's own
// business rules refuse a request that is otherwise valid (§8.3.1.2:
// "the Credential Request has not been accepted by the Credential
// Issuer"). Every Credential, Deferred Credential and Notification
// Endpoint error uses HTTP 400. description goes into the response's
// error_description as it is, so it must be safe to show the Wallet:
// never put passport data, internal errors or secrets in it. Write it
// with WriteJSON, or return it through WriteError.
func NewError(code ErrorCode, description string) *Error {
	return newError(code, http.StatusBadRequest, description, nil)
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
// ExchangePreAuthorizedCode error — to w: the "application/json"
// Content-Type, e's own
// HTTPStatus, and a {"error": ..., "error_description": ...} body
// built from Code and PublicDescription — never Unwrap's cause. Must
// be called before anything else writes to w.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	if e.code == ErrorInsufficientScope {
		// The token may be DPoP-bound or, outside HAIP, a Bearer token:
		// the challenge names both schemes.
		w.Header().Add("WWW-Authenticate", `DPoP error="insufficient_scope"`)
		w.Header().Add("WWW-Authenticate", `Bearer error="insufficient_scope"`)
	}
	w.Header().Set("Content-Type", "application/json")
	// RFC 6749 §5.2 has a Token Endpoint's error responses, which
	// ExchangePreAuthorizedCode's are, marked no-store; the Credential
	// Endpoint's answer one request, so they're marked alike.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(e.httpStatus)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: string(e.code), ErrorDescription: errorDescription(e.description)})
}

// WriteError writes err to w: err's own WriteJSON if err is a *Error
// (as every error this package's own Request* methods return for a
// failure they can attribute to the request itself is), or a generic
// 500 otherwise — the one case this package can't itself produce a
// *Error for, e.g. an unexpected error from a Dependencies
// collaborator (see Error's own doc comment). Saves every HTTP adapter
// from reimplementing this same errors.As-or-fallback dance itself —
// mirrors fapigo/resource.WriteError's identical role on the resource-
// server side.
func WriteError(w http.ResponseWriter, err error) {
	var issErr *Error
	if errors.As(err, &issErr) {
		issErr.WriteJSON(w)
		return
	}
	http.Error(w, "server_error", http.StatusInternalServerError)
}

// errorDescription is description as error_description allows it:
// printable ASCII without '"' or '\' (RFC 6749 §5.2, OID4VCI
// §8.3.1.2). Quotes become apostrophes, other characters '?'.
func errorDescription(description string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '"':
			return '\''
		case r == '\\' || r < 0x20 || r > 0x7e:
			return '?'
		default:
			return r
		}
	}, description)
}

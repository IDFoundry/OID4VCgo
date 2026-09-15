package issuer

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorCode is the closed set of Credential Request/Response error
// codes §8.3.1.2 defines.
type ErrorCode string

const (
	ErrorInvalidCredentialRequest    ErrorCode = "invalid_credential_request" //nolint:gosec // an OID4VCI error code, not a credential
	ErrorUnknownCredentialConfig     ErrorCode = "unknown_credential_configuration"
	ErrorUnknownCredentialIdentifier ErrorCode = "unknown_credential_identifier"
	ErrorInvalidProof                ErrorCode = "invalid_proof"
	ErrorInvalidNonce                ErrorCode = "invalid_nonce"
	ErrorCredentialRequestDenied     ErrorCode = "credential_request_denied" //nolint:gosec // an OID4VCI error code, not a credential

	// ErrorInvalidTransactionID is the Deferred Credential Endpoint's
	// own additional error code (§9.3): the request's transaction_id
	// was not issued by this Credential Issuer, or was already used to
	// obtain a Credential.
	ErrorInvalidTransactionID ErrorCode = "invalid_transaction_id"
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

// WriteJSON writes e as a complete Credential Error Response (§8.3.1.2)
// to w: the "application/json" Content-Type, e's own HTTPStatus, and a
// {"error": ..., "error_description": ...} body built from Code and
// PublicDescription — never Unwrap's cause. Must be called before
// anything else writes to w.
func (e *Error) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.httpStatus)
	_ = json.NewEncoder(w).Encode(struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{Error: string(e.code), ErrorDescription: e.description})
}

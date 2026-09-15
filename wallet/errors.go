package wallet

import (
	"encoding/json"
	"fmt"
)

// Error is a Credential Error Response (§8.3.1) RequestCredential
// parsed from a non-200 HTTP response. Code is the closed set of error
// codes issuer.ErrorCode names (e.g. "invalid_proof",
// "invalid_credential_request") — kept here as a plain string, not
// issuer.ErrorCode, so this package doesn't need to import issuer just
// to describe a value it only ever reads off the wire.
type Error struct {
	HTTPStatus  int
	Code        string
	Description string
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("wallet: credential error response: %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("wallet: credential error response: %s", e.Code)
}

// parseError builds an Error from a non-2xx Credential Endpoint
// response — the {"error": ..., "error_description": ...} body
// §8.3.1.2 defines. If body isn't valid JSON (a proxy's own HTML error
// page, for instance), Code is left empty and the raw HTTP status is
// still reported.
func parseError(httpStatus int, body []byte) *Error {
	var wire struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(body, &wire)
	return &Error{HTTPStatus: httpStatus, Code: wire.Error, Description: wire.ErrorDescription}
}

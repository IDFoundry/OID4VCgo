package verifier

import "fmt"

// Error is a VerifyResponse failure attributable to the Wallet's own
// presented response — a malformed, untrusted, or non-conforming
// Presentation — as opposed to a plain error, which means a
// caller/deployment mistake in VerifyResponseRequest or Dependencies
// that must be fixed before retrying, not something to report back to
// the Wallet. errors.As(err, &verifierErr) lets an HTTP adapter choose
// "malformed presentation, respond 400" from "my own config is
// broken, respond 500 and alert" without string-matching error text —
// the same split issuer.Error/its own doc comment already establish
// on the issuance side, found in a repo-wide integrator-interface
// review. Unlike issuer.Error, this type has no WriteJSON: OID4VP's
// direct_post flow has no spec-defined error response format the
// Verifier itself must construct back to the Wallet (see the package
// doc comment) — this exists purely for the caller's own
// dispatch/logging, not to build a wire body.
type Error struct {
	description string
	cause       error
}

func newError(description string, cause error) *Error {
	return &Error{description: description, cause: cause}
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("verifier: %s: %v", e.description, e.cause)
	}
	return fmt.Sprintf("verifier: %s", e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

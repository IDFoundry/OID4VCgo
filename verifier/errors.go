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
	reason      Reason
	description string
	cause       error
}

// Reason is why a response or presentation failed verification, for a
// caller to branch on without matching error text.
type Reason string

const (
	// ReasonMalformed: a presentation that doesn't decode or parse, or a
	// VP Token with no presentation, or more than a query takes.
	ReasonMalformed Reason = "malformed"
	// ReasonStateMismatch: a response, or error response, whose state
	// isn't the request's: not an answer to it.
	ReasonStateMismatch Reason = "state_mismatch"
	// ReasonNotAnswered: what was presented doesn't answer the query, or
	// a credential's claims don't satisfy its Credential Query.
	ReasonNotAnswered Reason = "not_answered"
	// ReasonUntrustedIssuer: the issuer's key couldn't be resolved to a
	// trusted one, its certificate chain or document signer checks
	// failed, or it isn't one of the query's trusted_authorities.
	ReasonUntrustedIssuer Reason = "untrusted_issuer"
	// ReasonInvalidCredential: the credential's own signature or
	// validity (expiry, digests, status claim shape) failed.
	ReasonInvalidCredential Reason = "invalid_credential" //nolint:gosec // a failure reason, not a credential
	// ReasonHolderBinding: the holder binding failed: the Key Binding
	// JWT or mdoc device authentication, its key, audience, nonce or
	// age.
	ReasonHolderBinding Reason = "holder_binding"
	// ReasonUnrequestedClaims: a presentation discloses claims its
	// Credential Query didn't ask for (see
	// VerifyResponseRequest.AllowUnrequestedClaims).
	ReasonUnrequestedClaims Reason = "unrequested_claims"
)

// description is a fixed description of r, for a display that mustn't
// show what an answer's sender wrote (Transaction.LastError).
func (r Reason) description() string {
	switch r {
	case ReasonMalformed:
		return "it is malformed (malformed)"
	case ReasonStateMismatch:
		return "its state isn't this request's (state_mismatch)"
	case ReasonNotAnswered:
		return "what it presents doesn't answer the request (not_answered)"
	case ReasonUntrustedIssuer:
		return "a credential's issuer isn't trusted for it (untrusted_issuer)"
	case ReasonInvalidCredential:
		return "a credential's signature or validity failed (invalid_credential)"
	case ReasonHolderBinding:
		return "a credential's holder binding failed (holder_binding)"
	case ReasonUnrequestedClaims:
		return "a credential discloses claims the request didn't ask for (unrequested_claims)"
	}
	return "it failed verification"
}

func newError(reason Reason, description string, cause error) *Error {
	return &Error{reason: reason, description: description, cause: cause}
}

// Reason is why verification failed.
func (e *Error) Reason() Reason { return e.reason }

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("verifier: %s: %v", e.description, e.cause)
	}
	return fmt.Sprintf("verifier: %s", e.description)
}

// Unwrap returns the underlying cause, if any.
func (e *Error) Unwrap() error { return e.cause }

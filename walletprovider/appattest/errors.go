package appattest

import (
	"errors"
	"fmt"
)

// The errors Verifier and EvidenceVerifier return wrap one of these,
// for errors.Is, with the detail in the message: a Wallet Provider can
// log the detail and decide on the kind.
var (
	// ErrConfig: the Verifier itself is misconfigured, or is asked for
	// something it can't check (an assertion with no stored key).
	ErrConfig = errors.New("appattest: verifier misconfigured")
	// ErrMalformed: the attestation object, the assertion or a
	// certificate doesn't parse, is too large, or has the wrong shape.
	ErrMalformed = errors.New("appattest: malformed attestation")
	// ErrUntrustedRoot: the attestation's certificates don't chain to a
	// configured root, at Verifier.Now.
	ErrUntrustedRoot = errors.New("appattest: attestation not anchored at a trusted root")
	// ErrNonce: the attestation's nonce isn't the one its
	// authenticator data and the expected client data make: it was made
	// over other client data (another challenge, purpose or key).
	ErrNonce = errors.New("appattest: attestation nonce mismatch")
	// ErrKeyID: the attested key's identifier isn't the SHA-256 of its
	// public key.
	ErrKeyID = errors.New("appattest: attested key identifier mismatch")
	// ErrAppNotAllowed: the attestation or assertion is for an App ID
	// the Verifier doesn't accept.
	ErrAppNotAllowed = errors.New("appattest: app not allowed")
	// ErrEnvironment: the attestation is from App Attest's development
	// environment, and the Verifier accepts production only, or its
	// AAGUID is neither environment's.
	ErrEnvironment = errors.New("appattest: App Attest environment not accepted")
	// ErrCounter: an attestation's counter isn't zero, or an assertion's
	// doesn't exceed the last one accepted.
	ErrCounter = errors.New("appattest: counter not acceptable")
	// ErrSignature: the assertion's signature doesn't verify with the
	// attested key over the expected client data.
	ErrSignature = errors.New("appattest: assertion signature invalid")
)

func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

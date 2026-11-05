package androidkey

import (
	"errors"
	"fmt"
)

// The errors Verify returns wrap one of these, for errors.Is, with the
// detail in the message: a Wallet Provider can log the detail and
// decide on the kind.
var (
	// ErrConfig: the Verifier itself is misconfigured.
	ErrConfig = errors.New("androidkey: verifier misconfigured")
	// ErrMalformed: a certificate or the key description doesn't parse,
	// is too large, or the chain has the wrong shape.
	ErrMalformed = errors.New("androidkey: malformed attestation")
	// ErrChainSignature: a certificate isn't signed by the next one.
	ErrChainSignature = errors.New("androidkey: attestation chain signature invalid")
	// ErrUntrustedRoot: the chain doesn't end at a configured root.
	ErrUntrustedRoot = errors.New("androidkey: attestation chain not anchored at a trusted root")
	// ErrCertificateValidity: a certificate is outside its validity
	// period.
	ErrCertificateValidity = errors.New("androidkey: attestation certificate outside its validity")
	// ErrRevoked: Google's attestation status list revokes or suspends
	// a certificate in the chain. The error is a *RevokedError.
	ErrRevoked = errors.New("androidkey: attestation certificate revoked")
	// ErrStatusUnavailable: revocation must be checked, and no current
	// status list is held.
	ErrStatusUnavailable = errors.New("androidkey: attestation status list unavailable")
	// ErrChallenge: the attestation challenge isn't the expected one.
	ErrChallenge = errors.New("androidkey: wrong attestation challenge")
	// ErrAttestationVersion: the attestation version is older than the
	// Verifier takes.
	ErrAttestationVersion = errors.New("androidkey: attestation version too old")
	// ErrSoftwareLevel: the key or its attestation isn't in the TEE or
	// StrongBox (or not in StrongBox, when that's required).
	ErrSoftwareLevel = errors.New("androidkey: attestation security level too low")
	// ErrBootState: the bootloader is unlocked, or the boot wasn't
	// verified with a trusted key.
	ErrBootState = errors.New("androidkey: device boot state not trusted")
	// ErrPatchLevel: the OS patch level is older than the Verifier
	// takes.
	ErrPatchLevel = errors.New("androidkey: OS patch level too old")
	// ErrAppNotAllowed: the key wasn't made by an allowed app package
	// signed with an allowed certificate.
	ErrAppNotAllowed = errors.New("androidkey: attesting app not allowed")
	// ErrKeyProperties: the key's hardware-enforced properties — its
	// purpose, algorithm, curve or origin — aren't those of a signing
	// key generated in the secure hardware, or don't match the leaf
	// certificate's key.
	ErrKeyProperties = errors.New("androidkey: attested key properties not acceptable")
	// ErrKeyNotRequested: the chain attests a key the request to the
	// Wallet Provider doesn't name (EvidenceVerifier).
	ErrKeyNotRequested = errors.New("androidkey: attested key not one the request names")
)

func fail(kind error, format string, args ...any) error {
	return fmt.Errorf("%w: %s", kind, fmt.Sprintf(format, args...))
}

// RevokedError is the error for a certificate the status list names.
type RevokedError struct {
	// Position is the certificate's place in the chain, the leaf 0.
	Position int
	// Serial is its serial number, as the status list keys it.
	Serial string
	// Entry is the status list's entry for it.
	Entry StatusEntry
}

func (e *RevokedError) Error() string {
	msg := fmt.Sprintf("%v: certificate %d (serial %s) is %s", ErrRevoked, e.Position, e.Serial, e.Entry.Status)
	if e.Entry.Reason != "" {
		msg += ", reason " + e.Entry.Reason
	}
	return msg
}

// Unwrap returns ErrRevoked.
func (e *RevokedError) Unwrap() error { return ErrRevoked }

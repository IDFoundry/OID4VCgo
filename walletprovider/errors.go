package walletprovider

import "errors"

// The errors a Provider's methods return, possibly wrapped, for a
// request it refuses. An HTTP layer maps them to responses; any other
// error is the provider's own failure.
var (
	// ErrChallenge: the challenge is unknown, already used, expired, or
	// was issued for another Purpose.
	ErrChallenge = errors.New("walletprovider: invalid challenge")

	// ErrEvidenceRequired: the request carries no evidence. Nothing is
	// attested without it.
	ErrEvidenceRequired = errors.New("walletprovider: platform evidence is required")

	// ErrEvidenceKind: no EvidenceVerifier is configured for the
	// evidence's Kind.
	ErrEvidenceKind = errors.New("walletprovider: unsupported evidence kind")

	// ErrEvidenceRejected: the evidence didn't verify, or doesn't cover
	// the keys it was sent for.
	ErrEvidenceRejected = errors.New("walletprovider: evidence rejected")

	// ErrPolicy: the evidence verified, but the Policy refuses it.
	ErrPolicy = errors.New("walletprovider: refused by policy")

	// ErrInstanceNotFound: no instance has the ID.
	ErrInstanceNotFound = errors.New("walletprovider: instance not found")

	// ErrInstanceKeyRegistered: the key is already another's: a
	// registration key that's already registered or recorded as an
	// instance key, or an instance key recorded for another instance
	// or that is the instance's registration key. A key is one
	// instance's registration key or one of its instance keys, once.
	ErrInstanceKeyRegistered = errors.New("walletprovider: instance key already registered")

	// ErrUnknownInstanceKey: a Key Attestation request names an
	// instance key no Wallet Attestation recorded for the instance.
	ErrUnknownInstanceKey = errors.New("walletprovider: unknown instance key")

	// ErrInstanceNotActive: the instance is suspended or revoked.
	ErrInstanceNotActive = errors.New("walletprovider: instance not active")

	// ErrInstanceRevoked: the instance is revoked, which is final.
	ErrInstanceRevoked = errors.New("walletprovider: instance revoked")

	// ErrUnknownClient: the client ID isn't one of Config.ClientIDs.
	ErrUnknownClient = errors.New("walletprovider: unknown client")

	// ErrInvalidRequest: the request is malformed: an unsupported key,
	// too many keys, a key listed twice, or a signed request that
	// doesn't verify or doesn't match.
	ErrInvalidRequest = errors.New("walletprovider: invalid request")

	// ErrNoKeyAttested: no key in a Key Attestation request has evidence
	// that passed and a security level the Policy accepts.
	ErrNoKeyAttested = errors.New("walletprovider: no key could be attested")
)

// Store errors, which InstanceStore, InstanceKeyStore and
// ChallengeStore implementations return, possibly wrapped.
var (
	// ErrNotFound: no record has the key.
	ErrNotFound = errors.New("walletprovider: not found")

	// ErrExists: a record with the key already exists.
	ErrExists = errors.New("walletprovider: already exists")

	// ErrConflict: the record changed since it was read
	// (InstanceStore.Update's compare-and-swap).
	ErrConflict = errors.New("walletprovider: concurrent update")
)

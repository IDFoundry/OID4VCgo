package issuer

import (
	"context"
	"time"

	"github.com/idfoundry/oid4vcgo"
)

// CredentialOfferRecord is what CredentialOfferStore.Store persists for
// one Credential Offer issued by reference (§4.1.3).
type CredentialOfferRecord struct {
	// Reference is the opaque lookup key — the last path segment of
	// the credential_offer_uri CreateCredentialOffer returned.
	Reference string

	Offer oid4vci.CredentialOffer

	// ExpiresAt bounds how long the offer remains fetchable.
	// GetCredentialOffer checks it against the current time itself;
	// the store never judges expiry, mirroring NonceStore's own split.
	ExpiresAt time.Time
}

// CredentialOfferStore persists Credential Offers issued by reference,
// keyed by their own opaque Reference. Unlike NonceStore.Consume, Get
// does not retire the record it returns — a Wallet's GET request
// (§4.1.3) is not spec-mandated to be single-use, and retrying a
// dropped fetch must not fail just because an earlier attempt already
// succeeded.
type CredentialOfferStore interface {
	Store(ctx context.Context, record CredentialOfferRecord) error

	// Get retrieves the record identified by reference. It returns an
	// error if reference is unknown; the caller compares the returned
	// record's own ExpiresAt against the time it's serving at.
	Get(ctx context.Context, reference string) (CredentialOfferRecord, error)
}

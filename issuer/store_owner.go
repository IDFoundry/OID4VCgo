package issuer

import (
	"crypto/subtle"
	"fmt"
	"sync/atomic"
)

// storeOwner is the Owner this Issuer stamps on every record it saves
// in its stores (a pre-authorized_code, c_nonce, deferred transaction
// or notification_id): its Credential Issuer identifier, Config.Issuer.
// Credential Issuers sharing a store backend — the tenants of one
// deployment, say — each honour only the records they created, so a
// code, transaction_id or notification_id one of them handed out is
// unknown to the others: none redeems it under its own subjects,
// signer or policy.
func (iss *Issuer) storeOwner() string {
	return iss.cfg.Issuer.String()
}

// owns reports whether a record with owner is this Issuer's. One with
// no Owner, from a store that doesn't keep it, is accepted under
// AssuranceDevelopment, so a development store needn't; under
// AssuranceProduction it isn't, so a store that dropped Owner can't
// make the records of the Credential Issuers sharing it each other's.
func (iss *Issuer) owns(owner string) bool {
	if owner == "" {
		return iss.cfg.Assurance != AssuranceProduction
	}
	return subtle.ConstantTimeCompare([]byte(owner), []byte(iss.storeOwner())) == 1
}

// ownerReadBack is whether a store has been seen to keep the Owner of a
// record it saved (checkOwnerKept).
type ownerReadBack struct{ kept atomic.Bool }

// checkOwnerKept, under AssuranceProduction, reads back the Owner of a
// record just saved in store with read, and refuses a store that
// didn't keep it, until the store once has: records with no Owner are
// refused there (owns), so such a store would fail every later request
// for them instead of this one. The check repeats until it passes, so
// a store that drops Owner is refused on every save, not just the
// first.
func (iss *Issuer) checkOwnerKept(rb *ownerReadBack, store any, read func() (owner string, err error)) error {
	if iss.cfg.Assurance != AssuranceProduction || rb.kept.Load() {
		return nil
	}
	owner, err := read()
	if err != nil {
		return fmt.Errorf("reading back a saved record: %w", err)
	}
	if owner != iss.storeOwner() {
		return fmt.Errorf("the store (%T) didn't keep the record's Owner: an issuer store must persist every record field, or the Credential Issuers sharing it can't be kept apart", store)
	}
	rb.kept.Store(true)
	return nil
}

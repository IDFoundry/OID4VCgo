package statuslist

import (
	"context"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/listhttp"
)

// TokenStore shares the tokens a list's Publishers sign between the
// replicas serving it (Publisher.Tokens), so that one of them signs a
// list's token at a time and the others serve it, rather than each
// reading every status and signing its own. identifierlist.Publisher
// shares its tokens through one too.
//
// A list has a version: a number that grows whenever one of its
// statuses changes, in the same transaction as the change. A replica
// serves a stored token signed from the list's current version (or a
// later one) within CacheFor; once there's none, the replica that takes
// the list's lease (Claim) reads the version, then the statuses, signs a
// token and stores it with that version (Put), and the others serve it
// from their next check. A replica that can't take the lease serves
// the stored token only for a bounded time (Publisher.Tokens), then
// signs its own, so a holder that keeps renewing its lease but can't
// sign holds no replica to a stale token. A store that keeps no versions — every list
// at version zero — still shares tokens: a status change is then
// served once the token's CacheFor has passed, or at once when the
// replica that made it calls the Publisher's Invalidate, as without a
// TokenStore.
//
// A token is stored with its signer (StoredToken.Signer: the SHA-256 of
// its chain's leaf certificate), which a store keeps and returns as it
// was put, and a replica serves only a token its own signer signed.
// After a key or certificate changes, then, a replica signs its own
// token rather than serve one the old signer signed — which a relying
// party would refuse once the old signer is revoked. While replicas
// with different signers serve a list, as during a rollout, each signs
// its own and the newer stays stored: the token changes hands about
// once per TokensCheck until the rollout ends.
//
// A list is named by its uri, and each of its forms has its own token
// and lease. Times are kept to the millisecond. sqlstore's
// StatusListTokenStore is one, its versions kept by the status changes
// of its own StatusIndices.
type TokenStore interface {
	// Head returns the list's version and, without its bytes, the token
	// stored for form, if any.
	Head(ctx context.Context, uri string, form Form) (TokenHead, error)

	// Token returns the token stored for form, with its bytes, or false
	// if there's none.
	Token(ctx context.Context, uri string, form Form) (StoredToken, bool, error)

	// Claim gives holder the lease on signing form's token until until,
	// unless another holder's lease runs past now, and reports whether
	// holder holds it. One atomic step: of two concurrent Claims with
	// no live lease, one succeeds.
	Claim(ctx context.Context, uri string, form Form, holder string, now, until time.Time) (bool, error)

	// Put stores token as form's, unless the token stored is newer —
	// signed from a later version, or from the same one later — and
	// ends holder's lease, if it holds one.
	Put(ctx context.Context, uri string, form Form, holder string, token StoredToken) error
}

// StoredToken is a token in a TokenStore: its bytes, the list version
// it was signed from, when it was signed, when it expires, and who
// signed it (the SHA-256 of its chain's leaf certificate).
type StoredToken = listhttp.Stored

// TokenHead is what a TokenStore holds for one list and form, without
// the token's bytes: the list's version, and whether a token is stored
// and, if one is, its Version, SignedAt, Exp and Signer (its Bytes nil).
type TokenHead = listhttp.Head

// DefaultTokensCheck is Publisher.TokensCheck's default: how often a
// replica asks its TokenStore for a newer token.
const DefaultTokensCheck = 5 * time.Second

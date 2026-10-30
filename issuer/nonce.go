package issuer

import (
	"context"
	"errors"
	"time"
)

// ErrNonceUnknown is what a NonceStore's Consume returns, or wraps, for
// a c_nonce it holds no record of: one it never issued, one already
// consumed, or one it dropped after its ExpiresAt. A Credential Request
// carrying it is answered invalid_nonce (§8.3.1.2). Any other Consume
// error means the store couldn't answer (its backend unreachable, a
// timeout, context.Canceled or context.DeadlineExceeded), and fails the
// request as a plain error, a 500 from WriteError, rather than telling
// the Wallet its proof is stale.
var ErrNonceUnknown = errors.New("issuer: unknown or already consumed c_nonce")

// NonceIssuance is what NonceStore.Issue persists for one c_nonce this
// issuer has handed out via the Nonce Endpoint (§7).
type NonceIssuance struct {
	Nonce     string
	ExpiresAt time.Time
}

// NonceConsumption is the input to NonceStore.Consume.
type NonceConsumption struct {
	// Nonce is the value a Credential Request's key proof carried in
	// its own "nonce" claim (§8.2) — the lookup key.
	Nonce string
}

// NonceRecord is what Consume returns for a successfully consumed
// nonce — the expiry Issue persisted, for the caller to compare
// against the time it's verifying at. The store itself never judges
// expiry, mirroring FAPIgo's storage.NonceStore precisely.
type NonceRecord struct {
	ExpiresAt time.Time
}

// NonceStore persists c_nonce values this issuer has issued, keyed by
// the nonce value itself. There is no generic CRUD — Consume is the
// only way to check a nonce, and it always retires the record it
// returns, so a captured nonce can never be presented twice.
//
// §8.2's own example shows several key proofs in one Credential
// Request sharing a single c_nonce (batch issuance) — Consume is still
// called once per request, not once per proof, since freshness is a
// property of the request as a whole, not of each individual proof
// within it.
type NonceStore interface {
	Issue(ctx context.Context, issuance NonceIssuance) error

	// Consume atomically retrieves and retires the nonce identified by
	// consumption.Nonce. It returns an error wrapping ErrNonceUnknown if
	// the nonce is unknown or already consumed, and any other error only
	// when it couldn't answer; the caller checks the returned record's
	// own ExpiresAt against the time it's verifying at.
	Consume(ctx context.Context, consumption NonceConsumption) (NonceRecord, error)
}

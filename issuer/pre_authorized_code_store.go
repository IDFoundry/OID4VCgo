package issuer

import (
	"context"
	"errors"
	"time"
)

// ErrWrongTxCode is what Consume returns when code is known and
// unexpired but wantTxCode doesn't match the record's own TxCode —
// distinguishing this from "code is unknown or already consumed" lets
// a caller (ExchangePreAuthorizedCode) report the right error, and
// tells a PreAuthorizedCodeStore implementation which case must NOT
// invalidate code (see Consume's own doc comment for why that
// distinction is a security requirement, not just error-message
// polish).
var ErrWrongTxCode = errors.New("issuer: tx_code does not match")

// PreAuthorizedCodeRecord is what a caller stores when it issues a
// pre-authorized_code — as part of a Credential Offer's own
// Grants.PreAuthorizedCode (§4.1.1) — everything ExchangePreAuthorizedCode
// needs to validate a Token Request presenting it and decide what
// access to grant. This package never creates or issues a
// pre-authorized_code value itself, the same "caller-supplied" split
// CreateCredentialOffer's own doc comment already draws for it and
// issuer_state.
type PreAuthorizedCodeRecord struct {
	// TxCode is REQUIRED whenever the original Credential Offer's own
	// Grants.PreAuthorizedCode.TxCode was non-nil — the Wallet must
	// present the exact End-User Transaction Code value entered
	// (§6.1's own MUST), matched against this record's own value.
	// Empty when the offer carried no TxCode object at all, in which
	// case ExchangePreAuthorizedCode never checks
	// ExchangePreAuthorizedCodeRequest.TxCode.
	TxCode string

	// Scopes is what access this pre-authorized_code entitles the
	// resulting access token to.
	Scopes []string

	// CredentialConfigurationIDs, if non-empty, additionally mints one
	// fresh credential_identifier per entry (§6.2) and returns them all
	// via the Token Response's own "authorization_details" parameter
	// (RFC 9396 §5.1.1, this specification's own "openid_credential"
	// type) — see ExchangePreAuthorizedCodeResult.AuthorizationDetails.
	// Independent of Scopes — set this when the paired Credential
	// Offer's own credential_configuration_ids should also be
	// redeemable via credential_identifier (§8.2), entirely this
	// caller's own choice, the same "constructing an offer and
	// redeeming a pre-authorized_code are two separate steps" split
	// this store's own doc comment already draws.
	CredentialConfigurationIDs []string

	// ExpiresAt bounds how long this pre-authorized_code remains
	// redeemable.
	ExpiresAt time.Time
}

// PreAuthorizedCodeStore persists pre-authorized_code values a caller
// has issued and lets ExchangePreAuthorizedCode redeem one exactly
// once — a pre-authorized_code, like an authorization code, is a
// one-time credential — the same consume-once shape NonceStore
// already establishes for c_nonce.
type PreAuthorizedCodeStore interface {
	// Issue persists record under code, matching NonceStore.Issue's own
	// contract: implementations aren't required to reject a duplicate
	// code, since callers are expected to generate one with enough
	// entropy that a collision is negligible.
	Issue(ctx context.Context, code string, record PreAuthorizedCodeRecord) error

	// Consume retrieves code and checks it against wantTxCode
	// (ExchangePreAuthorizedCodeRequest.TxCode) in one atomic step —
	// but must invalidate code only when the check actually succeeds.
	// A record whose own TxCode is empty requires no check at all
	// (wantTxCode is ignored) and is always consumed on a successful
	// lookup. A record whose own TxCode is non-empty and doesn't match
	// wantTxCode MUST be left in place and return ErrWrongTxCode — not
	// invalidated — so a mistyped PIN doesn't permanently destroy the
	// code with no retry path (a real denial-of-service against the
	// code's own legitimate holder; found in a repo-wide security
	// review of an earlier implementation that consumed unconditionally
	// before checking TxCode). Returns a different (non-ErrWrongTxCode)
	// error if code is unknown or already consumed — expiry
	// (PreAuthorizedCodeRecord.ExpiresAt) is checked by
	// ExchangePreAuthorizedCode itself once Consume returns a record,
	// not by Consume.
	Consume(ctx context.Context, code, wantTxCode string) (PreAuthorizedCodeRecord, error)
}

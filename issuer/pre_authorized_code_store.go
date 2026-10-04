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

// ErrTooManyTxCodeAttempts is returned by PreAuthorizedCodeStore.Consume
// for a code whose tx_code was guessed wrong maxAttempts times: the code
// is invalidated and no further guess is compared.
var ErrTooManyTxCodeAttempts = errors.New("issuer: too many incorrect tx_code attempts")

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

	// Subject identifies, to this caller only, whose Credential this
	// pre-authorized_code redeems for — typically an opaque reference
	// to whatever the caller verified before making the offer (an
	// end-user account, a pending issuance transaction). The
	// Pre-Authorized Code Flow's own Token Request carries no end-user
	// identity of its own (§6.1), so without this nothing links the
	// resulting access token, and therefore a later Credential
	// Request, back to that data. ExchangePreAuthorizedCode passes it
	// through as AccessTokenParams.Subject unmodified; this package
	// never interprets it. Optional. Use an opaque, unguessable value,
	// not personal data: a self-contained access token (e.g. a JWT's
	// own "sub" claim) is readable by the Wallet.
	Subject string
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
	//
	// wrongAttempts is code's own running count of ErrWrongTxCode
	// outcomes so far (including this one), atomically incremented as
	// part of this same call whenever it returns ErrWrongTxCode —
	// meaningless (implementations may return 0) on any other outcome.
	//
	// maxAttempts (ExchangePreAuthorizedCode passes
	// Config.Limits.MaxTxCodeAttempts; 0 or less means no limit) bounds
	// the guesses, in the same atomic step as the comparison: once code
	// has maxAttempts wrong guesses, Consume MUST invalidate it and
	// return ErrTooManyTxCodeAttempts without comparing wantTxCode —
	// and a wrong guess that reaches maxAttempts invalidates it too.
	// Left to a separate Invalidate call after the comparison,
	// concurrent requests could each have a guess compared before any
	// of them invalidated the code (found in an adversarial review:
	// about 200 guesses per burst against a store with 1 ms latency).
	// Concurrent guesses against one code must each observe a distinct,
	// correctly incrementing count, and at most maxAttempts of them may
	// be compared.
	Consume(ctx context.Context, code, wantTxCode string, maxAttempts int) (record PreAuthorizedCodeRecord, wrongAttempts int, err error)

	// Invalidate permanently invalidates code, the same way a
	// successful Consume already does. ExchangePreAuthorizedCode also
	// calls it once Config.Limits.MaxTxCodeAttempts is reached, though
	// Consume itself must already have invalidated the code then (see
	// maxAttempts).
	// A no-op if code is already invalidated (consumed or previously
	// invalidated) or was never issued — Invalidate's own caller has
	// already decided code should stop existing, so there is nothing
	// further for it to report either way.
	Invalidate(ctx context.Context, code string) error
}

package issuer

import (
	"context"
	"errors"
	"time"
)

// ErrPreAuthorizedCodeUnknown is what a PreAuthorizedCodeStore's Consume
// returns, or wraps, for a code it holds no record of: one never
// issued, already consumed or invalidated, or dropped after its
// ExpiresAt. ExchangePreAuthorizedCode answers it invalid_grant. Any
// other Consume error that isn't one of the tx_code errors below, or
// accept's own, means the store couldn't answer (its backend
// unreachable, a timeout, context.Canceled or
// context.DeadlineExceeded), and fails the request as a plain error, a
// 500 from WriteError: the Wallet isn't told its code, or its holder's
// Transaction Code, is wrong when it may not be.
var ErrPreAuthorizedCodeUnknown = errors.New("issuer: unknown or already used pre-authorized_code")

// ErrWrongTxCode is what Consume returns when code is known and
// unexpired but wantTxCodeHash doesn't match the record's own
// TxCodeHash —
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

// ErrTxCodeRequired is what Consume returns when code's record has a
// TxCodeHash and the request sent no tx_code: an invalid_request (§6.3), not a
// wrong guess, so it neither counts as an attempt nor invalidates code.
var ErrTxCodeRequired = errors.New("issuer: tx_code is required")

// ErrTxCodeUnexpected is what Consume returns when code's record has no
// TxCodeHash and the request sent a tx_code: an invalid_request (§6.3). code is
// left in place.
var ErrTxCodeUnexpected = errors.New("issuer: tx_code was not expected")

// PreAuthorizedCodeRecord is what the issuer stores when it issues a
// pre-authorized_code — as part of a Credential Offer's own
// Grants.PreAuthorizedCode (§4.1.1) — everything ExchangePreAuthorizedCode
// needs to validate a Token Request presenting it and decide what
// access to grant. CreatePreAuthorizedOffer generates the code,
// stores this record and builds the offer in one step, its tx_code
// derived from the Transaction Code; IssuePreAuthorizedCode stores one
// for a code the caller made itself, in development.
//
// Neither the code nor its Transaction Code reaches the store: the
// store's key is a hash of the code, and TxCodeHash a hash of the
// Transaction Code keyed by the code, so a read of the store, or a
// leak of it, yields neither a redeemable code nor a PIN.
type PreAuthorizedCodeRecord struct {
	// Owner is the Credential Issuer that issued the code, its
	// Config.Issuer: only that Issuer redeems it, so Credential Issuers
	// sharing a store each redeem only their own codes. The issuer sets
	// it, and binds it into the store's key too; a store keeps it as it
	// is.
	Owner string

	// TxCodeHash is set whenever the original Credential Offer's own
	// Grants.PreAuthorizedCode.TxCode was non-nil — the Wallet must
	// present the exact End-User Transaction Code value entered
	// (§6.1's own MUST), and the store compares its hash with this.
	// Empty when the offer carried no TxCode object at all, in which
	// case a request carrying a tx_code is refused. The issuer sets it;
	// a store keeps it as it is, an opaque string.
	TxCodeHash string

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
//
// The issuer hands the store hashes, never the code or Transaction Code
// themselves (see PreAuthorizedCodeRecord): codeHash, the key, which
// is bound to the record's Owner as well as the code, and
// wantTxCodeHash, compared with the record's TxCodeHash. Both are
// opaque base64url strings of at most 43 characters to the store,
// which compares the two Transaction Code hashes in constant time
// (crypto/subtle) and otherwise treats them as any other key and value.
type PreAuthorizedCodeStore interface {
	// Issue persists record under codeHash, matching NonceStore.Issue's
	// own contract: implementations aren't required to reject a
	// duplicate key, since codes are generated with enough entropy that
	// a collision is negligible.
	Issue(ctx context.Context, codeHash string, record PreAuthorizedCodeRecord) error

	// Consume retrieves codeHash's record and checks it against
	// wantTxCodeHash (the hash of ExchangePreAuthorizedCodeRequest.TxCode)
	// in one atomic step — but must invalidate the code only when the
	// check actually succeeds (and accept, below, accepts the record). A
	// record whose own TxCodeHash is empty passes the check when
	// wantTxCodeHash is empty too; a non-empty wantTxCodeHash is refused
	// with ErrTxCodeUnexpected and the code left in place. A record
	// whose own TxCodeHash is non-empty and an empty wantTxCodeHash
	// returns ErrTxCodeRequired, counting no attempt and leaving the
	// code in place. A record whose own TxCodeHash is non-empty and
	// doesn't match wantTxCodeHash MUST be left in place and return
	// ErrWrongTxCode — not invalidated — so a mistyped PIN doesn't permanently destroy the
	// code with no retry path (a real denial-of-service against the
	// code's own legitimate holder; found in a repo-wide security
	// review of an earlier implementation that consumed unconditionally
	// before checking the Transaction Code). Returns an error wrapping
	// ErrPreAuthorizedCodeUnknown if the code is unknown or already
	// consumed, and any other error only when it couldn't answer — expiry
	// (PreAuthorizedCodeRecord.ExpiresAt) is checked by
	// ExchangePreAuthorizedCode, in accept, not by Consume itself.
	//
	// accept, when non-nil, is the caller's check of the record before
	// code is consumed. Once the tx_code check passes — never for an
	// unknown code, a missing, unexpected or wrong tx_code, or a code
	// with too many wrong attempts — Consume calls accept with a copy
	// of the record, in the same atomic step, and invalidates code only
	// if accept returns nil. When accept returns an error, Consume
	// returns that error (so that errors.Is and errors.As find it),
	// leaves code in place and counts no wrong attempt: the tx_code was
	// right, and the request was refused for something else.
	// ExchangePreAuthorizedCode checks there the code's expiry and that
	// it grants the requested authorization_details, so a request the
	// code doesn't allow doesn't spend it. accept doesn't call the store
	// and returns promptly, so a store may run it while holding its own
	// lock (or a row lock in a transaction). A store that retries its
	// atomic step may call accept again on each retry.
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
	// return ErrTooManyTxCodeAttempts without comparing wantTxCodeHash —
	// and a wrong guess that reaches maxAttempts invalidates it too.
	// Left to a separate Invalidate call after the comparison,
	// concurrent requests could each have a guess compared before any
	// of them invalidated the code (found in an adversarial review:
	// about 200 guesses per burst against a store with 1 ms latency).
	// Concurrent guesses against one code must each observe a distinct,
	// correctly incrementing count, and at most maxAttempts of them may
	// be compared.
	Consume(ctx context.Context, codeHash, wantTxCodeHash string, maxAttempts int, accept func(PreAuthorizedCodeRecord) error) (record PreAuthorizedCodeRecord, wrongAttempts int, err error)

	// Invalidate permanently invalidates code, the same way a
	// successful Consume already does. ExchangePreAuthorizedCode also
	// calls it once Config.Limits.MaxTxCodeAttempts is reached, though
	// Consume itself must already have invalidated the code then (see
	// maxAttempts).
	// A no-op if code is already invalidated (consumed or previously
	// invalidated) or was never issued — Invalidate's own caller has
	// already decided code should stop existing, so there is nothing
	// further for it to report either way.
	Invalidate(ctx context.Context, codeHash string) error
}

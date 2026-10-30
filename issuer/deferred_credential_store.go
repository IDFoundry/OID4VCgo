package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/idfoundry/oid4vcgo"
)

// ErrDeferredTransactionUnknown is what a DeferredTransactionStore's
// Get, Invalidate and Update return, or wrap, for a transaction_id it
// holds no record of, or one already invalidated.
// RequestDeferredCredential answers it invalid_transaction_id, and
// IssueDeferredCredential and DenyDeferredCredential return it wrapped.
// Any other store error means the store couldn't answer (its backend
// unreachable, a timeout, context.Canceled or
// context.DeadlineExceeded), and fails a Deferred Credential Request as
// a plain error, a 500 from WriteError.
var ErrDeferredTransactionUnknown = errors.New("issuer: unknown or invalidated transaction_id")

// DeferredTransactionStatus is a Deferred Issuance transaction's
// current state.
type DeferredTransactionStatus int

const (
	// DeferredTransactionPending means the Credential Issuer still
	// requires more time (§9.2's HTTP 202 case).
	DeferredTransactionPending DeferredTransactionStatus = iota

	// DeferredTransactionIssued means the requested Credential(s) are
	// ready (§9.2's HTTP 200 case).
	DeferredTransactionIssued

	// DeferredTransactionDenied means this Credential Issuer can no
	// longer issue the requested Credential(s) (§9.3's own
	// credential_request_denied guidance).
	DeferredTransactionDenied
)

// DeferredTransactionRecord is one Deferred Issuance transaction
// (§9). RequestCredential creates one when a request is deferred
// (CredentialRequest.Defer), holding what the request's proofs
// established; the deployment's own business process later resolves
// it with IssueDeferredCredential or DenyDeferredCredential, and
// RequestDeferredCredential answers the Wallet's polls from it. A
// deployment may also create and resolve records itself through the
// store.
type DeferredTransactionRecord struct {
	// Owner is the Credential Issuer that created the transaction, its
	// Config.Issuer: only that Issuer answers, issues or denies it, so
	// Credential Issuers sharing a store each see only their own
	// transactions, and another's transaction_id is unknown to them.
	// RequestCredential sets it; a record a deployment creates itself
	// must set it too. One with none is honoured only under
	// AssuranceDevelopment.
	Owner string

	// ClientID binds this transaction to the client that originally
	// requested it. When set, RequestDeferredCredential rejects a
	// request whose AuthorizedRequest.ClientIdentity isn't that client —
	// including an anonymous one (§9: "The Wallet MUST present ... an Access Token that
	// is valid for the issuance of the Credential(s) previously
	// requested").
	ClientID string

	// Subject binds this transaction to the access token subject that
	// requested it (AuthorizedRequest.Subject). When set,
	// RequestDeferredCredential rejects a request with a different
	// Subject. RequestCredential always sets it when it defers; a record
	// a deployment creates itself with neither ClientID nor Subject is
	// answerable by any access token.
	Subject string

	Status DeferredTransactionStatus

	// Credentials/NotificationID are meaningful, and should be set,
	// only when Status is DeferredTransactionIssued. NotificationID
	// should come from IssueNotificationID, called before marking this
	// transaction Issued — a value that was never issued through it
	// fails validation at RequestNotification, since it was never
	// persisted to Dependencies.Notifications.
	Credentials    []oid4vci.IssuedCredential
	NotificationID string

	// CredentialConfigurationID, BindingKeys and ExpiresAt are set when
	// RequestCredential defers (CredentialRequest.Defer): the
	// configuration to issue, the Wallet keys its proofs established —
	// one public JWK per Credential — and when the transaction lapses.
	// IssueDeferredCredential issues from them, and restarts ExpiresAt
	// so the Wallet has a full Limits.DeferredTransactionLifetime to
	// collect them. A transaction past ExpiresAt is answered as unknown;
	// zero means it never lapses. Nothing here deletes an expired
	// record: a production store should drop records some time after
	// their ExpiresAt.
	CredentialConfigurationID string
	BindingKeys               []json.RawMessage
	ExpiresAt                 time.Time

	// KeyAttestations are the compact Key Attestation JWTs (Appendix D)
	// that attested BindingKeys, each once, when the request's proofs
	// carried any. IssueDeferredCredential verifies each again, its
	// signature, exp and, with Dependencies.AttestationStatus, its
	// status, so a key attestation that has expired or been revoked
	// while the transaction was pending stops the issuance. A record
	// without them, one saved before this field existed or for proofs
	// with no key attestation, has nothing to check again.
	KeyAttestations []string

	// Reference is the deployment's own handle for the business
	// process behind the transaction (Deferral.Reference).
	Reference string
}

// DeferredTransactionStore persists Deferred Issuance transactions,
// keyed by their own opaque transaction_id. Under AssuranceProduction
// it must declare itself Durable, with AtomicConsume covering both
// Invalidate and Update.
type DeferredTransactionStore interface {
	// Get retrieves the record identified by transactionID. It returns
	// an error wrapping ErrDeferredTransactionUnknown if transactionID
	// is unknown or invalidated, and any other error only when it
	// couldn't answer.
	Get(ctx context.Context, transactionID string) (DeferredTransactionRecord, error)

	// Invalidate retires transactionID as its Credentials are returned
	// to the Wallet (§9.1: "The Credential Issuer MUST invalidate the
	// transaction_id after the Credential for which it was meant has
	// been obtained by the Wallet"). Called only for a
	// DeferredTransactionIssued record, and the Credentials are served
	// only if it succeeds — so it MUST be atomic and MUST fail, with an
	// error wrapping ErrDeferredTransactionUnknown, if transactionID is
	// unknown or already invalidated: of concurrent
	// requests for one transaction_id, exactly one gets the Credentials.
	// RequestDeferredCredential already holds them from Get by then, so
	// Invalidate MUST drop the stored Credentials: the Wallet has them,
	// and nothing reads them from the store again.
	Invalidate(ctx context.Context, transactionID string) error

	// Create saves a new transaction; transactionID must be unused.
	Create(ctx context.Context, transactionID string, record DeferredTransactionRecord) error

	// Update loads transactionID's record, calls fn on it, and saves
	// the result, atomically: concurrent Updates of one transaction run
	// one after another. fn's error aborts the update, saving nothing,
	// and is returned. It fails for an unknown or invalidated
	// transaction with an error wrapping ErrDeferredTransactionUnknown.
	Update(ctx context.Context, transactionID string, fn func(*DeferredTransactionRecord) error) error
}

package issuer

import "context"

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

// DeferredTransactionRecord is what DeferredTransactionStore.Get
// returns for one Deferred Issuance transaction. Creating a
// transaction (when the Credential Endpoint decides it cannot issue
// immediately) and resolving it (deciding issuance is ready, or that
// it can no longer proceed) is entirely the caller's own business
// process, running independently of a Wallet's polling — this package
// only implements the polling protocol §9 defines on top of it.
type DeferredTransactionRecord struct {
	// ClientID binds this transaction to the client that originally
	// requested it. RequestDeferredCredential rejects a request whose
	// AuthorizedRequest.ClientID doesn't match, when both are
	// non-empty (§9: "The Wallet MUST present ... an Access Token that
	// is valid for the issuance of the Credential(s) previously
	// requested").
	ClientID string

	Status DeferredTransactionStatus

	// Credentials/NotificationID are meaningful, and should be set,
	// only when Status is DeferredTransactionIssued.
	Credentials    []IssuedCredential
	NotificationID string
}

// DeferredTransactionStore persists Deferred Issuance transactions,
// keyed by their own opaque transaction_id — see
// DeferredTransactionRecord's own doc comment for why this package
// never creates or resolves one itself.
type DeferredTransactionStore interface {
	// Get retrieves the record identified by transactionID. It returns
	// an error if transactionID is unknown.
	Get(ctx context.Context, transactionID string) (DeferredTransactionRecord, error)

	// Invalidate retires transactionID after its Credentials have been
	// returned to the Wallet (§9.1: "The Credential Issuer MUST
	// invalidate the transaction_id after the Credential for which it
	// was meant has been obtained by the Wallet"). Called only right
	// after a DeferredTransactionIssued record has actually been served.
	Invalidate(ctx context.Context, transactionID string) error
}

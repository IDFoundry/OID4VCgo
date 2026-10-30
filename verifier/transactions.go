package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
)

// TransactionStatus is where a presentation request is in its life.
type TransactionStatus uint8

const (
	_ TransactionStatus = iota

	// TransactionPending is waiting for the Wallet's answer.
	TransactionPending

	// TransactionAwaitingRedirect is a same-device request whose answer
	// verified, waiting for the browser that asked to come back with
	// the response_code (OpenID4VP §8.2) before the result is released.
	TransactionAwaitingRedirect

	// TransactionDone verified; its result is available to the browser
	// that asked.
	TransactionDone

	// TransactionClosed ended without a result: closed by the caller, or
	// its same-device redirect arrived in a different browser.
	TransactionClosed

	// TransactionExpired outlived TransactionsConfig.Lifetime without
	// completing, or completed and is past its result's retention (see
	// Transactions.Lookup). Only ever reported by Transactions.Lookup;
	// a store never holds it.
	TransactionExpired
)

// Transaction is one presentation request's state: its secrets (the
// response decryption key, nonce and state) and its progress. A
// TransactionStore persists it; only Transactions interprets it.
type Transaction struct {
	ID                    string
	KeyID                 string // the response encryption key's kid, which routes an answer here
	State                 string
	Nonce                 string
	Query                 dcql.Query
	ResponseDecryptionKey *ecdsa.PrivateKey
	RequestObject         string

	// Origin is set for a Digital Credentials API request (BeginDCAPI):
	// the origin of the page that makes it, and the request's only
	// expected_origins entry. "" for a redirect-flow request.
	Origin string

	// Owner identifies the Transactions that created the transaction
	// (TransactionsConfig.Scope): only a Transactions with the same
	// owner reads it. "" for one saved before it was set, which only a
	// derived scope under AssuranceDevelopment reads.
	Owner string

	// BrowserBindingHash is SHA-256 of the browser binding Begin was
	// given; nil for an unbound request.
	BrowserBindingHash []byte
	SameDevice         bool
	ExpiresAt          time.Time

	// RetainUntil is the earliest a store may delete the transaction:
	// ExpiresAt plus TransactionsConfig.Lifetime, how long
	// Transactions.Lookup still reports a completed one's result. Zero
	// for one saved before it was set.
	RetainUntil time.Time

	Status TransactionStatus

	// ResponseCodeHash is SHA-256 (base64url) of the response_code a
	// same-device answer was given; "" once redeemed, and otherwise.
	ResponseCodeHash string

	// Result is set once the answer verified.
	Result *VerifyResponseResult

	// LastError is why the latest answer was refused, for the
	// Verifier's own display. Never sent to the Wallet. It isn't
	// evidence of anything the holder did: anyone who has fetched the
	// request (its QR code or link is enough) can send an answer that
	// fails, or an error response such as access_denied, which
	// OpenID4VP doesn't authenticate — so don't show it as the holder
	// declining.
	//
	// It never carries text the answer's sender chose: a refused answer
	// is recorded as a fixed description of its Reason, and an error
	// response as its error code alone. Only a TransactionsConfig.Status
	// or Accept refusal keeps its own text — they run only on an answer
	// that verified, holder binding included — kept short and printable. It
	// must still be escaped when displayed. The full error, for the
	// Verifier's logs, is the one HandleResponse (or
	// HandleDCAPIResponse) returns, which TransactionsConfig.OnRefused
	// also sees.
	LastError string
}

// TransactionStore persists Transactions. Update must be atomic per
// transaction: concurrent Updates of one ID run one after another,
// each seeing the previous one's saved result — that is what lets a
// transaction complete at most once, and a response_code be redeemed
// at most once. Lookups by KeyID and ResponseCodeHash must reflect the
// latest saved Transaction.
//
// One store may be shared by several Transactions — instances of one
// deployment, or the use cases of one relying party: each reads only
// the transactions it created (TransactionsConfig.Scope), so none can
// complete another's request under its own verification and policy. A
// store must persist each Transaction's Owner for that to hold: Begin
// and BeginDCAPI read the first transaction a Transactions creates back,
// and refuse a store that dropped it.
//
// A completed transaction's Result holds the claims the holder
// disclosed. Transactions never reports it past ExpiresAt plus
// TransactionsConfig.Lifetime (see Transactions.Lookup), and
// Transactions.Forget drops it on demand, but nothing here deletes a
// transaction: a store should delete each one some time after its
// ExpiresAt — no sooner than that retention, its RetainUntil, which an
// answer's browser may still need — rather than keep holders' claims
// indefinitely.
type TransactionStore interface {
	// Create saves a new transaction; its ID must be unused.
	Create(ctx context.Context, tx Transaction) error

	// Get returns the transaction with id, or ErrTransactionUnknown.
	Get(ctx context.Context, id string) (Transaction, error)

	// Update loads the transaction with id, calls fn on it, and saves
	// the result, atomically. fn's error aborts the update, saving
	// nothing, and is returned.
	Update(ctx context.Context, id string, fn func(*Transaction) error) error

	// IDByKeyID returns the ID of the transaction whose KeyID is kid,
	// or ErrTransactionUnknown.
	IDByKeyID(ctx context.Context, kid string) (string, error)

	// IDByResponseCode returns the ID of the transaction whose
	// ResponseCodeHash is codeHash, or ErrTransactionUnknown.
	IDByResponseCode(ctx context.Context, codeHash string) (string, error)
}

// StoreCapabilities is what a TransactionStore declares about itself,
// checked under AssuranceProduction.
type StoreCapabilities struct {
	// Durable: transactions survive a restart.
	Durable bool
	// AtomicUpdate: Update is atomic per transaction, across every
	// instance sharing the store.
	AtomicUpdate bool
}

// StoreAssurance is implemented by a TransactionStore that declares its
// capabilities; NewTransactions requires it, with both set, under
// AssuranceProduction.
type StoreAssurance interface {
	Capabilities() StoreCapabilities
}

// Errors Transactions returns.
var (
	ErrTransactionUnknown  = errors.New("verifier: unknown presentation request")
	ErrTransactionExpired  = errors.New("verifier: the presentation request has expired")
	ErrTransactionAnswered = errors.New("verifier: the presentation request has already been answered")
	ErrTransactionClosed   = errors.New("verifier: the presentation request is closed")
	ErrWrongBrowser        = errors.New("verifier: the presentation request belongs to another browser")
)

// TransactionsConfig configures Transactions.
type TransactionsConfig struct {
	// RequestURIBase is the URL request objects are served under; a
	// request's request_uri is RequestURIBase + "/" + its ID. REQUIRED
	// for Begin; a Digital Credentials API request (BeginDCAPI) has no
	// request_uri.
	RequestURIBase string

	// Lifetime bounds how long a request stays answerable, and how long
	// a same-device response_code stays redeemable. Zero means 10
	// minutes.
	Lifetime time.Duration

	// Verify is the verification every answer gets: its IssuerKeys,
	// MdocIssuerKeys, TrustedAuthorities, MaxKeyBindingAge and Now.
	// Query, Response, ExpectedNonce and ResponseEncryptionKey are set
	// per request, and Origin and ExpectedOrigins per Digital
	// Credentials API request (BeginDCAPI); leave them zero.
	Verify VerifyResponseRequest

	// Status, if set, checks every credential's revocation status (see
	// StatusPolicy) once an answer verifies, before Accept. Its error
	// refuses the answer as Accept's does. Nothing else checks
	// revocation: without Status, a revoked credential is accepted.
	Status *StatusPolicy

	// Accept, if set, runs after an answer verifies and Status passes
	// it, before the request completes — the Verifier's own checks
	// (Chain composes several). An error refuses the answer like a
	// failed verification: recorded as LastError, with the request left
	// open for another answer.
	//
	// Accept runs before the request completes atomically, so when two
	// answers to one request arrive together, both can be accepted and
	// only one completes it. Keep it free of side effects, or tie what
	// it records to the result that completed (TransactionView.Result).
	//
	// Its error's text is LastError (see Transaction.LastError): keep it
	// to what the Verifier's own display may show.
	Accept func(ctx context.Context, id string, result VerifyResponseResult) error

	// OnRefused, if set, is called with each refused answer to request
	// id and its full error, for the Verifier's logs: LastError keeps
	// only a fixed description of why (Transaction.LastError), and
	// ResponseHandler tells the sender nothing. The error's text may
	// carry values the sender chose — anyone with the request's QR code
	// or link can send an answer — so log it as data, quoted, and never
	// render it as markup.
	OnRefused func(ctx context.Context, id string, err error)

	// RedirectURI is where a same-device answer sends the browser back
	// to, with response_code added to its query (OpenID4VP §8.2).
	// REQUIRED for Begin with sameDevice.
	RedirectURI string

	// Origins are the serialized origins of the pages that may make a
	// Digital Credentials API request (BeginDCAPI): each https, or
	// loopback http under AssuranceDevelopment, with no path, query or
	// fragment; each is normalized as a browser serializes an origin
	// (scheme and host lowercased, no trailing "/" or default port).
	// BeginDCAPI refuses any other origin, so one taken from the request
	// (its Origin header, say) can't bind a presentation to a page the
	// Verifier doesn't serve. REQUIRED for BeginDCAPI under
	// AssuranceProduction: NewTransactions refuses a production
	// Transactions without them only when it has no RequestURIBase
	// either, and so can serve nothing else; otherwise BeginDCAPI
	// refuses each request. Under AssuranceDevelopment, empty allows any.
	Origins []string

	// NoStatusCheck declares that this Verifier deliberately checks no
	// credential's revocation status — its credentials carry none, say,
	// or it checks status its own way in Accept. Under
	// AssuranceProduction, NewTransactions needs either Status or this
	// (CheckStatusDecision): a Verifier that simply forgot Status would
	// take revoked credentials, and an Accept, which may check business
	// rules alone, doesn't count.
	NoStatusCheck bool

	// Scope names this Transactions among those sharing its
	// TransactionStore: each transaction records the scope that
	// created it, and a Transactions reads only its own — an answer
	// routed to, a result looked up for, a request closed in another
	// scope is ErrTransactionUnknown — so one never completes another's
	// request under its own Verify and Accept.
	//
	// "" derives the scope from the Verifier's client_id, its
	// response_uri and RequestURIBase, which tells apart instances that
	// differ in any of them. Set it, unique to each policy, where
	// instances sharing a store have all three in common but verify or
	// accept differently; instances of one deployment, alike, share it.
	// Transactions for the Digital Credentials API alone have no
	// RequestURIBase, so those of one Verifier always derive the same
	// scope: give each policy among them its own.
	//
	// A transaction saved before scopes were recorded has none: a
	// Transactions with the derived scope reads it, as before, under
	// AssuranceDevelopment; under AssuranceProduction, and with an
	// explicit Scope, none does. Begin and BeginDCAPI refuse a store
	// that doesn't keep a transaction's Owner.
	Scope string

	// ForgetResultOnRead releases each request's result once: the
	// Lookup that first reports it completed, Redeem or
	// HandleDCAPIResponse returns the result and, in the same Update,
	// drops it from the store and closes the request, as Forget does —
	// so the store holds the claims the holder disclosed only until the
	// Verifier has them. A later Lookup reports TransactionClosed. Set
	// it where the Verifier takes the result from its first read; a
	// Verifier that loses it then (a crash before it's used) can't read
	// it again, and the holder presents again.
	ForgetResultOnRead bool
}

// Transactions tracks presentation requests from creation to a verified
// result, so that an answer completes only the request it answers, at
// most once, and its result reaches only the browser that asked
// (OpenID4VP §13.3). It routes each direct_post.jwt answer to its
// request by the response encryption key's kid, checks state, verifies
// it against that request's own nonce and key, and completes the
// request atomically. A same-device request releases its result only
// when the browser comes back with the single-use response_code, bound
// to it by a browser binding the caller keeps as a cookie.
//
// Answers that fail — including the Wallet's own error responses, which
// anyone holding the request's public key can send — are recorded but
// leave the request open, so they can't be used to cancel it.
//
// It covers the redirect flows (cross-device and same-device) with
// request_uri fetched by GET, and signed OpenID4VP requests over the
// Digital Credentials API (BeginDCAPI, HandleDCAPIResponse). Use the
// lower-level BuildAuthorizationRequest, ParseDirectPostJWTResponse and
// VerifyResponse directly for anything else.
type Transactions struct {
	v     *Verifier
	store TransactionStore
	cfg   TransactionsConfig

	// owner is what this Transactions' transactions record as their
	// Owner; derived is whether it's the derived scope, which also
	// reads a transaction with none outside AssuranceProduction.
	owner   string
	derived bool

	// ownerKept is set once the store has been seen to keep a created
	// transaction's Owner (create).
	ownerKept atomic.Bool
}

// NewTransactions builds Transactions for v, keeping state in store.
func NewTransactions(v *Verifier, store TransactionStore, cfg TransactionsConfig) (*Transactions, error) {
	switch {
	case v == nil:
		return nil, errors.New("verifier: transactions: a Verifier is required")
	case store == nil:
		return nil, errors.New("verifier: transactions: a TransactionStore is required")
	}
	if cfg.RequestURIBase != "" {
		if err := checkAbsoluteURL("request_uri_base", cfg.RequestURIBase, v.cfg.Assurance); err != nil {
			return nil, err
		}
	}
	if cfg.RedirectURI != "" {
		if err := checkAbsoluteURL("redirect_uri", cfg.RedirectURI, v.cfg.Assurance); err != nil {
			return nil, err
		}
	}
	origins, err := weborigin.NormalizeAll(cfg.Origins, v.cfg.Assurance == AssuranceDevelopment)
	if err != nil {
		return nil, fmt.Errorf("verifier: transactions: origins: %w", err)
	}
	cfg.Origins = origins
	if cfg.Lifetime < 0 {
		return nil, errors.New("verifier: transactions: lifetime must not be negative")
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 10 * time.Minute
	}
	if err := checkTransactionsVerify(cfg.Verify); err != nil {
		return nil, err
	}
	if err := CheckStatusDecision(v.cfg.Assurance, cfg.Status, cfg.NoStatusCheck); err != nil {
		return nil, fmt.Errorf("verifier: transactions: %w", err)
	}
	if v.cfg.Assurance == AssuranceProduction {
		if err := checkProductionTransactions(store, cfg); err != nil {
			return nil, err
		}
	}
	t := &Transactions{v: v, store: store, cfg: cfg}
	t.owner, t.derived = ownerScope(v, cfg)
	return t, nil
}

// ownerScope is the Owner the transactions Transactions for v and cfg
// create record, and whether it's derived (TransactionsConfig.Scope).
func ownerScope(v *Verifier, cfg TransactionsConfig) (owner string, derived bool) {
	if cfg.Scope != "" {
		return "scope:" + cfg.Scope, false
	}
	h := sha256.New()
	for _, part := range []string{v.ClientID(), v.cfg.ResponseURI.String(), cfg.RequestURIBase} {
		// Length-prefixed, so no two triples hash alike.
		_, _ = fmt.Fprintf(h, "%d:%s", len(part), part) // a hash.Hash never fails to write
	}
	return "derived:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), true
}

// owns reports whether tx is this Transactions' to read. One without
// an Owner, saved before scopes were recorded, is the derived scope's,
// except under AssuranceProduction: there, a store that lost the Owner
// mustn't make every derived scope's transactions each other's.
func (t *Transactions) owns(tx Transaction) bool {
	if tx.Owner == "" {
		return t.derived && t.v.cfg.Assurance != AssuranceProduction
	}
	return subtle.ConstantTimeCompare([]byte(tx.Owner), []byte(t.owner)) == 1
}

// create saves the new transaction tx. Until the store has once given
// back a created transaction with its Owner, it reads tx back and
// refuses a store that dropped it: scopes (TransactionsConfig.Scope)
// keep Transactions sharing a store apart only if the store persists
// Owner, and one that doesn't would silently let any derived scope
// read the others' transactions. The check repeats until it passes,
// so a store that drops Owner is refused on every Begin, not just the
// first.
func (t *Transactions) create(ctx context.Context, tx Transaction) error {
	if err := t.store.Create(ctx, tx); err != nil {
		return fmt.Errorf("verifier: transactions: store: %w", err)
	}
	if t.ownerKept.Load() {
		return nil
	}
	saved, err := t.store.Get(ctx, tx.ID)
	if err != nil {
		return fmt.Errorf("verifier: transactions: store: reading back a created transaction: %w", err)
	}
	if saved.Owner != tx.Owner {
		return fmt.Errorf("verifier: transactions: the store (%T) didn't keep the transaction's Owner: a TransactionStore must persist every Transaction field, or TransactionsConfig.Scope can't keep the Transactions sharing it apart", t.store)
	}
	t.ownerKept.Store(true)
	return nil
}

// get is the store's transaction id, ErrTransactionUnknown when it's
// another scope's: whether it exists there isn't this one's to tell.
func (t *Transactions) get(ctx context.Context, id string) (Transaction, error) {
	tx, err := t.store.Get(ctx, id)
	if err != nil {
		return Transaction{}, err
	}
	if !t.owns(tx) {
		return Transaction{}, ErrTransactionUnknown
	}
	return tx, nil
}

// update is the store's Update of the transaction id, refused with
// ErrTransactionUnknown when it's another scope's.
func (t *Transactions) update(ctx context.Context, id string, fn func(*Transaction) error) error {
	return t.store.Update(ctx, id, func(cur *Transaction) error {
		if !t.owns(*cur) {
			return ErrTransactionUnknown
		}
		return fn(cur)
	})
}

// checkTransactionsVerify refuses, in TransactionsConfig.Verify, the
// fields Transactions sets per request or takes from its own config.
func checkTransactionsVerify(verify VerifyResponseRequest) error {
	if verify.Query.Credentials != nil || verify.ExpectedNonce != "" || verify.ResponseEncryptionKey != nil || verify.Origin != "" || verify.ExpectedOrigins != nil || verify.Response.VPToken != nil {
		return errors.New("verifier: transactions: verify: query, response, expected_nonce, response_encryption_key, origin and expected_origins are set per request; leave them zero")
	}
	if err := checkTimeBounds(verify); err != nil {
		return err
	}
	if err := checkIssuerKeysValid(verify); err != nil {
		return fmt.Errorf("verifier: transactions: verify: %w", err)
	}
	if verify.Accept != nil || verify.Status != nil || verify.NoStatusCheck {
		return errors.New("verifier: transactions: set status, accept and no_status_check on the transactions config, not on verify")
	}
	return nil
}

// checkProductionTransactions refuses a store and config that aren't
// fit for AssuranceProduction.
func checkProductionTransactions(store TransactionStore, cfg TransactionsConfig) error {
	asserter, ok := store.(StoreAssurance)
	if !ok || !asserter.Capabilities().Durable || !asserter.Capabilities().AtomicUpdate {
		return errors.New("verifier: transactions: the store must implement verifier.StoreAssurance with Durable and AtomicUpdate under AssuranceProduction")
	}
	if err := checkProductionKeySources(cfg.Verify); err != nil {
		return fmt.Errorf("verifier: transactions: %w", err)
	}
	if cfg.Verify.IssuerAuthorized == nil && !cfg.Verify.AnyIssuerForAnyType {
		return errors.New("verifier: transactions: under AssuranceProduction, set verify.issuer_authorized (which issuers may issue which types) or verify.any_issuer_for_any_type: without either, any trusted issuer is accepted for any type")
	}
	if cfg.RequestURIBase == "" && len(cfg.Origins) == 0 {
		// Without RequestURIBase only BeginDCAPI can begin a request,
		// and without Origins it refuses every one.
		return errors.New("verifier: transactions: under AssuranceProduction, a Transactions without request_uri_base serves the Digital Credentials API alone: set origins, the origins of the pages that make its requests")
	}
	return nil
}

func checkAbsoluteURL(name, raw string, assurance AssuranceLevel) error {
	u, err := url.Parse(raw)
	switch {
	case raw == "":
		return fmt.Errorf("verifier: transactions: %s is required", name)
	case err != nil || !u.IsAbs() || u.Host == "":
		return fmt.Errorf("verifier: transactions: %s %q isn't an absolute URL", name, raw)
	case u.Scheme == "https":
		return nil
	case u.Scheme == "http" && assurance == AssuranceDevelopment && isLoopback(u.Hostname()):
		return nil
	default:
		return fmt.Errorf("verifier: transactions: %s %q must be https", name, raw)
	}
}

// Begun is a newly created presentation request.
type Begun struct {
	// ID identifies the request: its request_uri path segment, and the
	// handle Lookup and Close take.
	ID string

	// Link is the openid4vp:// Authorization Request to hand the
	// Wallet — as a QR code for another device, or a link on this one.
	Link string
}

// MinBrowserBindingLength is the shortest browser binding Begin
// accepts: enough for a base64url-encoded 96-bit random token, and well
// past a user ID or a short session number, which an attacker who sees
// the public request ID could guess.
const MinBrowserBindingLength = 16

// Begin creates a presentation request for query.
//
// browserBinding ties the request's result to whoever asked: an
// unguessable secret the caller keeps — a cookie on the browser that
// asked, or a value held server-side when no browser is involved — and
// passes back to Lookup and Redeem. Only its hash is stored. It is
// required: the request's ID is public, as the last segment of the
// request_uri in its link or QR code, so the binding is what keeps the
// result from anyone who saw that, and so must be at least
// MinBrowserBindingLength bytes — a random token, not a user ID or a
// short session number. A same-device request (sameDevice)
// also needs TransactionsConfig.RedirectURI, where its answer sends the
// browser back with a response_code.
func (t *Transactions) Begin(ctx context.Context, query dcql.Query, browserBinding string, sameDevice bool) (Begun, error) {
	if len(browserBinding) < MinBrowserBindingLength {
		return Begun{}, fmt.Errorf("verifier: transactions: a browser binding of at least %d bytes is required: an unguessable random token", MinBrowserBindingLength)
	}
	if t.cfg.RequestURIBase == "" {
		return Begun{}, errors.New("verifier: transactions: Begin needs TransactionsConfig.RequestURIBase")
	}
	if sameDevice && t.cfg.RedirectURI == "" {
		return Begun{}, errors.New("verifier: transactions: a same-device request needs TransactionsConfig.RedirectURI")
	}
	if err := t.checkVerifies(query); err != nil {
		return Begun{}, err
	}
	id, err := t.randomToken()
	if err != nil {
		return Begun{}, err
	}
	secret, err := t.randomToken()
	if err != nil {
		return Begun{}, err
	}
	// The state names its request, so an unencrypted error response,
	// which has no response key to route it by, can be tied to it
	// (HandleUnencryptedError); the secret part makes it unguessable.
	state := id + stateSeparator + secret
	built, err := t.v.BuildAuthorizationRequest(BuildAuthorizationRequestRequest{Query: query, State: state})
	if err != nil {
		return Begun{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	tx := Transaction{
		ID: id, KeyID: built.ResponseEncryptionKeyID, State: state, Nonce: built.Nonce, Query: query,
		ResponseDecryptionKey: built.ResponseDecryptionKey, RequestObject: built.RequestObject,
		SameDevice: sameDevice, Status: TransactionPending, Owner: t.owner,
	}
	tx.ExpiresAt, tx.RetainUntil = t.expiry()
	sum := sha256.Sum256([]byte(browserBinding))
	tx.BrowserBindingHash = sum[:]
	if err := t.create(ctx, tx); err != nil {
		return Begun{}, err
	}
	link := "openid4vp://?" + url.Values{
		"client_id": {t.v.ClientID()}, "request_uri": {t.cfg.RequestURIBase + "/" + id},
	}.Encode()
	return Begun{ID: id, Link: link}, nil
}

// RequestObject returns the signed Request Object to serve at the
// request_uri of the request id, until the request expires. It's served
// alike whether the request is pending, answered or closed: anyone
// holding the request's QR code can fetch it, and a request_uri that
// stopped answering would tell them the holder had presented. An answer
// a Wallet sends to a request that's no longer pending is refused.
func (t *Transactions) RequestObject(ctx context.Context, id string) (string, error) {
	tx, err := t.get(ctx, id)
	if err != nil {
		return "", err
	}
	if tx.Origin != "" {
		// A Digital Credentials API request goes to the page, not to a request_uri.
		return "", ErrTransactionUnknown
	}
	if !t.now().Before(tx.ExpiresAt) {
		return "", ErrTransactionExpired
	}
	return tx.RequestObject, nil
}

// Answered is an answer that verified and completed its request.
type Answered struct {
	ID string

	// RedirectURI, for a same-device request, is where the Wallet must
	// send the browser: TransactionsConfig.RedirectURI with the
	// response_code (OpenID4VP §8.2). "" for a cross-device request.
	RedirectURI string
}

// HandleResponse processes a direct_post.jwt answer — the "response"
// form parameter — end to end: routes it to its request by kid, checks
// the request is still pending, decrypts it with that request's key,
// checks state, verifies it against the request's own query and nonce,
// runs TransactionsConfig.Accept, and completes the request. The
// request completes at most once: a second answer, even a valid one,
// gets ErrTransactionAnswered.
//
// A refused answer is recorded as the request's LastError, and the
// request stays open. The returned error's text is for the Verifier's
// logs, not for the Wallet: ResponseHandler replies with a generic
// description.
//
// A Wallet's Authorization Error Response (§8.5) whose state matches
// the request is recorded the same way, and returned as a
// *ResponseError: the request stays open, since the state is in the
// request's public Request Object and anyone could send one — which is
// also why LastError mustn't be shown as the holder declining. One whose
// state doesn't match is refused like any other answer.
//
// An error response carrying the state of a request that's no longer
// pending — answered, closed or expired — is answered as a pending
// request's is: returned as a *ResponseError (which also matches the
// request's ErrTransactionAnswered, ErrTransactionClosed or
// ErrTransactionExpired), with a same-device request's redirect_uri,
// though not recorded. Anyone holding the request's QR code or link can
// send one, and a reply that differed would tell them whether the
// holder had presented.
func (t *Transactions) HandleResponse(ctx context.Context, responseJWE string) (Answered, error) {
	kid, err := ResponseKeyID(responseJWE)
	if err != nil {
		return Answered{}, err
	}
	id, err := t.store.IDByKeyID(ctx, kid)
	if err != nil {
		return Answered{}, storeFault(err)
	}
	tx, err := t.get(ctx, id)
	if err != nil {
		return Answered{}, storeFault(err)
	}
	if tx.Origin != "" {
		// A Digital Credentials API request's answer comes back through
		// its page (HandleDCAPIResponse), never to the response endpoint.
		return Answered{}, ErrTransactionUnknown
	}
	if err := t.checkPending(tx); err != nil {
		return t.answerNotPending(tx, responseJWE, err)
	}
	result, err := t.verify(ctx, tx, responseJWE)
	if err != nil {
		t.recordFailure(ctx, id, err)
		var walletErr *ResponseError
		if errors.As(err, &walletErr) && tx.SameDevice {
			// The holder's browser goes back to the Verifier, which shows
			// the refusal (HAIP 1.0 §5.1: in the same-device flow,
			// "Verifiers MUST include redirect_uri" in the response).
			return Answered{ID: id, RedirectURI: withQuery(t.cfg.RedirectURI, "error", errorCodeOf(walletErr.Code))}, err
		}
		return Answered{}, err
	}

	var code string
	if tx.SameDevice {
		if code, err = t.randomToken(); err != nil {
			return Answered{}, &serverFault{err}
		}
	}
	err = t.update(ctx, id, func(cur *Transaction) error {
		if err := t.checkPending(*cur); err != nil {
			return err
		}
		cur.Result, cur.LastError = &result, ""
		if cur.SameDevice {
			cur.Status, cur.ResponseCodeHash = TransactionAwaitingRedirect, hashToken(code)
		} else {
			cur.Status = TransactionDone
		}
		return nil
	})
	if err != nil {
		return Answered{}, storeFault(err)
	}
	answered := Answered{ID: id}
	if tx.SameDevice {
		answered.RedirectURI = withQuery(t.cfg.RedirectURI, "response_code", code)
	}
	return answered, nil
}

// answerNotPending answers responseJWE, sent to tx when it's no longer
// pending (notPending says why), as it would have been answered while
// pending, so the reply doesn't tell whoever holds the request's public
// key whether the holder has presented: an error response carrying the
// request's state is acknowledged — returned as a *ResponseError, with
// a same-device request's redirect_uri — though not recorded, and
// anything else is refused with notPending. It's decrypted either way,
// as a pending request's answer is.
func (t *Transactions) answerNotPending(tx Transaction, responseJWE string, notPending error) (Answered, error) {
	_, err := t.v.ParseDirectPostJWTResponse(responseJWE, tx.ResponseDecryptionKey)
	var walletErr *ResponseError
	if !errors.As(err, &walletErr) || subtle.ConstantTimeCompare([]byte(walletErr.State), []byte(tx.State)) != 1 {
		return Answered{}, notPending
	}
	var answered Answered
	if tx.SameDevice {
		answered = Answered{ID: tx.ID, RedirectURI: withQuery(t.cfg.RedirectURI, "error", errorCodeOf(walletErr.Code))}
	}
	return answered, fmt.Errorf("%w: %w", notPending, walletErr)
}

// verify decrypts, checks state, verifies and accepts one answer.
func (t *Transactions) verify(ctx context.Context, tx Transaction, responseJWE string) (VerifyResponseResult, error) {
	parsed, err := t.v.ParseDirectPostJWTResponse(responseJWE, tx.ResponseDecryptionKey)
	var walletErr *ResponseError
	switch {
	case errors.As(err, &walletErr):
		// An error response is this request's only if it echoes the
		// request's state.
		if subtle.ConstantTimeCompare([]byte(walletErr.State), []byte(tx.State)) != 1 {
			return VerifyResponseResult{}, newError(ReasonStateMismatch, "the error response's state doesn't match the request", nil)
		}
		return VerifyResponseResult{}, err
	case err != nil:
		return VerifyResponseResult{}, err
	}
	if subtle.ConstantTimeCompare([]byte(parsed.State), []byte(tx.State)) != 1 {
		return VerifyResponseResult{}, newError(ReasonStateMismatch, "the response's state doesn't match the request", nil)
	}
	return t.verifyParsed(ctx, tx, parsed)
}

// verifyParsed verifies and accepts one decrypted answer to tx.
func (t *Transactions) verifyParsed(ctx context.Context, tx Transaction, parsed ParsedResponse) (VerifyResponseResult, error) {
	req := t.cfg.Verify
	req.Query, req.Response, req.ExpectedNonce, req.ResponseEncryptionKey = tx.Query, parsed, tx.Nonce, tx.ResponseDecryptionKey
	if tx.Origin != "" {
		req.Origin, req.ExpectedOrigins = tx.Origin, []string{tx.Origin}
	}
	req.statusByTransactions = true
	result, err := t.v.VerifyResponse(ctx, req)
	if err != nil {
		return VerifyResponseResult{}, err
	}
	if t.cfg.Status != nil {
		if err := t.cfg.Status.Check(ctx, result.Credentials...); err != nil {
			return VerifyResponseResult{}, &acceptError{err}
		}
	}
	if t.cfg.Accept != nil {
		if err := t.cfg.Accept(ctx, tx.ID, result); err != nil {
			return VerifyResponseResult{}, &acceptError{err}
		}
	}
	return result, nil
}

// acceptError is TransactionsConfig.Status's or Accept's refusal of an
// answer that verified: its text is the Verifier's own, or describes
// the credential's status, so LastError keeps it.
type acceptError struct{ err error }

func (e *acceptError) Error() string { return e.err.Error() }
func (e *acceptError) Unwrap() error { return e.err }

// recordFailure notes why an answer was refused, if the request is
// still pending. Best effort: a store error here doesn't change the
// answer's own error.
// stateSeparator separates a request's ID from the secret in its state.
const stateSeparator = "."

// HandleUnencryptedError takes an unencrypted error response (OpenID4VP
// §8.3.1: a Wallet unable to encrypt "MAY send an error response
// without encryption"), its error code and the state it echoed: the
// request whose state that is records it as its LastError, still
// pending, and a same-device request is answered with its redirect_uri
// (HAIP 1.0 §5.1). It's unauthenticated, so it never closes the
// request: anyone who saw the Request Object could send one. A state
// that names no request is acknowledged with nothing. One naming a
// request that's no longer pending is answered as if it were, though
// not recorded, so the reply doesn't tell whoever sent it whether the
// holder has presented.
func (t *Transactions) HandleUnencryptedError(ctx context.Context, code, state string) Answered {
	id, _, ok := strings.Cut(state, stateSeparator)
	if !ok || id == "" {
		return Answered{}
	}
	tx, err := t.get(ctx, id)
	if err != nil || tx.Origin != "" || subtle.ConstantTimeCompare([]byte(state), []byte(tx.State)) != 1 {
		return Answered{}
	}
	walletErr := &ResponseError{Code: errorCodeOf(code)}
	if t.checkPending(tx) == nil {
		t.recordFailure(ctx, id, walletErr)
	}
	if !tx.SameDevice {
		return Answered{ID: id}
	}
	return Answered{ID: id, RedirectURI: withQuery(t.cfg.RedirectURI, "error", walletErr.Code)}
}

func (t *Transactions) recordFailure(ctx context.Context, id string, cause error) {
	if t.cfg.OnRefused != nil {
		t.cfg.OnRefused(ctx, id, cause)
	}
	_ = t.update(ctx, id, func(cur *Transaction) error {
		if cur.Status != TransactionPending {
			return ErrTransactionAnswered
		}
		cur.LastError = failureText(cause)
		return nil
	})
}

// maxFailureText bounds LastError.
const maxFailureText = 256

// failureText is what LastError records for cause. Anyone holding the
// request's public key can send an answer, and an error's text can
// carry values from it — a JWE header, a claim, an error description
// — so only fixed text is recorded for one: a Wallet's error response
// is reduced to its error code when that's a plain token, and a failed
// verification to a description of its Reason. A Status or Accept
// refusal, which only an answer that verified can reach, keeps its own text,
// cut to maxFailureText with anything unprintable replaced.
//
// Every refusal is recorded, whether or not the answer decrypted:
// decrypting proves nothing about its sender, since anyone can encrypt
// to the request's public key, and a genuine Wallet's answer can fail
// before it decrypts too.
func failureText(cause error) string {
	var walletErr *ResponseError
	var accepted *acceptError
	var verr *Error
	switch {
	case errors.As(cause, &walletErr):
		if isErrorCode(walletErr.Code) {
			return "an error response arrived: " + walletErr.Code
		}
		return "an error response arrived"
	case errors.As(cause, &accepted):
		return printableText(accepted.err.Error())
	case errors.As(cause, &verr):
		return "the answer was refused: " + verr.Reason().description()
	}
	// A plain error: a mistake in the Verifier's own configuration.
	return "the answer couldn't be verified: the Verifier's configuration is incomplete (see the returned error)"
}

// printableText is text cut to maxFailureText, with anything
// unprintable replaced.
func printableText(text string) string {
	var b strings.Builder
	for _, r := range text {
		if b.Len() >= maxFailureText {
			b.WriteString("…")
			break
		}
		if !unicode.IsPrint(r) {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isErrorCode reports whether code is a plausible OAuth error code:
// 1–64 lowercase letters, digits and underscores (RFC 6749 §5.2 codes
// and the extensions OpenID4VP adds all fit).
func isErrorCode(code string) bool {
	if code == "" || len(code) > 64 {
		return false
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// Redeem releases a same-device request's result to the browser the
// Wallet sent back with responseCode. The code is single-use. If
// browserBinding isn't the one the request began with — the redirect
// arrived in another browser, e.g. a victim's in a session fixation
// attempt — the request is closed and ErrWrongBrowser returned.
func (t *Transactions) Redeem(ctx context.Context, responseCode, browserBinding string) (TransactionView, error) {
	if responseCode == "" {
		return TransactionView{}, ErrTransactionUnknown
	}
	codeHash := hashToken(responseCode)
	id, err := t.store.IDByResponseCode(ctx, codeHash)
	if err != nil {
		return TransactionView{}, err
	}
	var view TransactionView
	var wrongBrowser bool
	err = t.update(ctx, id, func(cur *Transaction) error {
		switch {
		case cur.Status != TransactionAwaitingRedirect || cur.ResponseCodeHash == "" ||
			subtle.ConstantTimeCompare([]byte(cur.ResponseCodeHash), []byte(codeHash)) != 1:
			return ErrTransactionUnknown
		case !t.now().Before(cur.ExpiresAt):
			return ErrTransactionExpired
		}
		cur.ResponseCodeHash = ""
		if !bindingMatches(cur.BrowserBindingHash, browserBinding) {
			wrongBrowser = true
			cur.Status, cur.Result = TransactionClosed, nil
			cur.LastError = "the wallet's redirect back arrived in a different browser than the one that asked"
			return nil
		}
		cur.Status = TransactionDone
		view = t.release(cur)
		return nil
	})
	switch {
	case err != nil:
		return TransactionView{}, err
	case wrongBrowser:
		return TransactionView{}, ErrWrongBrowser
	}
	return view, nil
}

// TransactionView is what Lookup reports about a request.
type TransactionView struct {
	ID     string
	Status TransactionStatus
	// Result is set when Status is TransactionDone.
	Result *VerifyResponseResult
	// LastError is why the latest answer was refused, if one was —
	// from anyone who has the request, not necessarily the holder (see
	// Transaction.LastError).
	LastError string
}

// expiry is a new transaction's ExpiresAt and RetainUntil: it stays
// answerable for Lifetime, and a result it completes with is reported
// for one more (Lookup).
func (t *Transactions) expiry() (expiresAt, retainUntil time.Time) {
	expiresAt = t.now().Add(t.cfg.Lifetime)
	return expiresAt, expiresAt.Add(t.cfg.Lifetime)
}

// Lookup reports the request id's progress to whoever asked:
// browserBinding must be the one the request began with.
//
// A completed request's result is reported for one more
// TransactionsConfig.Lifetime past the request's own expiry — enough
// for the browser that asked to collect an answer that arrived just
// before it — and after that as TransactionExpired, without it. Call
// Forget once the result has been used to drop it sooner, or set
// TransactionsConfig.ForgetResultOnRead to drop it as it's read.
func (t *Transactions) Lookup(ctx context.Context, id, browserBinding string) (TransactionView, error) {
	tx, err := t.get(ctx, id)
	if err != nil {
		return TransactionView{}, err
	}
	if !bindingMatches(tx.BrowserBindingHash, browserBinding) {
		return TransactionView{}, ErrWrongBrowser
	}
	status := tx.Status
	switch now := t.now(); {
	case (status == TransactionPending || status == TransactionAwaitingRedirect) && !now.Before(tx.ExpiresAt):
		status = TransactionExpired
	case status == TransactionDone && !now.Before(tx.ExpiresAt.Add(t.cfg.Lifetime)):
		status = TransactionExpired
	}
	if status == TransactionDone && t.cfg.ForgetResultOnRead {
		return t.takeResult(ctx, id)
	}
	return viewOf(tx, status), nil
}

// takeResult is Lookup's view of the completed request id under
// ForgetResultOnRead: its result, dropped from the store as it's read,
// so of concurrent Lookups only one has it.
func (t *Transactions) takeResult(ctx context.Context, id string) (TransactionView, error) {
	var view TransactionView
	err := t.update(ctx, id, func(cur *Transaction) error {
		if cur.Status != TransactionDone {
			view = viewOf(*cur, cur.Status)
			return nil
		}
		view = t.release(cur)
		return nil
	})
	if err != nil {
		return TransactionView{}, err
	}
	return view, nil
}

// release is the view of cur, just completed or about to be read
// completed, with its result; under ForgetResultOnRead, cur's result is
// then dropped, as Forget does.
func (t *Transactions) release(cur *Transaction) TransactionView {
	view := viewOf(*cur, TransactionDone)
	if t.cfg.ForgetResultOnRead {
		forget(cur)
	}
	return view
}

// forget drops cur's result and closes it (Forget).
func forget(cur *Transaction) {
	cur.Status, cur.ResponseCodeHash, cur.Result, cur.LastError = TransactionClosed, "", nil, ""
}

// Close ends the request id without a result — for example the other
// half of a pair offered both cross-device and same-device, once one of
// them completes. A completed or already closed request is left as is.
// It takes no browser binding, and id is public (the last segment of
// the request_uri), so call it only from the Verifier's own logic,
// never for an id a caller supplies.
func (t *Transactions) Close(ctx context.Context, id string) error {
	return t.update(ctx, id, func(cur *Transaction) error {
		if cur.Status == TransactionPending || cur.Status == TransactionAwaitingRedirect {
			cur.Status, cur.ResponseCodeHash, cur.Result = TransactionClosed, "", nil
		}
		return nil
	})
}

// Forget drops the request id's result — the claims the holder
// disclosed — and closes it, whatever its state: call it once the
// Verifier has taken what it needs from a completed request (Lookup or
// Redeem), so the store no longer holds the claims for the rest of the
// request's life. Lookup then reports TransactionClosed. The request
// itself stays in the store until the store deletes it (see
// TransactionStore): its Request Object is still served until it
// expires, as for any closed request, and a late answer is refused as
// one to a closed request. Like Close, it takes no browser binding:
// call it only from the Verifier's own logic.
func (t *Transactions) Forget(ctx context.Context, id string) error {
	return t.update(ctx, id, func(cur *Transaction) error {
		forget(cur)
		return nil
	})
}

func viewOf(tx Transaction, status TransactionStatus) TransactionView {
	view := TransactionView{ID: tx.ID, Status: status, LastError: tx.LastError}
	if status == TransactionDone {
		view.Result = tx.Result
	}
	return view
}

func (t *Transactions) checkPending(tx Transaction) error {
	switch {
	case tx.Status == TransactionClosed:
		return ErrTransactionClosed
	case tx.Status != TransactionPending:
		return ErrTransactionAnswered
	case !t.now().Before(tx.ExpiresAt):
		return ErrTransactionExpired
	}
	return nil
}

func (t *Transactions) now() time.Time {
	if t.cfg.Verify.Now != nil {
		return t.cfg.Verify.Now()
	}
	return time.Now()
}

// randomToken is a 192-bit random, URL-safe token.
func (t *Transactions) randomToken() (string, error) {
	var b [24]byte
	if _, err := io.ReadFull(t.v.deps.Random, b[:]); err != nil {
		return "", fmt.Errorf("verifier: transactions: random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func bindingMatches(hash []byte, binding string) bool {
	if binding == "" {
		return false
	}
	sum := sha256.Sum256([]byte(binding))
	return subtle.ConstantTimeCompare(hash, sum[:]) == 1
}

// withQuery adds key=value to raw's query.
func withQuery(raw, key, value string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String()
}

func isLoopback(host string) bool { return weborigin.IsLoopback(host) }

// checkVerifies refuses a query the Verify configuration can't verify
// an answer to, so the mistake shows when the request is made, not as
// every answer's LastError: a resolver for each credential format it
// asks for, MaxKeyBindingAge for an SD-JWT VC query, and
// TrustedAuthorities where it declares trusted_authorities.
func (t *Transactions) checkVerifies(query dcql.Query) error {
	for _, cq := range query.Credentials {
		switch {
		case cq.Format == sdjwtvc.CredentialFormat && t.cfg.Verify.IssuerKeys == nil:
			return fmt.Errorf("verifier: transactions: credential query %q asks for %q, and Verify.IssuerKeys isn't set", cq.ID, cq.Format)
		case cq.Format == mdoc.CredentialFormat && t.cfg.Verify.MdocIssuerKeys == nil:
			return fmt.Errorf("verifier: transactions: credential query %q asks for %q, and Verify.MdocIssuerKeys isn't set", cq.ID, cq.Format)
		}
	}
	req := t.cfg.Verify
	req.Query = query
	if err := checkMaxKeyBindingAgeRequired(req); err != nil {
		return fmt.Errorf("verifier: transactions: Verify: %w", err)
	}
	if err := checkTrustedAuthoritiesConfigured(req); err != nil {
		return fmt.Errorf("verifier: transactions: Verify: %w", err)
	}
	return nil
}

// serverFault is a failure of the Verifier's own, such as its store's,
// not of the answer: ResponseHandler reports it as a 500, so the Wallet
// isn't told its answer was refused.
type serverFault struct{ err error }

func (e *serverFault) Error() string { return e.err.Error() }
func (e *serverFault) Unwrap() error { return e.err }

// storeFault is err, a TransactionStore's, as a serverFault unless it's
// one of the outcomes the store reports about the request itself.
func storeFault(err error) error {
	for _, known := range []error{ErrTransactionUnknown, ErrTransactionExpired, ErrTransactionAnswered, ErrTransactionClosed} {
		if errors.Is(err, known) {
			return err
		}
	}
	var fault *serverFault
	if errors.As(err, &fault) {
		return err
	}
	return &serverFault{err}
}

// errorCodeOf is a Wallet's error code fit for a redirect: a plain
// OAuth error code token (lowercase letters and underscores) as it is,
// anything else invalid_request.
func errorCodeOf(code string) string {
	if code == "" || len(code) > 64 {
		return "invalid_request"
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return "invalid_request"
		}
	}
	return code
}

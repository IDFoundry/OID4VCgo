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
	"net"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/idfoundry/oid4vcgo/dcql"
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
	// completing. Only ever reported by Transactions.Lookup; a store
	// never holds it.
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

	// BrowserBindingHash is SHA-256 of the browser binding Begin was
	// given; nil for an unbound request.
	BrowserBindingHash []byte
	SameDevice         bool
	ExpiresAt          time.Time

	Status TransactionStatus

	// ResponseCodeHash is SHA-256 (base64url) of the response_code a
	// same-device answer was given; "" once redeemed, and otherwise.
	ResponseCodeHash string

	// Result is set once the answer verified.
	Result *VerifyResponseResult

	// LastError is why the latest answer was refused, for the
	// Verifier's own display. Never sent to the Wallet. Anyone holding
	// the request's public key can send an answer, so this may carry
	// text derived from one: it's kept short and printable, and a
	// Wallet's own error response is reduced to its error code, but it
	// must still be escaped when displayed.
	LastError string
}

// TransactionStore persists Transactions. Update must be atomic per
// transaction: concurrent Updates of one ID run one after another,
// each seeing the previous one's saved result — that is what lets a
// transaction complete at most once, and a response_code be redeemed
// at most once. Lookups by KeyID and ResponseCodeHash must reflect the
// latest saved Transaction.
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
	// request's request_uri is RequestURIBase + "/" + its ID. REQUIRED.
	RequestURIBase string

	// Lifetime bounds how long a request stays answerable, and how long
	// a same-device response_code stays redeemable. Zero means 10
	// minutes.
	Lifetime time.Duration

	// Verify is the verification every answer gets: its IssuerKeys,
	// MdocIssuerKeys, TrustedAuthorities, MaxKeyBindingAge and Now.
	// Query, Response, ExpectedNonce and ResponseEncryptionKey are set
	// per request, and Origin (the DC API flow) isn't supported yet;
	// leave them zero.
	Verify VerifyResponseRequest

	// Accept, if set, runs after an answer verifies and before the
	// request completes — the Verifier's own checks, such as revocation
	// (statuslist.Checker). An error refuses the answer like a failed
	// verification: recorded as LastError, with the request left open
	// for another answer.
	//
	// Accept runs before the request completes atomically, so when two
	// answers to one request arrive together, both can be accepted and
	// only one completes it. Keep it free of side effects, or tie what
	// it records to the result that completed (TransactionView.Result).
	Accept func(ctx context.Context, id string, result VerifyResponseResult) error

	// RedirectURI is where a same-device answer sends the browser back
	// to, with response_code added to its query (OpenID4VP §8.2).
	// REQUIRED for Begin with sameDevice.
	RedirectURI string
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
// request_uri fetched by GET. Use the lower-level BuildAuthorizationRequest,
// ParseDirectPostJWTResponse and VerifyResponse directly for anything
// else, such as the DC API.
type Transactions struct {
	v     *Verifier
	store TransactionStore
	cfg   TransactionsConfig
}

// NewTransactions builds Transactions for v, keeping state in store.
func NewTransactions(v *Verifier, store TransactionStore, cfg TransactionsConfig) (*Transactions, error) {
	switch {
	case v == nil:
		return nil, errors.New("verifier: transactions: a Verifier is required")
	case store == nil:
		return nil, errors.New("verifier: transactions: a TransactionStore is required")
	}
	if err := checkAbsoluteURL("request_uri_base", cfg.RequestURIBase, v.cfg.Assurance); err != nil {
		return nil, err
	}
	if cfg.RedirectURI != "" {
		if err := checkAbsoluteURL("redirect_uri", cfg.RedirectURI, v.cfg.Assurance); err != nil {
			return nil, err
		}
	}
	if cfg.Lifetime < 0 {
		return nil, errors.New("verifier: transactions: lifetime must not be negative")
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 10 * time.Minute
	}
	if cfg.Verify.Query.Credentials != nil || cfg.Verify.ExpectedNonce != "" || cfg.Verify.ResponseEncryptionKey != nil || cfg.Verify.Origin != "" || cfg.Verify.Response.VPToken != nil {
		return nil, errors.New("verifier: transactions: verify: query, response, expected_nonce, response_encryption_key and origin are set per request; leave them zero")
	}
	if v.cfg.Assurance == AssuranceProduction {
		asserter, ok := store.(StoreAssurance)
		if !ok || !asserter.Capabilities().Durable || !asserter.Capabilities().AtomicUpdate {
			return nil, errors.New("verifier: transactions: the store must implement verifier.StoreAssurance with Durable and AtomicUpdate under AssuranceProduction")
		}
		if err := checkProductionKeySources(cfg.Verify); err != nil {
			return nil, fmt.Errorf("verifier: transactions: %w", err)
		}
	}
	return &Transactions{v: v, store: store, cfg: cfg}, nil
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

// Begin creates a presentation request for query.
//
// browserBinding ties the request's result to whoever asked: an
// unguessable secret the caller keeps — a cookie on the browser that
// asked, or a value held server-side when no browser is involved — and
// passes back to Lookup and Redeem. Only its hash is stored. It is
// required: the request's ID is public, as the last segment of the
// request_uri in its link or QR code, so the binding is what keeps the
// result from anyone who saw that. A same-device request (sameDevice)
// also needs TransactionsConfig.RedirectURI, where its answer sends the
// browser back with a response_code.
func (t *Transactions) Begin(ctx context.Context, query dcql.Query, browserBinding string, sameDevice bool) (Begun, error) {
	if browserBinding == "" {
		return Begun{}, errors.New("verifier: transactions: a browser binding is required")
	}
	if sameDevice && t.cfg.RedirectURI == "" {
		return Begun{}, errors.New("verifier: transactions: a same-device request needs TransactionsConfig.RedirectURI")
	}
	id, err := t.randomToken()
	if err != nil {
		return Begun{}, err
	}
	state, err := t.randomToken()
	if err != nil {
		return Begun{}, err
	}
	built, err := t.v.BuildAuthorizationRequest(BuildAuthorizationRequestRequest{Query: query, State: state})
	if err != nil {
		return Begun{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	tx := Transaction{
		ID: id, KeyID: built.ResponseEncryptionKeyID, State: state, Nonce: built.Nonce, Query: query,
		ResponseDecryptionKey: built.ResponseDecryptionKey, RequestObject: built.RequestObject,
		SameDevice: sameDevice, ExpiresAt: t.now().Add(t.cfg.Lifetime), Status: TransactionPending,
	}
	sum := sha256.Sum256([]byte(browserBinding))
	tx.BrowserBindingHash = sum[:]
	if err := t.store.Create(ctx, tx); err != nil {
		return Begun{}, fmt.Errorf("verifier: transactions: store: %w", err)
	}
	link := "openid4vp://?" + url.Values{
		"client_id": {t.v.ClientID()}, "request_uri": {t.cfg.RequestURIBase + "/" + id},
	}.Encode()
	return Begun{ID: id, Link: link}, nil
}

// RequestObject returns the signed Request Object to serve at the
// request_uri of the request id, while it's still waiting for an
// answer.
func (t *Transactions) RequestObject(ctx context.Context, id string) (string, error) {
	tx, err := t.store.Get(ctx, id)
	if err != nil {
		return "", err
	}
	if err := t.checkPending(tx); err != nil {
		return "", err
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
// request's public Request Object and anyone could send one. One whose
// state doesn't match is refused like any other answer.
func (t *Transactions) HandleResponse(ctx context.Context, responseJWE string) (Answered, error) {
	kid, err := ResponseKeyID(responseJWE)
	if err != nil {
		return Answered{}, err
	}
	id, err := t.store.IDByKeyID(ctx, kid)
	if err != nil {
		return Answered{}, err
	}
	tx, err := t.store.Get(ctx, id)
	if err != nil {
		return Answered{}, err
	}
	if err := t.checkPending(tx); err != nil {
		return Answered{}, err
	}
	result, err := t.verify(ctx, tx, responseJWE)
	if err != nil {
		t.recordFailure(ctx, id, err)
		return Answered{}, err
	}

	var code string
	if tx.SameDevice {
		if code, err = t.randomToken(); err != nil {
			return Answered{}, err
		}
	}
	err = t.store.Update(ctx, id, func(cur *Transaction) error {
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
		return Answered{}, err
	}
	answered := Answered{ID: id}
	if tx.SameDevice {
		answered.RedirectURI = withQuery(t.cfg.RedirectURI, "response_code", code)
	}
	return answered, nil
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
			return VerifyResponseResult{}, newError("the error response's state doesn't match the request", nil)
		}
		return VerifyResponseResult{}, err
	case err != nil:
		return VerifyResponseResult{}, err
	}
	if subtle.ConstantTimeCompare([]byte(parsed.State), []byte(tx.State)) != 1 {
		return VerifyResponseResult{}, newError("the response's state doesn't match the request", nil)
	}
	req := t.cfg.Verify
	req.Query, req.Response, req.ExpectedNonce, req.ResponseEncryptionKey = tx.Query, parsed, tx.Nonce, tx.ResponseDecryptionKey
	result, err := t.v.VerifyResponse(ctx, req)
	if err != nil {
		return VerifyResponseResult{}, err
	}
	if t.cfg.Accept != nil {
		if err := t.cfg.Accept(ctx, tx.ID, result); err != nil {
			return VerifyResponseResult{}, err
		}
	}
	return result, nil
}

// recordFailure notes why an answer was refused, if the request is
// still pending. Best effort: a store error here doesn't change the
// answer's own error.
func (t *Transactions) recordFailure(ctx context.Context, id string, cause error) {
	_ = t.store.Update(ctx, id, func(cur *Transaction) error {
		if cur.Status != TransactionPending {
			return ErrTransactionAnswered
		}
		cur.LastError = failureText(cause)
		return nil
	})
}

// maxFailureText bounds LastError.
const maxFailureText = 256

// failureText is what LastError records for cause. A Wallet's error
// response — which anyone holding the request's public key can send —
// is reduced to its error code when that's a plain token; otherwise
// the text is cut to maxFailureText and anything unprintable replaced.
func failureText(cause error) string {
	var walletErr *ResponseError
	if errors.As(cause, &walletErr) {
		if isErrorCode(walletErr.Code) {
			return "the wallet returned an error: " + walletErr.Code
		}
		return "the wallet returned an error"
	}
	var b strings.Builder
	for _, r := range cause.Error() {
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
	err = t.store.Update(ctx, id, func(cur *Transaction) error {
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
		view = viewOf(*cur, cur.Status)
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
	// LastError is why the latest answer was refused, if one was.
	LastError string
}

// Lookup reports the request id's progress to whoever asked:
// browserBinding must be the one the request began with.
func (t *Transactions) Lookup(ctx context.Context, id, browserBinding string) (TransactionView, error) {
	tx, err := t.store.Get(ctx, id)
	if err != nil {
		return TransactionView{}, err
	}
	if !bindingMatches(tx.BrowserBindingHash, browserBinding) {
		return TransactionView{}, ErrWrongBrowser
	}
	status := tx.Status
	if (status == TransactionPending || status == TransactionAwaitingRedirect) && !t.now().Before(tx.ExpiresAt) {
		status = TransactionExpired
	}
	return viewOf(tx, status), nil
}

// Close ends the request id without a result — for example the other
// half of a pair offered both cross-device and same-device, once one of
// them completes. A completed or already closed request is left as is.
// It takes no browser binding, and id is public (the last segment of
// the request_uri), so call it only from the Verifier's own logic,
// never for an id a caller supplies.
func (t *Transactions) Close(ctx context.Context, id string) error {
	return t.store.Update(ctx, id, func(cur *Transaction) error {
		if cur.Status == TransactionPending || cur.Status == TransactionAwaitingRedirect {
			cur.Status, cur.ResponseCodeHash, cur.Result = TransactionClosed, "", nil
		}
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

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

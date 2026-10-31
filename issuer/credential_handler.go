package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	fapi "github.com/idfoundry/fapigo"
	"io"
	"net/http"
	"net/url"
	"sync"

	"github.com/idfoundry/oid4vcgo"
)

// headerContentType is the Content-Type header's name.
const headerContentType = "Content-Type"

// AccessTokenVerifier checks the access token presented to a protected
// Credential Issuer endpoint. This package doesn't verify access tokens
// itself (see resource_verifier.go); issuer/fapiresource adapts a
// fapigo/resource.Verifier to this interface.
type AccessTokenVerifier interface {
	// Verify checks r's access token, and its sender constraint (a DPoP
	// proof or client certificate), for a request to endpoint — the
	// endpoint's absolute URL, which a DPoP proof's htu is compared
	// with: a server-side r.URL has no scheme or host.
	Verify(r *http.Request, endpoint *url.URL) (Grant, error)

	// WriteError writes the response for an error Verify returned: 401
	// with WWW-Authenticate, a DPoP-Nonce challenge, and so on.
	WriteError(w http.ResponseWriter, err error)
}

// Grant is what a verified access token allows.
//
// Subject and Authorized.Subject must be equal: Prepare looks up what
// to issue by the first, while deferred transactions and
// notification_ids are bound to the second, so a Grant whose two differ
// (or that sets only one) would issue one holder's Credentials under
// another's, or no, binding. The handlers answer such a Grant with a
// 500, as an AccessTokenVerifier misconfiguration.
type Grant struct {
	// Subject is who the token was issued for — for a token minted by
	// ExchangePreAuthorizedCode, the redeemed PreAuthorizedCodeRecord's
	// Subject. Look up what to issue by it.
	Subject string

	// Authorized is checked against the Credential Request by
	// RequestCredential. Its Subject must be Subject.
	Authorized AuthorizedRequest

	// DPoPNonce, if set, is sent as the response's DPoP-Nonce header,
	// so the Wallet's next request already carries a fresh nonce.
	DPoPNonce string
}

// CredentialHandlerConfig configures CredentialHandler.
type CredentialHandlerConfig struct {
	// URL is the Credential Endpoint's absolute URL, as published in
	// the Issuer's metadata. Leave it nil to use
	// Config.Endpoints.Credential; set, it must equal it, the URL a
	// Wallet's DPoP proofs name (htu).
	URL *url.URL

	// Tokens checks each request's access token. REQUIRED.
	Tokens AccessTokenVerifier

	// Prepare decides what to issue for grant: it sets req's
	// SDJWTClaims and MdocClaims, and PerCredential when each
	// credential needs its own value (a status list index, for
	// instance) — or sets req.Defer to defer issuance, which the
	// handler answers with 202 and a transaction_id (§8.3). Those are
	// the only fields of req read after it; req.ResolvedConfigurationID
	// names the configuration to build the claims of. Returning a *Error — typically
	// NewError(ErrorCredentialRequestDenied, ...) — refuses the request
	// with that error; any other error is a 500 whose detail the Wallet
	// never sees. REQUIRED.
	//
	// Look up what to issue by grant.Subject. req.CredentialIdentifier,
	// when set, has been found among the access token's
	// authorization_details, which only says the Authorization Server
	// granted it: if it names a dataset beyond its configuration, look
	// that up among the identifiers minted for grant.Subject, never by
	// the identifier alone. With fapigo/server, register
	// oid4vci.AuthorizationDetailRARDefinition, which refuses a Wallet's
	// own credential_identifiers when it starts a grant and lets its
	// token requests only keep or drop the grant's, so each is one the
	// Authorization Server minted for this grant.
	//
	// The handler calls Prepare only for a request the access token
	// authorizes, once its proofs are verified and its c_nonce
	// consumed. The request can still fail after it — issuing fails, or
	// the response can't be encrypted — so Prepare must not do anything
	// done can't undo: reserve, and commit in done(true).
	//
	// done, if not nil, is called exactly once after Prepare succeeds,
	// with whether the Credential Response was sent — the Credentials,
	// or a deferral's transaction_id — so Prepare can release anything
	// it reserved when that fails.
	Prepare func(ctx context.Context, grant Grant, req *CredentialRequest) (done func(issued bool), err error)
}

// CredentialHandler serves the Credential Endpoint (§8). For each POST
// it checks the access token with cfg.Tokens, reads and parses the
// request (ParseCredentialRequest, decrypting it if it arrived
// encrypted), checks it as RequestCredential does, lets cfg.Prepare
// fill in what to issue once its proofs are verified, issues it, and
// sends the Credential Response — encrypted
// when the Wallet asked for that (EncryptResponseBody) — with
// Cache-Control: no-store. Errors are Credential Error Responses
// (WriteError).
func (iss *Issuer) CredentialHandler(cfg CredentialHandlerConfig) (http.Handler, error) {
	var err error
	if cfg.URL, err = endpointURL("credential handler", cfg.URL, iss.cfg.Endpoints.Credential); err != nil {
		return nil, err
	}
	switch {
	case cfg.Tokens == nil:
		return nil, fmt.Errorf("issuer: credential handler: Tokens is required")
	case cfg.Prepare == nil:
		return nil, fmt.Errorf("issuer: credential handler: Prepare is required")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iss.serveCredential(w, r, cfg)
	}), nil
}

func (iss *Issuer) serveCredential(w http.ResponseWriter, r *http.Request, cfg CredentialHandlerConfig) {
	grant, body, ok := authorizePost(w, r, cfg.URL, cfg.Tokens, MaxCredentialRequestBytes, ErrorInvalidCredentialRequest)
	if !ok {
		return
	}
	req, err := iss.ParseCredentialRequest(body, r.Header.Get(headerContentType))
	if err != nil {
		WriteError(w, err)
		return
	}
	var done func(issued bool)
	prepare := func(ctx context.Context, req *CredentialRequest) error {
		d, err := cfg.Prepare(ctx, grant, req)
		if err != nil {
			return fmt.Errorf("issuer: credential handler: prepare: %w", err)
		}
		done = d
		return nil
	}
	status, encoded, contentType, err := iss.credentialResponse(r.Context(), grant, req, prepare)
	issued := false
	if done != nil {
		defer func() { done(issued) }()
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	issued = true
	writeCredentialResponse(w, status, encoded, contentType)
}

// writeCredentialResponse sends a Credential or Deferred Credential
// Response body, uncached.
func writeCredentialResponse(w http.ResponseWriter, status int, encoded []byte, contentType string) {
	w.Header().Set(headerContentType, contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// #nosec G705 -- encoded is a Credential Response this package built
	// (JSON, or a JWE of it), sent as its own Content-Type, not HTML.
	_, _ = w.Write(encoded)
}

// authorizePost checks a request to a protected endpoint: POST only,
// then its access token (passing the grant's next DPoP nonce on), then
// reads its body, at most maxBytes (a longer one is left for the
// parser to refuse). It reports whether to go on; if not, the response
// has been written.
func authorizePost(w http.ResponseWriter, r *http.Request, endpoint *url.URL, tokens AccessTokenVerifier, maxBytes int, unreadable ErrorCode) (Grant, []byte, bool) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return Grant{}, nil, false
	}
	grant, err := tokens.Verify(r, endpoint)
	if err != nil {
		tokens.WriteError(w, err)
		return Grant{}, nil, false
	}
	if grant.Subject != grant.Authorized.Subject {
		// The verifier's own inconsistency, not the Wallet's: a 500
		// that doesn't reveal either subject.
		http.Error(w, "server_error", http.StatusInternalServerError)
		return Grant{}, nil, false
	}
	if grant.DPoPNonce != "" {
		w.Header().Set("DPoP-Nonce", grant.DPoPNonce)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
	if err != nil {
		WriteError(w, NewError(unreadable, "request body is unreadable"))
		return Grant{}, nil, false
	}
	return grant, body, true
}

// ProtectedEndpointConfig configures NotificationEndpointHandler, and
// DeferredCredentialHandler through DeferredCredentialHandlerConfig.
type ProtectedEndpointConfig struct {
	// URL is the endpoint's absolute URL, as published in the Issuer's
	// metadata. Leave it nil to use the one in Config.Endpoints
	// (DeferredCredential or Notification); set, it must equal it, the
	// URL a Wallet's DPoP proofs name (htu).
	URL *url.URL

	// Tokens checks each request's access token. REQUIRED.
	Tokens AccessTokenVerifier
}

// validate checks cfg for handler, defaulting its URL to published.
func (cfg *ProtectedEndpointConfig) validate(handler string, published fapi.URL) error {
	var err error
	if cfg.URL, err = endpointURL(handler, cfg.URL, published); err != nil {
		return err
	}
	if cfg.Tokens == nil {
		return fmt.Errorf("issuer: %s: Tokens is required", handler)
	}
	return nil
}

// endpointURL is a handler's URL: given, which must equal published
// when both are set, or published when given is nil.
func endpointURL(handler string, given *url.URL, published fapi.URL) (*url.URL, error) {
	switch {
	case given == nil && published.IsZero():
		return nil, fmt.Errorf("issuer: %s: URL is required: Config.Endpoints doesn't publish this endpoint", handler)
	case given == nil:
		u := published.URL()
		return &u, nil
	case !given.IsAbs():
		return nil, fmt.Errorf("issuer: %s: URL must be the endpoint's absolute URL", handler)
	case !published.IsZero() && given.String() != published.String():
		return nil, fmt.Errorf("issuer: %s: URL %s isn't the published endpoint %s, which Wallets' DPoP proofs name", handler, given, published)
	}
	return given, nil
}

// DeferredCredentialHandlerConfig configures DeferredCredentialHandler.
type DeferredCredentialHandlerConfig struct {
	ProtectedEndpointConfig

	// Resolve, if set, is called when a poll finds its transaction
	// still pending, before it's answered — for a deployment that
	// decides when the Wallet asks rather than in a background process.
	// It may call IssueDeferredCredential or DenyDeferredCredential for
	// tx, or do nothing to leave it pending. It's called only when the
	// polling grant's client and Subject are the ones the transaction
	// was created for, so grant.Subject is the transaction's own, and
	// the grant still covers the transaction's credential configuration
	// (§9), so a poll the endpoint will refuse never makes the
	// deployment issue. Its error is a 500 whose detail the Wallet
	// never sees, except ErrDeferredTransactionResolved: a concurrent
	// poll resolved tx first, and this poll is answered from the store.
	//
	// The handler runs Resolve once at a time per transaction: a poll
	// arriving while another's Resolve for the same transaction is
	// running skips it and is answered from the store (still pending,
	// usually). That holds within one handler only: behind several
	// handlers or instances, polls can still run Resolve concurrently,
	// and only the first IssueDeferredCredential or
	// DenyDeferredCredential to finish takes effect (see
	// IssueDeferredCredential), so Resolve must release whatever a
	// losing call reserved.
	Resolve func(ctx context.Context, grant Grant, transactionID string, tx DeferredTransactionRecord) error
}

// DeferredCredentialHandler serves the Deferred Credential Endpoint
// (§9). For each POST it checks the access token with cfg.Tokens,
// reads and parses the request (ParseDeferredCredentialRequest,
// decrypting it if it arrived encrypted), lets cfg.Resolve decide a
// still-pending transaction, and answers with
// RequestDeferredCredential's result: 200 with the Credentials, or 202
// with transaction_id and interval while the transaction is pending —
// encrypted when the Wallet asked for that, and with Cache-Control:
// no-store. Errors are Credential Error Responses (WriteError).
func (iss *Issuer) DeferredCredentialHandler(cfg DeferredCredentialHandlerConfig) (http.Handler, error) {
	if err := cfg.validate("deferred credential handler", iss.cfg.Endpoints.DeferredCredential); err != nil {
		return nil, err
	}
	var resolving sync.Map // transaction_ids whose Resolve is running
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grant, body, ok := authorizePost(w, r, cfg.URL, cfg.Tokens, MaxCredentialRequestBytes, ErrorInvalidCredentialRequest)
		if !ok {
			return
		}
		req, err := iss.ParseDeferredCredentialRequest(body, r.Header.Get(headerContentType))
		if err == nil {
			// Checked before Resolve, so a malformed poll can't make
			// the deployment issue.
			err = iss.checkDeferredCredentialRequest(grant.Authorized, req)
		}
		if err != nil {
			WriteError(w, err)
			return
		}
		if cfg.Resolve != nil {
			if err := iss.resolvePending(r.Context(), &resolving, grant, req.TransactionID, cfg.Resolve); err != nil {
				writePrepareError(w, err)
				return
			}
		}
		iss.writeDeferredResult(w, r, grant, req)
	}), nil
}

// writeDeferredResult answers a checked Deferred Credential Request
// with RequestDeferredCredential's result, encrypted when the Wallet
// asked for that.
func (iss *Issuer) writeDeferredResult(w http.ResponseWriter, r *http.Request, grant Grant, req DeferredCredentialRequest) {
	result, err := iss.RequestDeferredCredential(r.Context(), grant.Authorized, req)
	if err != nil {
		WriteError(w, err)
		return
	}
	status, plain := result.wire()
	resultJSON, err := json.Marshal(plain)
	if err != nil {
		WriteError(w, fmt.Errorf("issuer: deferred credential handler: %w", err))
		return
	}
	encoded, contentType, err := iss.EncryptResponseBody(resultJSON, req.ResponseEncryption)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeCredentialResponse(w, status, encoded, contentType)
}

// NotificationEndpointHandler serves the Notification Endpoint (§11).
// For each POST it checks the access token with cfg.Tokens, parses the
// request (ParseNotificationRequest), and passes it to
// RequestNotification, which hands the event to
// Dependencies.NotificationHandler. It answers 204 No Content (§11.2);
// errors are Notification Error Responses (WriteError).
func (iss *Issuer) NotificationEndpointHandler(cfg ProtectedEndpointConfig) (http.Handler, error) {
	if err := cfg.validate("notification endpoint handler", iss.cfg.Endpoints.Notification); err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grant, body, ok := authorizePost(w, r, cfg.URL, cfg.Tokens, MaxNotificationRequestBytes, ErrorInvalidNotificationRequest)
		if !ok {
			return
		}
		req, err := ParseNotificationRequest(body)
		if err != nil {
			WriteError(w, err)
			return
		}
		if err := iss.RequestNotification(r.Context(), grant.Authorized, req); err != nil {
			WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}), nil
}

// credentialResponse issues (or defers) req, with prepare filling in
// what to issue once it's checked, and encodes the Credential Response,
// encrypted when req asks for that, with its HTTP status.
func (iss *Issuer) credentialResponse(ctx context.Context, grant Grant, req CredentialRequest, prepare preparer) (int, []byte, string, error) {
	result, err := iss.requestCredentialAudited(ctx, grant.Authorized, req, prepare)
	if err != nil {
		return 0, nil, "", err
	}
	encoded, contentType, err := iss.encodeCredentialResponse(result, req.ResponseEncryption)
	if err != nil && result.TransactionID != "" {
		// The Wallet never learns this transaction_id, so nothing can
		// collect what the deployment would issue for it.
		iss.abandonDeferral(ctx, result.TransactionID)
	}
	return credentialResponseStatus(result), encoded, contentType, err
}

func (iss *Issuer) encodeCredentialResponse(result oid4vci.CredentialResponse, enc *ResponseEncryptionRequest) ([]byte, string, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, "", fmt.Errorf("issuer: credential handler: %w", err)
	}
	return iss.EncryptResponseBody(resultJSON, enc)
}

// writePrepareError writes a Prepare error: a *Error as it is, anything
// else as a 500 that doesn't reveal it.
func writePrepareError(w http.ResponseWriter, err error) {
	var issErr *Error
	if errors.As(err, &issErr) {
		issErr.WriteJSON(w)
		return
	}
	http.Error(w, "server_error", http.StatusInternalServerError)
}

// resolvePending calls resolve for transactionID when it's pending,
// belongs to grant's client and subject, and grant covers its
// credential configuration. Anything else — unknown, resolved,
// expired, someone else's, not granted — is left for
// RequestDeferredCredential to answer, as is a transaction a concurrent
// poll resolved first, or is resolving: resolving holds the
// transaction_ids whose resolve is running.
func (iss *Issuer) resolvePending(ctx context.Context, resolving *sync.Map, grant Grant, transactionID string,
	resolve func(context.Context, Grant, string, DeferredTransactionRecord) error) error {
	if transactionID == "" || iss.deps.DeferredTransactions == nil {
		return nil
	}
	record, err := iss.pendingDeferredTransaction(ctx, transactionID)
	if err != nil || !iss.deferredAuthorized(record, grant.Authorized) {
		return nil
	}
	if _, running := resolving.LoadOrStore(transactionID, struct{}{}); running {
		return nil
	}
	defer resolving.Delete(transactionID)
	if err := resolve(ctx, grant, transactionID, record); err != nil && !errors.Is(err, ErrDeferredTransactionResolved) {
		return err
	}
	return nil
}

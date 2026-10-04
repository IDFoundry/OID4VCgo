package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

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
type Grant struct {
	// Subject is who the token was issued for — for a token minted by
	// ExchangePreAuthorizedCode, the redeemed PreAuthorizedCodeRecord's
	// Subject. Look up what to issue by it.
	Subject string

	// Authorized is checked against the Credential Request by
	// RequestCredential.
	Authorized AuthorizedRequest

	// DPoPNonce, if set, is sent as the response's DPoP-Nonce header,
	// so the Wallet's next request already carries a fresh nonce.
	DPoPNonce string
}

// CredentialHandlerConfig configures CredentialHandler.
type CredentialHandlerConfig struct {
	// URL is the Credential Endpoint's absolute URL, as published in
	// the Issuer's metadata. REQUIRED.
	URL *url.URL

	// Tokens checks each request's access token. REQUIRED.
	Tokens AccessTokenVerifier

	// Prepare decides what to issue for grant: it sets req's
	// SDJWTClaims and MdocClaims, and PerCredential when each
	// credential needs its own value (a status list index, for
	// instance) — or sets req.Defer to defer issuance, which the
	// handler answers with 202 and a transaction_id (§8.3). Returning a *Error — typically
	// NewError(ErrorCredentialRequestDenied, ...) — refuses the request
	// with that error; any other error is a 500 whose detail the Wallet
	// never sees. REQUIRED.
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
// encrypted), lets cfg.Prepare fill in what to issue, issues it
// (RequestCredential), and sends the Credential Response — encrypted
// when the Wallet asked for that (EncryptResponseBody) — with
// Cache-Control: no-store. Errors are Credential Error Responses
// (WriteError).
func (iss *Issuer) CredentialHandler(cfg CredentialHandlerConfig) (http.Handler, error) {
	switch {
	case cfg.URL == nil || !cfg.URL.IsAbs():
		return nil, fmt.Errorf("issuer: credential handler: URL must be the endpoint's absolute URL")
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
	done, err := cfg.Prepare(r.Context(), grant, &req)
	if err != nil {
		writePrepareError(w, err)
		return
	}
	issued := false
	if done != nil {
		defer func() { done(issued) }()
	}
	status, encoded, contentType, err := iss.credentialResponse(r.Context(), grant, req)
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
	// metadata. REQUIRED.
	URL *url.URL

	// Tokens checks each request's access token. REQUIRED.
	Tokens AccessTokenVerifier
}

func (cfg ProtectedEndpointConfig) validate(handler string) error {
	switch {
	case cfg.URL == nil || !cfg.URL.IsAbs():
		return fmt.Errorf("issuer: %s: URL must be the endpoint's absolute URL", handler)
	case cfg.Tokens == nil:
		return fmt.Errorf("issuer: %s: Tokens is required", handler)
	}
	return nil
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
	// was created for, so grant.Subject is the transaction's own. Its
	// error is a 500 whose detail the Wallet never sees, except
	// ErrDeferredTransactionResolved: a concurrent poll resolved tx
	// first, and this poll is answered from the store.
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
	if err := cfg.validate("deferred credential handler"); err != nil {
		return nil, err
	}
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
			if err := iss.resolvePending(r.Context(), grant, req.TransactionID, cfg.Resolve); err != nil {
				writePrepareError(w, err)
				return
			}
		}
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
	}), nil
}

// NotificationEndpointHandler serves the Notification Endpoint (§11).
// For each POST it checks the access token with cfg.Tokens, parses the
// request (ParseNotificationRequest), and passes it to
// RequestNotification, which hands the event to
// Dependencies.NotificationHandler. It answers 204 No Content (§11.2);
// errors are Notification Error Responses (WriteError).
func (iss *Issuer) NotificationEndpointHandler(cfg ProtectedEndpointConfig) (http.Handler, error) {
	if err := cfg.validate("notification endpoint handler"); err != nil {
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

// credentialResponse issues (or defers) req and encodes the Credential
// Response, encrypted when req asks for that, with its HTTP status.
func (iss *Issuer) credentialResponse(ctx context.Context, grant Grant, req CredentialRequest) (int, []byte, string, error) {
	result, err := iss.RequestCredential(ctx, grant.Authorized, req)
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

// resolvePending calls resolve for transactionID when it's pending and
// belongs to grant's client and subject. Anything else — unknown,
// resolved, expired, someone else's — is left for
// RequestDeferredCredential to answer, as is a transaction a concurrent
// poll resolved first.
func (iss *Issuer) resolvePending(ctx context.Context, grant Grant, transactionID string,
	resolve func(context.Context, Grant, string, DeferredTransactionRecord) error) error {
	if transactionID == "" || iss.deps.DeferredTransactions == nil {
		return nil
	}
	record, err := iss.pendingDeferredTransaction(ctx, transactionID)
	if err != nil || !deferredOwner(record, grant.Authorized) {
		return nil
	}
	if err := resolve(ctx, grant, transactionID, record); err != nil && !errors.Is(err, ErrDeferredTransactionResolved) {
		return err
	}
	return nil
}

package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

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
	// instance). Returning a *Error — typically
	// NewError(ErrorCredentialRequestDenied, ...) — refuses the request
	// with that error; any other error is a 500 whose detail the Wallet
	// never sees. REQUIRED.
	//
	// done, if not nil, is called exactly once after Prepare succeeds,
	// with whether the Credential Response was issued, so Prepare can
	// release anything it reserved when issuing fails later.
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
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	grant, err := cfg.Tokens.Verify(r, cfg.URL)
	if err != nil {
		cfg.Tokens.WriteError(w, err)
		return
	}
	if grant.DPoPNonce != "" {
		w.Header().Set("DPoP-Nonce", grant.DPoPNonce)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxCredentialRequestBytes+1))
	if err != nil {
		WriteError(w, NewError(ErrorInvalidCredentialRequest, "credential request is unreadable"))
		return
	}
	req, err := iss.ParseCredentialRequest(body, r.Header.Get("Content-Type"))
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
	encoded, contentType, err := iss.credentialResponse(r.Context(), grant, req)
	if err != nil {
		WriteError(w, err)
		return
	}
	issued = true
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// #nosec G705 -- encoded is the Credential Response RequestCredential
	// built (JSON, or a JWE of it), sent as its own Content-Type, not HTML.
	_, _ = w.Write(encoded)
}

// credentialResponse issues req and encodes the Credential Response,
// encrypted when req asks for that.
func (iss *Issuer) credentialResponse(ctx context.Context, grant Grant, req CredentialRequest) ([]byte, string, error) {
	result, err := iss.RequestCredential(ctx, grant.Authorized, req)
	if err != nil {
		return nil, "", err
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, "", fmt.Errorf("issuer: credential handler: %w", err)
	}
	return iss.EncryptResponseBody(resultJSON, req.ResponseEncryption)
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

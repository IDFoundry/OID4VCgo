package wallet

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
)

// PreAuthorizedCodeGrantType is the Token Request's own "grant_type"
// value for the Pre-Authorized Code Flow (§3.5, §6.1).
const PreAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// maxTokenResponseBytes bounds how much of a Token Response body
// RequestPreAuthorizedCodeToken reads — this call goes straight
// through Dependencies.HTTP, not the hardened fapihttp.Client
// Config.Fetch otherwise wraps it in (that type has no way to attach
// this request's own DPoP header), so this package applies its own
// bound instead of relying on one further down the stack.
const maxTokenResponseBytes = 1 << 16

// PreAuthorizedCodeTokenRequest is the input to
// RequestPreAuthorizedCodeToken — the Pre-Authorized Code Flow's own
// Token Request (§6.1). Client authentication is OPTIONAL in OID4VCI
// (§6.1), but HAIP 1.0 §4.4.1 requires it: set ClientAttestation to
// authenticate with the Wallet Attestation, as fapigo/client does for
// the Authorization Code Flow.
type PreAuthorizedCodeTokenRequest struct {
	// PreAuthorizedCode is REQUIRED — a resolved Credential Offer's own
	// Grants.PreAuthorizedCode.PreAuthorizedCode.
	PreAuthorizedCode string

	// TxCode is REQUIRED whenever the Credential Offer's own
	// Grants.PreAuthorizedCode.TxCode was present, even if empty
	// (§4.1.1/§6.1's own MUST) — the End-User's own Transaction Code
	// value itself, not the TxCode object. Left "" when the offer
	// carried no TxCode object at all.
	TxCode string

	// DPoPKey signs this request's own DPoP proof (RFC 9449 §4) —
	// REQUIRED, since HAIP 1.0 §4 makes DPoP mandatory. The resulting
	// access token is bound to this key's public key (§4.3's own
	// cnf.jkt): every later request presenting it — RequestCredential,
	// RequestDeferredCredential, RequestNotification, via whatever
	// ProtectedResourceClient the caller supplies — must be signed by
	// this same key, or the Credential Issuer rejects it. This package
	// doesn't build that ProtectedResourceClient itself; see the
	// package doc comment for why.
	DPoPKey crypto.Signer

	// ClientAttestation, if set, authenticates this Wallet with its
	// Wallet Attestation and a fresh Client Attestation PoP (OAuth 2.0
	// Attestation-Based Client Authentication), as HAIP 1.0 §4.4.1
	// requires at the Token Endpoint. fapigo/client's *client.Client
	// is one, configured for storage.ClientAuthMethodAttestation, so the
	// PoP is built exactly as for its own PAR and token requests.
	ClientAttestation ClientAttestationSource
}

// ClientAttestationSource supplies the OAuth-Client-Attestation and a
// fresh OAuth-Client-Attestation-PoP header value for one request to the
// Authorization Server; RequestPreAuthorizedCodeToken calls it for each
// attempt. fapigo/client's (*client.Client).ClientAttestationHeaders
// implements it.
type ClientAttestationSource interface {
	ClientAttestationHeaders(ctx context.Context) (attestation, pop string, err error)
}

// PreAuthorizedCodeTokenResult is returned by a successful
// RequestPreAuthorizedCodeToken.
type PreAuthorizedCodeTokenResult struct {
	// AccessToken is bound to PreAuthorizedCodeTokenRequest.DPoPKey's
	// own public key — see that field's own doc comment.
	AccessToken fapi.Secret

	// TokenType is whatever the Token Response carried — "DPoP" per RFC
	// 9449 §5 for a properly sender-constrained token.
	TokenType string

	// ExpiresIn is set only when the Token Response actually carried
	// expires_in (RFC 6749 §5.1 marks it RECOMMENDED, not REQUIRED).
	ExpiresIn    time.Duration
	HasExpiresIn bool

	// AuthorizationDetails is whatever the Token Response's own
	// "authorization_details" parameter carried (RFC 9396 §6.2), empty
	// if absent — an Authorization Server that supports this optional
	// mechanism (§6.2's own "MAY do so") echoes back one entry per
	// requested Credential Configuration, each with its own
	// CredentialIdentifiers. Pass one of those values as
	// CredentialRequest.CredentialIdentifier in a later
	// RequestCredential call instead of CredentialConfigurationID
	// (§8.2).
	AuthorizationDetails []oid4vci.AuthorizationDetail

	// RefreshToken is the Token Response's refresh_token, when the
	// Authorization Server issued one, to refresh the credentials later
	// (§13.5); empty otherwise.
	RefreshToken fapi.Secret
}

// tokenResponseBody is the Token Response's own wire shape this
// package reads — RFC 6749 §5.1 plus RFC 9449 §5's token_type value
// RFC 9396 §6.2's own authorization_details, and the refresh_token;
// every other optional member (§6.2) is still ignored.
type tokenResponseBody struct {
	AccessToken          string                        `json:"access_token"`
	TokenType            string                        `json:"token_type"`
	ExpiresIn            *int64                        `json:"expires_in"`
	AuthorizationDetails []oid4vci.AuthorizationDetail `json:"authorization_details,omitempty"`
	RefreshToken         string                        `json:"refresh_token,omitempty"`
}

// RequestPreAuthorizedCodeToken implements the Pre-Authorized Code
// Flow's own Token Request/Response (§6.1/§6.2). Send it only to the
// token endpoint of the Authorization Server PlanPreAuthorizedCode
// chose: the code and PIN go to endpoint, and a server the issuer's
// metadata doesn't list could redeem them itself. It builds a DPoP
// proof for this one request (see GenerateDPoPProof's own doc comment
// for why this package builds it directly here, rather than through
// fapigo/client), POSTs a form-encoded Token Request to endpoint via
// Dependencies.HTTP, and retries exactly once if the Authorization
// Server challenges with a fresh DPoP nonce (RFC 9449 §8's own
// Authorization-Server-side nonce-challenge: HTTP 400, a JSON body
// whose "error" member is use_dpop_nonce, and a DPoP-Nonce response
// header — see dpopNonceChallenge's own doc comment for why this is
// §8, not §9's WWW-Authenticate-header challenge, which only a
// resource server sends) — the same one-retry behavior
// (*client.ResourceClient).Do applies for its own resource requests.
// A non-200 response (after that retry, if any) is returned as a
// *Error.
func (w *Wallet) RequestPreAuthorizedCodeToken(
	ctx context.Context, endpoint fapi.URL, req PreAuthorizedCodeTokenRequest,
) (PreAuthorizedCodeTokenResult, error) {
	if err := w.checkPreAuthorizedCodeTokenRequest(req); err != nil {
		return PreAuthorizedCodeTokenResult{}, err
	}
	body, err := w.postToken(ctx, endpoint, preAuthorizedCodeTokenForm(req), req.DPoPKey, req.ClientAttestation, "request pre-authorized code token")
	if err != nil {
		return PreAuthorizedCodeTokenResult{}, err
	}
	return decodeTokenResponse(body)
}

// postToken POSTs form to the token endpoint, with a DPoP proof when
// dpopKey is set and the attestation headers when attestation is,
// retrying once on a DPoP nonce challenge, and returns the 200
// response's body. op names the call in errors.
func (w *Wallet) postToken(
	ctx context.Context, endpoint fapi.URL, form []byte, dpopKey crypto.Signer, attestation ClientAttestationSource, op string,
) ([]byte, error) {
	target := endpoint.URL()
	htu := target
	htu.RawQuery, htu.Fragment = "", ""
	post := tokenPost{target: target.String(), htu: htu.String(), body: form, dpopKey: dpopKey, attestation: attestation, op: op}

	// At most two attempts: the second only after a DPoP nonce
	// challenge to the first.
	var nonce string
	for attempt := 0; ; attempt++ {
		res, err := w.postTokenOnce(ctx, post, nonce)
		if err != nil {
			return nil, err
		}
		if res.status == http.StatusOK {
			return res.body, nil
		}
		if attempt == 0 && dpopKey != nil {
			if nonce = dpopNonceChallenge(res.status, res.header, res.body); nonce != "" {
				continue
			}
		}
		return nil, parseError(res.status, res.body)
	}
}

func (w *Wallet) checkPreAuthorizedCodeTokenRequest(req PreAuthorizedCodeTokenRequest) error {
	switch {
	case req.PreAuthorizedCode == "":
		return fmt.Errorf("wallet: request pre-authorized code token: pre-authorized_code is required")
	case req.DPoPKey == nil:
		return fmt.Errorf("wallet: request pre-authorized code token: dpop_key is required")
	case w.deps.Random == nil:
		return fmt.Errorf("wallet: request pre-authorized code token: dependencies.random is required")
	}
	return nil
}

// preAuthorizedCodeTokenForm is the Token Request's form body (§6.1).
func preAuthorizedCodeTokenForm(req PreAuthorizedCodeTokenRequest) []byte {
	form := url.Values{}
	form.Set("grant_type", PreAuthorizedCodeGrantType)
	form.Set("pre-authorized_code", req.PreAuthorizedCode)
	if req.TxCode != "" {
		form.Set("tx_code", req.TxCode)
	}
	return []byte(form.Encode())
}

// tokenHTTPResponse is one Token Request's answer.
type tokenHTTPResponse struct {
	status int
	header http.Header
	body   []byte
}

// tokenPost is a Token Request, the same on each attempt: body POSTed
// to target, with a DPoP proof for htu when dpopKey is set and the
// attestation headers when attestation is. op names the call in errors.
type tokenPost struct {
	target, htu string
	body        []byte
	dpopKey     crypto.Signer
	attestation ClientAttestationSource
	op          string
}

// postTokenOnce sends p once, with a fresh DPoP proof (with nonce, if
// set) and a fresh attestation PoP: both are single-use.
func (w *Wallet) postTokenOnce(ctx context.Context, p tokenPost, nonce string) (tokenHTTPResponse, error) {
	op := p.op
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.target, bytes.NewReader(p.body))
	if err != nil {
		return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: build request: %w", op, err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.dpopKey != nil {
		proof, err := w.GenerateDPoPProof(p.dpopKey, http.MethodPost, p.htu, nonce, "")
		if err != nil {
			return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: %w", op, err)
		}
		httpReq.Header.Set("DPoP", proof)
	}
	if p.attestation != nil {
		attestation, pop, err := p.attestation.ClientAttestationHeaders(ctx)
		if err != nil {
			return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: client attestation: %w", op, err)
		}
		httpReq.Header.Set("OAuth-Client-Attestation", attestation)
		httpReq.Header.Set("OAuth-Client-Attestation-PoP", pop)
	}
	res, err := w.deps.HTTP.Do(httpReq)
	if err != nil {
		return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: %w", op, err)
	}
	respBody, readErr := io.ReadAll(io.LimitReader(res.Body, maxTokenResponseBytes))
	_ = res.Body.Close()
	if readErr != nil {
		return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: read response: %w", op, readErr)
	}
	return tokenHTTPResponse{status: res.StatusCode, header: res.Header, body: respBody}, nil
}

func decodeTokenResponse(body []byte) (PreAuthorizedCodeTokenResult, error) {
	var wire tokenResponseBody
	if err := json.Unmarshal(body, &wire); err != nil {
		return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: decode response: %w", err)
	}
	result := PreAuthorizedCodeTokenResult{
		AccessToken:          fapi.NewSecret(wire.AccessToken),
		TokenType:            wire.TokenType,
		AuthorizationDetails: wire.AuthorizationDetails, RefreshToken: fapi.NewSecret(wire.RefreshToken),
	}
	if wire.ExpiresIn != nil {
		result.ExpiresIn = time.Duration(*wire.ExpiresIn) * time.Second
		result.HasExpiresIn = true
	}
	return result, nil
}

// dpopNonceChallenge reports the fresh nonce a DPoP nonce challenge
// response carries, or "" if res isn't one. RFC 9449 §8 — the
// Authorization Server's own nonce-challenge, what a Token Request
// gets — is HTTP 400 with a JSON body whose "error" member is
// "use_dpop_nonce", plus a DPoP-Nonce response header; this is
// deliberately not RFC 9449 §9's own WWW-Authenticate-header challenge,
// which only a resource server (a 401 response to a presented access
// token) ever sends, not a token endpoint. The DPoP-Nonce header alone
// isn't sufficient grounds to retry — a server may send it unprompted
// to pre-seed a future request — so both conditions must hold. body is
// the already-read response body (parseError's own input, reused here
// rather than re-reading res.Body a second time).
func dpopNonceChallenge(statusCode int, header http.Header, body []byte) string {
	if statusCode != http.StatusBadRequest {
		return ""
	}
	if parseError(statusCode, body).Code != "use_dpop_nonce" {
		return ""
	}
	return header.Get("DPoP-Nonce")
}

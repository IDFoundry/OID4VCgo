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
// Token Request (§6.1). Client authentication isn't supported: §6.1
// itself makes it OPTIONAL for this grant type ("authentication of the
// Client is OPTIONAL ... the client_id parameter is only needed when a
// form of Client Authentication that relies on this parameter is
// used"), and the one mechanism HAIP would otherwise want here —
// Wallet Attestation — isn't buildable yet; see the package doc
// comment's own note on storage.ClientAuthMethodAttestation.
// authorization_details isn't supported either, matching this
// package's own credential_configuration_id-only scope elsewhere.
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
}

// tokenResponseBody is the Token Response's own wire shape this
// package reads — RFC 6749 §5.1 plus RFC 9449 §5's token_type value;
// authorization_details and every other optional member (§6.2) are
// ignored, matching this package's own credential_configuration_id-only
// scope.
type tokenResponseBody struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   *int64 `json:"expires_in"`
}

// RequestPreAuthorizedCodeToken implements the Pre-Authorized Code
// Flow's own Token Request/Response (§6.1/§6.2): it builds a DPoP
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
	if req.PreAuthorizedCode == "" {
		return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: pre-authorized_code is required")
	}
	if req.DPoPKey == nil {
		return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: dpop_key is required")
	}
	if w.deps.Random == nil {
		return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: dependencies.random is required")
	}

	form := url.Values{}
	form.Set("grant_type", PreAuthorizedCodeGrantType)
	form.Set("pre-authorized_code", req.PreAuthorizedCode)
	if req.TxCode != "" {
		form.Set("tx_code", req.TxCode)
	}
	body := []byte(form.Encode())

	target := endpoint.URL()
	htu := target
	htu.RawQuery, htu.Fragment = "", ""

	var nonce string
	for attempt := 0; ; attempt++ {
		proof, err := w.GenerateDPoPProof(req.DPoPKey, http.MethodPost, htu.String(), nonce, "")
		if err != nil {
			return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: %w", err)
		}

		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(body))
		if err != nil {
			return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: build request: %w", err)
		}
		httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		httpReq.Header.Set("DPoP", proof)

		res, err := w.deps.HTTP.Do(httpReq)
		if err != nil {
			return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: %w", err)
		}
		respBody, readErr := io.ReadAll(io.LimitReader(res.Body, maxTokenResponseBytes))
		_ = res.Body.Close()
		if readErr != nil {
			return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: read response: %w", readErr)
		}

		if res.StatusCode == http.StatusOK {
			return decodeTokenResponse(respBody)
		}

		if attempt == 0 {
			if challengeNonce := dpopNonceChallenge(res.StatusCode, res.Header, respBody); challengeNonce != "" {
				nonce = challengeNonce
				continue
			}
		}
		return PreAuthorizedCodeTokenResult{}, parseError(res.StatusCode, respBody)
	}
}

func decodeTokenResponse(body []byte) (PreAuthorizedCodeTokenResult, error) {
	var wire tokenResponseBody
	if err := json.Unmarshal(body, &wire); err != nil {
		return PreAuthorizedCodeTokenResult{}, fmt.Errorf("wallet: request pre-authorized code token: decode response: %w", err)
	}
	result := PreAuthorizedCodeTokenResult{
		AccessToken: fapi.NewSecret(wire.AccessToken),
		TokenType:   wire.TokenType,
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

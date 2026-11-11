package wallet

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
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
	// PoP is built exactly as for its own PAR and token requests. The
	// request then also carries client_id, the Wallet Attestation's sub:
	// an Authorization Server that doesn't redeem pre-authorized codes
	// anonymously (pre-authorized_grant_anonymous_access_supported
	// false, OpenID4VCI 1.0 §12.3's default) identifies the client by
	// it (§6.1), and checks it matches the sub
	// (draft-ietf-oauth-attestation-based-client-auth-07 §6.3). Left
	// nil, the request is anonymous and carries no client_id.
	ClientAttestation ClientAttestationSource

	// Resource, OPTIONAL, names the resource servers the access token is
	// for (RFC 8707 §2): the Credential Issuer, so an Authorization
	// Server serving more than one can restrict the token to it, as the
	// authorization code flow does (OpenID4VCI §5.1.2). Each must be an
	// absolute URI without a fragment. A server that doesn't support
	// resource indicators ignores it.
	Resource []string
}

// ClientAttestationSource supplies the OAuth-Client-Attestation and a
// fresh OAuth-Client-Attestation-PoP header value for one request to the
// Authorization Server; RequestPreAuthorizedCodeToken calls it for each
// attempt. fapigo/client's (*client.Client).ClientAttestationHeaders
// implements it, and its ObserveAttestationChallenge implements
// AttestationChallengeObserver too.
type ClientAttestationSource interface {
	ClientAttestationHeaders(ctx context.Context) (attestation, pop string, err error)
}

// AttestationChallengeObserver is a ClientAttestationSource that takes
// the Challenge an Authorization Server sends in an
// OAuth-Client-Attestation-Challenge response header, for the next PoP
// it builds to carry (OAuth 2.0 Attestation-Based Client
// Authentication §6.2: the Client MUST use the most recent Challenge).
// RequestPreAuthorizedCodeToken passes it the headers of every Token
// Response, and retries once with a fresh PoP when the server answers
// use_attestation_challenge (§6.1). A source that isn't one gets no
// Challenge, and that error is returned as it is.
// fapigo/client's *client.Client is one.
type AttestationChallengeObserver interface {
	ClientAttestationSource
	ObserveAttestationChallenge(header http.Header)
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
// With a ClientAttestation, each attempt carries client_id, the sub of
// the Wallet Attestation the source returns for it.
// With a ClientAttestation that is an AttestationChallengeObserver, it
// passes the source every response's headers, and retries once more
// when the server answers use_attestation_challenge with a Challenge.
// A non-200 response (after those retries, if any) is returned as a
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
// dpopKey is set, and the attestation headers and client_id (the Wallet
// Attestation's sub) when attestation is, retrying once on a DPoP nonce
// challenge and once on an attestation challenge, and returns the 200
// response's body. op names the call in errors.
func (w *Wallet) postToken(
	ctx context.Context, endpoint fapi.URL, form url.Values, dpopKey crypto.Signer, attestation ClientAttestationSource, op string,
) ([]byte, error) {
	target := endpoint.URL()
	htu := target
	htu.RawQuery, htu.Fragment = "", ""
	post := tokenPost{target: target.String(), htu: htu.String(), form: form, dpopKey: dpopKey, attestation: attestation, op: op}

	observer, _ := attestation.(AttestationChallengeObserver)
	// At most three attempts: one retry after a DPoP nonce challenge,
	// and one after an attestation challenge, in either order.
	var nonce string
	var nonceRetried, challengeRetried bool
	for {
		res, err := w.postTokenOnce(ctx, post, nonce)
		if err != nil {
			return nil, err
		}
		if observer != nil {
			// The most recent Challenge, from any response, goes in
			// the next PoP (§6.2).
			observer.ObserveAttestationChallenge(res.header)
		}
		if res.status == http.StatusOK {
			return res.body, nil
		}
		if dpopKey != nil && !nonceRetried {
			if next := dpopNonceChallenge(res.status, res.header, res.body); next != "" {
				nonce, nonceRetried = next, true
				continue
			}
		}
		if observer != nil && !challengeRetried && attestationChallenge(res.status, res.header, res.body) {
			// The retry carries a DPoP nonce the response supplies, or
			// else the one this attempt did.
			if next := res.header.Get("DPoP-Nonce"); dpopKey != nil && next != "" {
				nonce = next
			}
			challengeRetried = true
			continue
		}
		return nil, parseError(EndpointToken, res.status, res.body)
	}
}

// attestationChallenge reports whether a Token Response asks for a retry
// with the Challenge it carries: a use_attestation_challenge error with
// an OAuth-Client-Attestation-Challenge header (OAuth 2.0
// Attestation-Based Client Authentication §6.1), as fapigo/client
// recognises one for its own requests.
func attestationChallenge(statusCode int, header http.Header, body []byte) bool {
	return header.Get("OAuth-Client-Attestation-Challenge") != "" &&
		parseError(EndpointToken, statusCode, body).Code == "use_attestation_challenge"
}

func (w *Wallet) checkPreAuthorizedCodeTokenRequest(req PreAuthorizedCodeTokenRequest) error {
	if err := checkResources(req.Resource); err != nil {
		return fmt.Errorf("wallet: pre-authorized code token request: %w", err)
	}
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

// preAuthorizedCodeTokenForm is the Token Request's form (§6.1), but
// for the client_id postTokenOnce adds when it authenticates the client.
func preAuthorizedCodeTokenForm(req PreAuthorizedCodeTokenRequest) url.Values {
	form := url.Values{}
	form.Set("grant_type", PreAuthorizedCodeGrantType)
	form.Set("pre-authorized_code", req.PreAuthorizedCode)
	if req.TxCode != "" {
		form.Set("tx_code", req.TxCode)
	}
	for _, r := range req.Resource {
		form.Add("resource", r)
	}
	return form
}

// tokenHTTPResponse is one Token Request's answer.
type tokenHTTPResponse struct {
	status int
	header http.Header
	body   []byte
}

// tokenPost is a Token Request, the same on each attempt: form POSTed
// to target, with a DPoP proof for htu when dpopKey is set, and the
// attestation headers and client_id when attestation is. op names the
// call in errors.
type tokenPost struct {
	target, htu string
	form        url.Values
	dpopKey     crypto.Signer
	attestation ClientAttestationSource
	op          string
}

// postTokenOnce sends p once, with a fresh DPoP proof (with nonce, if
// set) and a fresh attestation PoP: both are single-use.
func (w *Wallet) postTokenOnce(ctx context.Context, p tokenPost, nonce string) (tokenHTTPResponse, error) {
	op := p.op
	form := p.form
	var attestation, pop string
	if p.attestation != nil {
		var err error
		if attestation, pop, err = p.attestation.ClientAttestationHeaders(ctx); err != nil {
			return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: client attestation: %w", op, err)
		}
		clientID, err := attestationSubject(attestation)
		if err != nil {
			return tokenHTTPResponse{}, fmt.Errorf("wallet: %s: client attestation: %w", op, err)
		}
		form = maps.Clone(p.form)
		form.Set("client_id", clientID)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.target, strings.NewReader(form.Encode()))
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

// attestationSubject is the sub of the Wallet Attestation the wallet
// itself holds: its client_id
// (draft-ietf-oauth-attestation-based-client-auth-07 §5.1, where it's
// REQUIRED). The wallet doesn't verify its own attestation; the
// Authorization Server does, and checks client_id against it (§6.3).
func attestationSubject(attestation string) (string, error) {
	_, payload, err := jose.DecodeUnverified(attestation)
	if err != nil {
		return "", fmt.Errorf("decode wallet attestation: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := strictjson.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("decode wallet attestation: %w", err)
	}
	if claims.Sub == "" {
		return "", errors.New("wallet attestation has no sub to send as client_id")
	}
	return claims.Sub, nil
}

func decodeTokenResponse(body []byte) (PreAuthorizedCodeTokenResult, error) {
	var wire tokenResponseBody
	if err := strictjson.Unmarshal(body, &wire); err != nil {
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
	if parseError(EndpointToken, statusCode, body).Code != "use_dpop_nonce" {
		return ""
	}
	return header.Get("DPoP-Nonce")
}

// checkResources checks RFC 8707 §2's resource values: each an absolute
// URI without a fragment, none empty or repeated.
func checkResources(resources []string) error {
	seen := make(map[string]bool, len(resources))
	for _, r := range resources {
		u, err := url.Parse(r)
		switch {
		case r == "" || err != nil || !u.IsAbs():
			return fmt.Errorf("resource %q must be an absolute URI", r)
		case u.Fragment != "" || strings.Contains(r, "#"):
			return fmt.Errorf("resource %q must not have a fragment", r)
		case seen[r]:
			return fmt.Errorf("resource %q is repeated", r)
		}
		seen[r] = true
	}
	return nil
}

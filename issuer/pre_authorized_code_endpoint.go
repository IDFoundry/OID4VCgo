package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/dpop"
)

// DPoPReplayChecker detects DPoP proof replay by "jti" (RFC 9449
// §11.1) for ExchangePreAuthorizedCode's own Token Request — the same
// interface shape internal/dpop.ReplayChecker declares, restated here
// so a caller can satisfy it without reaching past this package's own
// public API into an internal one.
type DPoPReplayChecker interface {
	UseOnce(ctx context.Context, jti string, expiresAt time.Time) error
}

// ExchangePreAuthorizedCodeRequest is the Pre-Authorized Code Flow's
// own Token Request (§6.1).
type ExchangePreAuthorizedCodeRequest struct {
	// PreAuthorizedCode is REQUIRED.
	PreAuthorizedCode string

	// TxCode is the End-User's own Transaction Code value — REQUIRED
	// exactly when the matching PreAuthorizedCodeRecord's own TxCode is
	// non-empty (§6.1's own MUST); ignored otherwise.
	TxCode string

	// DPoPProof is REQUIRED: the presented "DPoP" HTTP header value.
	// HAIP 1.0 §4 makes DPoP mandatory for every grant, so this
	// package doesn't support an unconstrained (bearer) token for this
	// one either.
	DPoPProof string

	// TokenEndpoint is this Token Request's own target URL — needed to
	// verify DPoPProof's own "htu" claim (RFC 9449 §4.3). This package
	// has no Token Endpoint URL of its own to read this from: unlike
	// the Credential/Nonce/Deferred Credential/Notification Endpoints,
	// the Token Endpoint belongs to whichever Authorization Server this
	// issuer is paired with (see authorization_server.go), so the
	// caller — who already knows what URL the request arrived at —
	// supplies it directly.
	TokenEndpoint fapi.URL
}

// ExchangePreAuthorizedCodeResult is returned by a successful
// ExchangePreAuthorizedCode.
type ExchangePreAuthorizedCodeResult struct {
	AccessToken string

	// TokenType is always "DPoP" (RFC 9449 §5) — every access token
	// this method issues is DPoP-bound, per HAIP 1.0 §4.
	TokenType string

	ExpiresIn time.Duration

	// NextDPoPNonce is a freshly issued DPoP nonce the caller should
	// set as this response's own DPoP-Nonce header — WriteJSON already
	// does this — so the Wallet's next Token Request already carries a
	// valid one instead of needing its own challenge/retry round trip
	// (RFC 9449 §8's own proactive-refresh recommendation). Always ""
	// when Dependencies.DPoPNonces is nil (nonce-challenge support
	// disabled); otherwise always populated on success.
	NextDPoPNonce string
}

// WriteJSON writes r as a complete Token Response (§6.2): the
// DPoP-Nonce header when NextDPoPNonce is non-empty (RFC 9449 §8), HTTP
// 200, application/json, {"access_token","token_type","expires_in"}.
// Must be called before anything else writes to w.
func (r ExchangePreAuthorizedCodeResult) WriteJSON(w http.ResponseWriter) {
	if r.NextDPoPNonce != "" {
		w.Header().Set("DPoP-Nonce", r.NextDPoPNonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct { //nolint:gosec // the actual §6.2 Token Response body, meant to carry this
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}{AccessToken: r.AccessToken, TokenType: r.TokenType, ExpiresIn: int64(r.ExpiresIn.Seconds())})
}

// ExchangePreAuthorizedCode implements the Pre-Authorized Code Flow's
// own Token Request/Response (§6.1/§6.2) — the one OAuth 2.0 grant
// type entirely outside fapigo/server's own scope (it's OID4VCI-specific,
// not a FAPI 2.0 or base OAuth 2.0 grant), the same way it's outside
// fapigo/client's; see wallet.RequestPreAuthorizedCodeToken's own doc
// comment for that boundary's client-side half, which this method is
// the server-side counterpart to.
//
// It verifies req.DPoPProof via internal/dpop.Verify (using
// Config.Limits' own MaxDPoPProofAge/MaxDPoPClockSkew and
// Dependencies.DPoPReplay for jti-replay detection), and — only once
// that succeeds — consumes req.PreAuthorizedCode via
// Dependencies.PreAuthorizedCodes (§6.1's own single-use nature), checks
// the resulting record hasn't expired and its own TxCode (if any)
// matches req.TxCode exactly, and mints an access token via
// Dependencies.AccessTokens bound to the proof's own key by its RFC
// 7638 thumbprint.
//
// When Dependencies.DPoPNonces is configured, the presented proof's own
// "nonce" claim is checked between those two steps too (RFC 9449 §8):
// a missing, unknown, already-consumed, or expired nonce fails with
// ErrorUseDPoPNonce and a freshly issued replacement — before
// PreAuthorizedCode is ever consumed, so a Wallet's first, nonce-less
// attempt (it can't know the nonce in advance) never burns the
// single-use code it will need again on retry. A successful exchange
// then proactively issues the next nonce too (ExchangePreAuthorizedCodeResult's
// own NextDPoPNonce), the same "hand over the next nonce so the Wallet
// never round-trips through a challenge it can already avoid"
// convention DPoPNonceStore's own doc comment describes.
func (iss *Issuer) ExchangePreAuthorizedCode(ctx context.Context, req ExchangePreAuthorizedCodeRequest) (ExchangePreAuthorizedCodeResult, error) {
	if iss.deps.PreAuthorizedCodes == nil {
		return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: the pre-authorized_code grant is not configured")
	}
	if req.PreAuthorizedCode == "" {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidTokenRequest, 400, "pre-authorized_code is required", nil)
	}
	if req.DPoPProof == "" {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidTokenRequest, 400, "a DPoP proof is required", nil)
	}
	if req.TokenEndpoint.IsZero() {
		return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: token_endpoint is required")
	}

	now := iss.deps.Clock.Now()
	target := req.TokenEndpoint.URL()
	verified, err := dpop.Verify(ctx, dpop.VerifyRequest{
		Proof: req.DPoPProof, Method: http.MethodPost, URL: target.String(),
		Now: now, MaxProofAge: iss.cfg.Limits.MaxDPoPProofAge, MaxClockSkew: iss.cfg.Limits.MaxDPoPClockSkew,
		Replay: iss.deps.DPoPReplay,
	})
	if err != nil {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidTokenRequest, 400, "invalid DPoP proof", err)
	}

	if iss.deps.DPoPNonces != nil {
		if challenge := iss.checkDPoPNonce(ctx, verified.Nonce, now); challenge != nil {
			return ExchangePreAuthorizedCodeResult{}, challenge
		}
	}

	record, err := iss.deps.PreAuthorizedCodes.Consume(ctx, req.PreAuthorizedCode)
	if err != nil {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidGrant, 400, "pre-authorized_code is unknown or already used", err)
	}
	if now.After(record.ExpiresAt) {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidGrant, 400, "pre-authorized_code has expired", nil)
	}
	if record.TxCode != "" && req.TxCode != record.TxCode {
		return ExchangePreAuthorizedCodeResult{}, newError(ErrorInvalidGrant, 400, "tx_code does not match", nil)
	}

	accessToken, _, err := iss.deps.AccessTokens.IssueAccessToken(ctx, AccessTokenParams{
		Scope: record.Scopes, Thumbprint: verified.Thumbprint,
		Issuer: iss.cfg.Issuer.String(), Audience: iss.cfg.Issuer.String(),
		Now: now, Lifetime: iss.cfg.Limits.AccessTokenLifetime, Random: iss.deps.Random,
	})
	if err != nil {
		return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: issue access token: %w", err)
	}

	result := ExchangePreAuthorizedCodeResult{
		AccessToken: accessToken, TokenType: "DPoP", ExpiresIn: iss.cfg.Limits.AccessTokenLifetime,
	}
	if iss.deps.DPoPNonces != nil {
		nextNonce, err := iss.issueDPoPNonce(ctx, now)
		if err != nil {
			return ExchangePreAuthorizedCodeResult{}, fmt.Errorf("issuer: exchange pre-authorized code: issue next dpop nonce: %w", err)
		}
		result.NextDPoPNonce = nextNonce
	}
	return result, nil
}

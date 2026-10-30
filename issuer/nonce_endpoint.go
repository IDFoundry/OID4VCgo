package issuer

import (
	"context"
	"fmt"
	"net/http"
)

// nonceEntropyBytes sets how much randomness backs a c_nonce (§7.2:
// "New challenge values MUST be unpredictable"). 256 bits, matching
// FAPIgo's own DPoP-nonce entropy choice.
const nonceEntropyBytes = 32

// NonceResult is returned by a successful RequestNonce.
type NonceResult struct {
	// CNonce is the fresh challenge (§7.2's c_nonce) — pass it back to
	// the caller as the sole top-level member of the Nonce Response
	// body.
	CNonce string

	// DPoPNonce, when not empty, is the DPoP nonce
	// Dependencies.CredentialDPoPNonces issued, sent as the response's DPoP-Nonce
	// header (§7.2) for the Wallet to use at the Credential Endpoint.
	DPoPNonce string
}

// WriteJSON writes r as a Nonce Response (§7.2): the JSON body plus the
// required Cache-Control: no-store header ("Due to the temporal nature
// of the c_nonce value, the Credential Issuer MUST make the response
// uncacheable"), and DPoPNonce as the DPoP-Nonce header when set. Must
// be called before anything else writes to w.
func (r NonceResult) WriteJSON(w http.ResponseWriter) {
	if r.DPoPNonce != "" {
		w.Header().Set("DPoP-Nonce", r.DPoPNonce)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"c_nonce":%q}`, r.CNonce)
}

// RequestNonce implements the Nonce Endpoint (§7): it generates a
// fresh, unpredictable c_nonce, persists it via Dependencies.Nonces,
// and returns it, with a DPoP nonce from
// Dependencies.CredentialDPoPNonces when that's set. The Nonce Endpoint is not a protected resource
// (§7.1) — RequestNonce takes no credential of its own to check.
func (iss *Issuer) RequestNonce(ctx context.Context) (NonceResult, error) {
	if iss.cfg.Endpoints.Nonce.IsZero() {
		return NonceResult{}, fmt.Errorf("issuer: the nonce endpoint is not configured")
	}

	nonce, err := randomID(iss.deps.Random, nonceEntropyBytes)
	if err != nil {
		return NonceResult{}, fmt.Errorf("issuer: generate nonce: %w", err)
	}

	now := iss.deps.Clock.Now()
	if err := iss.deps.Nonces.Issue(ctx, NonceIssuance{
		Nonce:     nonce,
		Owner:     iss.storeOwner(),
		ExpiresAt: now.Add(iss.cfg.Limits.NonceLifetime),
	}); err != nil {
		return NonceResult{}, fmt.Errorf("issuer: persist nonce: %w", err)
	}

	result := NonceResult{CNonce: nonce}
	if iss.deps.CredentialDPoPNonces != nil {
		if result.DPoPNonce, err = iss.deps.CredentialDPoPNonces.IssueDPoPNonce(ctx); err != nil {
			return NonceResult{}, fmt.Errorf("issuer: issue dpop nonce: %w", err)
		}
	}
	return result, nil
}

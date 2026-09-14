package issuer

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
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
}

// WriteJSON writes r as a Nonce Response (§7.2): the JSON body plus the
// required Cache-Control: no-store header ("Due to the temporal nature
// of the c_nonce value, the Credential Issuer MUST make the response
// uncacheable"). Must be called before anything else writes to w.
func (r NonceResult) WriteJSON(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `{"c_nonce":%q}`, r.CNonce)
}

// RequestNonce implements the Nonce Endpoint (§7): it generates a
// fresh, unpredictable c_nonce, persists it via Dependencies.Nonces,
// and returns it. The Nonce Endpoint is not a protected resource
// (§7.1) — RequestNonce takes no credential of its own to check.
func (iss *Issuer) RequestNonce(ctx context.Context) (NonceResult, error) {
	if iss.cfg.Endpoints.Nonce.IsZero() {
		return NonceResult{}, fmt.Errorf("issuer: the nonce endpoint is not configured")
	}

	raw := make([]byte, nonceEntropyBytes)
	if _, err := io.ReadFull(iss.deps.Random, raw); err != nil {
		return NonceResult{}, fmt.Errorf("issuer: generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)

	now := iss.deps.Clock.Now()
	if err := iss.deps.Nonces.Issue(ctx, NonceIssuance{
		Nonce:     nonce,
		ExpiresAt: now.Add(iss.cfg.Limits.NonceLifetime),
	}); err != nil {
		return NonceResult{}, fmt.Errorf("issuer: persist nonce: %w", err)
	}

	return NonceResult{CNonce: nonce}, nil
}

package issuer

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"time"
)

// DPoPNonceIssuance is what DPoPNonceStore.Issue persists for one DPoP
// nonce this issuer has handed out via RFC 9449 §8's own nonce-challenge
// flow — a value the Wallet's next DPoP proof must carry in its own
// "nonce" claim (RFC 9449 §4.2). Unrelated to NonceStore's own c_nonce
// (§7's Nonce Endpoint binds Credential Request key proofs; this binds
// DPoP proofs to ExchangePreAuthorizedCode's own Token Request instead)
// — same shape, distinct protocol concepts, kept as separate stores
// rather than reusing NonceStore for both.
type DPoPNonceIssuance struct {
	Nonce     string
	ExpiresAt time.Time
}

// DPoPNonceConsumption is the input to DPoPNonceStore.Consume.
type DPoPNonceConsumption struct {
	// Nonce is the value a presented DPoP proof's own "nonce" claim
	// carried — the lookup key.
	Nonce string
}

// DPoPNonceRecord is what Consume returns for a successfully consumed
// nonce — the expiry Issue persisted, for the caller to compare against
// the time it's verifying at. The store itself never judges expiry,
// mirroring NonceStore's own convention.
type DPoPNonceRecord struct {
	ExpiresAt time.Time
}

// DPoPNonceStore persists DPoP nonces this issuer has issued via RFC
// 9449 §8's own nonce-challenge flow, keyed by the nonce value itself.
// There is no generic CRUD — Consume is the only way to check a nonce,
// and it always retires the record it returns, so a captured nonce can
// never be presented twice.
//
// Optional: nil (the default) disables nonce-challenge support
// entirely — ExchangePreAuthorizedCode then never issues or requires a
// DPoP nonce, exactly its behavior before this field existed. RFC 9449
// §8 leaves nonce-challenge support as the Authorization Server's own
// choice ("MAY"); HAIP 1.0 §4 only makes DPoP itself mandatory, not
// this extension.
type DPoPNonceStore interface {
	Issue(ctx context.Context, issuance DPoPNonceIssuance) error

	// Consume atomically retrieves and retires the nonce identified by
	// consumption.Nonce. It returns an error if the nonce is unknown or
	// already consumed; the caller checks the returned record's own
	// ExpiresAt against the time it's verifying at.
	Consume(ctx context.Context, consumption DPoPNonceConsumption) (DPoPNonceRecord, error)
}

// issueDPoPNonce generates and persists a fresh nonce, valid from now
// for iss.cfg.Limits.DPoPNonceLifetime. Only ever called once
// iss.deps.DPoPNonces is known to be non-nil.
func (iss *Issuer) issueDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	raw := make([]byte, nonceEntropyBytes)
	if _, err := io.ReadFull(iss.deps.Random, raw); err != nil {
		return "", fmt.Errorf("issuer: generate dpop nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	if err := iss.deps.DPoPNonces.Issue(ctx, DPoPNonceIssuance{
		Nonce: nonce, ExpiresAt: now.Add(iss.cfg.Limits.DPoPNonceLifetime),
	}); err != nil {
		return "", fmt.Errorf("issuer: issue dpop nonce: %w", err)
	}
	return nonce, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8) when
// iss.deps.DPoPNonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent). A missing, unknown, already-consumed
// or expired nonce is rejected with a *Error (via *Error's own Nonce
// method, and already set on its DPoP-Nonce response header by
// WriteJSON) carrying a freshly issued replacement for the caller to
// retry with; a validly consumed nonce returns nil, letting the caller
// proceed. A failure generating or persisting that replacement is
// returned as a plain error instead — not attributable to the request
// itself, the same "typed *Error only for what the request got wrong"
// split every other Dependencies failure in this package already
// takes.
//
// Called only when iss.deps.DPoPNonces != nil — every call site guards
// that, since this is an optional dependency (see DPoPNonceStore's own
// doc comment), not a required-with-visible-opt-out one.
func (iss *Issuer) checkDPoPNonce(ctx context.Context, presented string, now time.Time) error {
	valid := false
	if presented != "" {
		record, err := iss.deps.DPoPNonces.Consume(ctx, DPoPNonceConsumption{Nonce: presented})
		valid = err == nil && !now.After(record.ExpiresAt)
	}
	if valid {
		return nil
	}

	fresh, err := iss.issueDPoPNonce(ctx, now)
	if err != nil {
		return fmt.Errorf("issuer: check dpop nonce: %w", err)
	}
	challenge := newError(ErrorUseDPoPNonce, 400, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = fresh
	return challenge
}

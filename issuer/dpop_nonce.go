package issuer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// DPoPNonceIssuance is what DPoPNonceStore.Issue persists for one DPoP
// nonce this issuer has handed out via RFC 9449 §8's own nonce-challenge
// flow — a value the Wallet's DPoP proofs must carry in their own
// "nonce" claim (RFC 9449 §4.2). Unrelated to NonceStore's own c_nonce
// (§7's Nonce Endpoint binds Credential Request key proofs; this binds
// DPoP proofs to ExchangePreAuthorizedCode's own Token Request instead)
// — same shape, distinct protocol concepts, kept as separate stores
// rather than reusing NonceStore for both.
type DPoPNonceIssuance struct {
	Nonce     string
	ExpiresAt time.Time
}

// DPoPNonceLookup is the input to DPoPNonceStore.Lookup.
type DPoPNonceLookup struct {
	// Nonce is the value a presented DPoP proof's own "nonce" claim
	// carried — the lookup key.
	Nonce string
}

// DPoPNonceRecord is what Lookup returns for an issued nonce — the
// expiry Issue persisted, for the caller to compare against the time
// it's verifying at. The store itself never judges expiry, mirroring
// NonceStore's own convention.
type DPoPNonceRecord struct {
	ExpiresAt time.Time
}

// ErrDPoPNonceUnknown is what a DPoPNonceStore's Lookup returns, or
// wraps, for a nonce it holds no record of: one it never issued, or one
// it dropped after its ExpiresAt. ExchangePreAuthorizedCode answers it
// with a use_dpop_nonce challenge carrying the current nonce. Any other
// Lookup error means the store couldn't answer (its backend unreachable,
// a timeout, context.Canceled or context.DeadlineExceeded), and fails
// the request as a plain error, a 500 from WriteError, rather than
// telling the Wallet its proof is stale.
var ErrDPoPNonceUnknown = errors.New("issuer: unknown dpop nonce")

// errDPoPNoncesDeclined is what NoDPoPNonces's methods return.
var errDPoPNoncesDeclined = errors.New("issuer: NoDPoPNonces declines DPoP nonces and stores none")

// DPoPNonceStore persists DPoP nonces this issuer has issued via RFC
// 9449 §8's own nonce-challenge flow, keyed by the nonce value itself.
// There is no generic CRUD.
//
// A nonce is valid for a time window, not for one use: RFC 9449 §8
// expects that "clients need to keep only one nonce value and servers
// need to keep a window of recent nonces", and a Wallet presents the
// same nonce on every request until the server supplies a new one
// (§8.2). A replayed proof is refused by its "jti" (Dependencies.DPoPReplay),
// not by its nonce. The Issuer hands out one current nonce at a time
// and issues the next once half of Config.Limits.DPoPNonceLifetime has
// passed, so Issue is called rarely and Lookup on every Token Request
// that carries a nonce. Each Issuer instance keeps its own current
// nonce, so instances sharing one store accept each other's nonces.
//
// issuertest.TestDPoPNonceStoreContract checks an implementation
// against this contract.
//
// Optional under AssuranceDevelopment: nil disables nonce-challenge
// support entirely — ExchangePreAuthorizedCode then never issues or
// requires a DPoP nonce. RFC 9449 §8 leaves nonce-challenge support as
// the Authorization Server's own choice ("MAY"), and HAIP 1.0 §4 only
// makes DPoP itself mandatory, not this extension. Under
// AssuranceProduction, New requires either a store or the explicit
// NoDPoPNonces{} decline wherever this issuer verifies the Token
// Request's DPoP proof itself (see Dependencies.DPoPNonces).
type DPoPNonceStore interface {
	// Issue persists issuance under its Nonce until at least its
	// ExpiresAt, so Lookup can find it.
	Issue(ctx context.Context, issuance DPoPNonceIssuance) error

	// Lookup returns the record Issue persisted for lookup.Nonce,
	// leaving it in place: any number of calls, concurrent or not, with
	// an issued nonce must all succeed. It returns an error wrapping
	// ErrDPoPNonceUnknown if the nonce is unknown; the caller checks the
	// returned record's own ExpiresAt against the time it's verifying
	// at, so the store may drop a record once it has expired. Any other
	// error means the store couldn't answer.
	Lookup(ctx context.Context, lookup DPoPNonceLookup) (DPoPNonceRecord, error)
}

// NoDPoPNonces explicitly declines DPoP nonces (RFC 9449 §8) as
// Dependencies.DPoPNonces: ExchangePreAuthorizedCode then accepts a
// DPoP proof without a "nonce" claim, as it does with DPoPNonces left
// nil. AssuranceProduction refuses a nil DPoPNonces where this issuer
// verifies the Token Request's DPoP proof itself, so declining there is
// a conscious, visible line of code (DPoPNonces: issuer.NoDPoPNonces{}),
// matching fapigo/server.NoDPoPNonces.
//
// Without nonces, a DPoP proof's freshness rests on its "iat" alone
// (Config.Limits.MaxDPoPProofAge): an attacker who can make a Wallet
// generate proofs ahead of time, or capture them, can use one here
// until it ages out (RFC 9449 §11.1).
//
// New treats it as if DPoPNonces were nil; it never stores or looks up
// a nonce. Passed anywhere else as a DPoPNonceStore, Issue and Lookup
// fail.
type NoDPoPNonces struct{}

// Issue implements DPoPNonceStore by failing: NoDPoPNonces stores
// nothing.
func (NoDPoPNonces) Issue(context.Context, DPoPNonceIssuance) error {
	return errDPoPNoncesDeclined
}

// Lookup implements DPoPNonceStore by failing: NoDPoPNonces stores
// nothing.
func (NoDPoPNonces) Lookup(context.Context, DPoPNonceLookup) (DPoPNonceRecord, error) {
	return DPoPNonceRecord{}, errDPoPNoncesDeclined
}

// dpopNoncesDeclined reports whether nonces is NoDPoPNonces, by value or
// pointer.
func dpopNoncesDeclined(nonces DPoPNonceStore) bool {
	switch nonces.(type) {
	case NoDPoPNonces, *NoDPoPNonces:
		return true
	}
	return false
}

// dpopNonceRotator holds the nonce an Issuer currently hands out. Its
// zero value is ready to use; it must not be copied after first use.
type dpopNonceRotator struct {
	mu        sync.Mutex
	current   string
	expiresAt time.Time
	// rotating counts the calls persisting a new nonce right now,
	// without mu held.
	rotating int
}

// currentDPoPNonce returns the nonce to hand out at now: the one it
// last issued while more than half of iss.cfg.Limits.DPoPNonceLifetime
// remains, otherwise a fresh one, persisted in iss.deps.DPoPNonces until
// now plus that lifetime. A Wallet given the previous nonce can keep
// using it until it expires, at least half the lifetime after the
// switch, so its requests in flight across a rotation still succeed.
// Only ever called once iss.deps.DPoPNonces is known to be non-nil.
//
// The store write happens without the rotator's lock held, so a slow
// store stalls only the call rotating: while it does, other calls hand
// out the previous nonce, still valid until it expires. Only with no
// unexpired nonce at all does each call persist its own.
func (iss *Issuer) currentDPoPNonce(ctx context.Context, now time.Time) (string, error) {
	r := &iss.dpopNonces
	lifetime := iss.cfg.Limits.DPoPNonceLifetime
	r.mu.Lock()
	fresh := r.current != "" && now.Before(r.expiresAt.Add(-lifetime/2))
	stillValid := r.current != "" && r.rotating > 0 && now.Before(r.expiresAt)
	if fresh || stillValid {
		nonce := r.current
		r.mu.Unlock()
		return nonce, nil
	}
	r.rotating++
	r.mu.Unlock()

	nonce, expiresAt, err := iss.issueDPoPNonce(ctx, now.Add(lifetime))

	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotating--
	if err != nil {
		return "", err
	}
	if expiresAt.After(r.expiresAt) {
		r.current, r.expiresAt = nonce, expiresAt
	}
	return nonce, nil
}

// issueDPoPNonce generates a DPoP nonce and persists it in
// iss.deps.DPoPNonces until expiresAt.
func (iss *Issuer) issueDPoPNonce(ctx context.Context, expiresAt time.Time) (string, time.Time, error) {
	nonce, err := randomID(iss.deps.Random, nonceEntropyBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("issuer: generate dpop nonce: %w", err)
	}
	if err := iss.deps.DPoPNonces.Issue(ctx, DPoPNonceIssuance{Nonce: nonce, ExpiresAt: expiresAt}); err != nil {
		return "", time.Time{}, fmt.Errorf("issuer: issue dpop nonce: %w", err)
	}
	return nonce, expiresAt, nil
}

// checkDPoPNonce enforces the nonce challenge (RFC 9449 §8) when
// iss.deps.DPoPNonces is configured: presented is the DPoP proof's own
// "nonce" claim (empty if absent). A nonce this issuer issued is valid
// until it expires, for any number of proofs (§8.2: the client uses it
// "until the server supplies a new nonce"); each proof's "jti" is what
// refuses a replay. A missing, unknown (ErrDPoPNonceUnknown) or expired
// nonce is rejected with a *Error (via *Error's own Nonce method, and
// already set on its DPoP-Nonce response header by WriteJSON) carrying
// the current nonce for the caller to retry with; a valid nonce returns
// nil, letting the caller proceed. A store that can't answer the
// lookup, or a failure issuing the current nonce, is returned as a
// plain error instead — not attributable to the request itself, the
// same "typed *Error only for what the request got wrong" split every
// other Dependencies failure in this package already takes.
//
// Called only when iss.deps.DPoPNonces != nil — every call site guards
// that. New has already turned NoDPoPNonces into nil, so a declined
// store never gets here.
func (iss *Issuer) checkDPoPNonce(ctx context.Context, presented string, now time.Time) error {
	if presented != "" {
		record, err := iss.deps.DPoPNonces.Lookup(ctx, DPoPNonceLookup{Nonce: presented})
		switch {
		case err == nil && !now.After(record.ExpiresAt):
			return nil
		case err != nil && !errors.Is(err, ErrDPoPNonceUnknown):
			return fmt.Errorf("issuer: check dpop nonce: look up: %w", err)
		}
	}

	current, err := iss.currentDPoPNonce(ctx, now)
	if err != nil {
		return fmt.Errorf("issuer: check dpop nonce: %w", err)
	}
	challenge := newError(ErrorUseDPoPNonce, 400, "DPoP proof must carry a current nonce", nil)
	challenge.nonce = current
	return challenge
}

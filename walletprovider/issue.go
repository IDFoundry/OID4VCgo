package walletprovider

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// WalletAttestationRequest asks for a Wallet Attestation. The HTTP
// layer has already checked the request was signed with the instance
// key (VerifyRequest).
type WalletAttestationRequest struct {
	InstanceID string

	// ClientID is the client the Wallet Attestation authenticates: its
	// sub. One of Config.ClientIDs.
	ClientID string
}

// WalletAttestation issues a Wallet Attestation (HAIP 1.0 §4.4.1,
// OID4VCI 1.0 Appendix E) for an active instance whose registration
// evidence the Policy still accepts: sub is the client ID, cnf the
// instance key, status the instance's status list entry, and
// wallet_name and wallet_link are Config's. It expires after
// Config.WalletAttestationTTL, and carries Chain as x5c.
func (p *Provider) WalletAttestation(ctx context.Context, req WalletAttestationRequest) (string, error) {
	if !slices.Contains(p.cfg.ClientIDs, req.ClientID) {
		return "", fmt.Errorf("%w: %q", ErrUnknownClient, req.ClientID)
	}
	in, err := p.activeInstance(ctx, req.InstanceID)
	if err != nil {
		return "", err
	}
	key, err := jwk.ParsePublicKey(in.Key)
	if err != nil {
		return "", fmt.Errorf("walletprovider: the stored instance key: %w", err)
	}
	// The instance is updated first, and only while it's still active,
	// so an instance revoked meanwhile gets nothing.
	now := p.now()
	if err := p.update(ctx, in.ID, func(cur *Instance) error {
		if err := stateError(cur.State); err != nil {
			return err
		}
		cur.LastSeenAt = now
		cur.WalletAttestations++
		return nil
	}); err != nil {
		return "", err
	}
	jwt, err := attestation.IssueWalletAttestation(p.deps.Signer, p.alg, p.header, attestation.WalletAttestationClaims{
		Issuer: p.cfg.Identifier, Subject: req.ClientID, InstanceKey: key,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(p.cfg.WalletAttestationTTL).Unix(),
		Extra: attestation.WalletAttestationExtraClaims{
			WalletName: p.cfg.WalletName, WalletLink: p.cfg.WalletLink, Status: in.Status.Claim(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	return jwt, nil
}

// KeyAttestationRequest asks for a Key Attestation over holder keys.
// The HTTP layer has already checked the request was signed with the
// instance key (VerifyRequest).
type KeyAttestationRequest struct {
	InstanceID string

	// Challenge is a challenge issued for PurposeHolder, which every
	// piece of Evidence is bound to.
	Challenge string

	// Keys are the holder keys to attest: P-256 or Ed25519, at most
	// Policy.MaxKeys, each once.
	Keys []crypto.PublicKey

	// Evidence vouches for the keys: one per key (Android Key
	// Attestation), or one for all of them (an App Attest assertion).
	// At least one is REQUIRED.
	Evidence []Evidence

	// Nonce is the Credential Issuer's c_nonce, carried as the
	// attestation's nonce (HAIP 1.0 §4.5.1); empty leaves it out.
	Nonce string
}

// KeyAttestationResult is an issued Key Attestation.
type KeyAttestationResult struct {
	// JWT is the Key Attestation (OID4VCI 1.0 Appendix D.1).
	JWT string

	// AttestedKeys are the keys it attests: those of the request whose
	// evidence passed and whose security level the Policy accepts, in
	// the request's order.
	AttestedKeys []crypto.PublicKey

	// KeyStorage and UserAuthentication are its key_storage and
	// user_authentication claims, from Policy.KeyStorage alone.
	KeyStorage         []attestation.AttackPotentialResistance
	UserAuthentication []attestation.AttackPotentialResistance

	ExpiresAt time.Time
}

// KeyAttestation issues a Key Attestation (HAIP 1.0 §4.5.1, OID4VCI 1.0
// Appendix D) for holder keys of an active instance whose registration
// evidence the Policy still accepts. It consumes the challenge and
// verifies each piece of evidence; evidence must be from the instance's
// platform and app. attested_keys lists only the keys some evidence
// that passed vouches for at a security level the Policy accepts — a
// key without one is left out, and the request fails with
// ErrNoKeyAttested if that leaves none. key_storage and
// user_authentication come from Policy.KeyStorage alone. status is the
// instance's status list entry, so revoking the instance withdraws its
// Key Attestations too. It expires after Config.KeyAttestationTTL.
func (p *Provider) KeyAttestation(ctx context.Context, req KeyAttestationRequest) (KeyAttestationResult, error) {
	if err := p.checkKeys(req.Keys); err != nil {
		return KeyAttestationResult{}, err
	}
	if len(req.Evidence) == 0 || slices.ContainsFunc(req.Evidence, func(e Evidence) bool { return e.Kind == "" || len(e.Data) == 0 }) {
		return KeyAttestationResult{}, ErrEvidenceRequired
	}
	if len(req.Evidence) > len(req.Keys) {
		return KeyAttestationResult{}, fmt.Errorf("%w: more evidence than keys", ErrInvalidRequest)
	}
	in, err := p.activeInstance(ctx, req.InstanceID)
	if err != nil {
		return KeyAttestationResult{}, err
	}
	challenge, err := p.consumeChallenge(ctx, req.Challenge, PurposeHolder)
	if err != nil {
		return KeyAttestationResult{}, err
	}

	attested, counter, err := p.verifyHolderKeys(ctx, in, challenge, req)
	if err != nil {
		return KeyAttestationResult{}, err
	}
	keyStorage, userAuth := p.cfg.Policy.claims(in.Evidence.Platform, attested)

	// The instance is updated before the attestation is issued, and
	// only while it's still active: a counter an assertion advanced is
	// stored first, compared with the one the verifier was given, so a
	// replayed or concurrent assertion gets nothing.
	now := p.now()
	if err := p.update(ctx, in.ID, func(cur *Instance) error {
		if err := stateError(cur.State); err != nil {
			return err
		}
		if counter != nil {
			if cur.Counter != in.Counter {
				return fmt.Errorf("%w: the instance's counter changed while its assertion was verified", ErrEvidenceRejected)
			}
			cur.Counter = *counter
		}
		cur.LastSeenAt = now
		cur.KeyAttestations++
		return nil
	}); err != nil {
		return KeyAttestationResult{}, err
	}

	result := KeyAttestationResult{KeyStorage: keyStorage, UserAuthentication: userAuth, ExpiresAt: now.Add(p.cfg.KeyAttestationTTL)}
	jwks := make([]json.RawMessage, len(attested))
	for i, k := range attested {
		if jwks[i], err = attestation.AttestedKey(k.Key); err != nil {
			return KeyAttestationResult{}, fmt.Errorf("walletprovider: %w", err)
		}
		result.AttestedKeys = append(result.AttestedKeys, k.Key)
	}
	exp := result.ExpiresAt.Unix()
	result.JWT, err = attestation.Issue(p.deps.Signer, p.alg, p.header, attestation.Claims{
		Issuer: p.cfg.Identifier, IssuedAt: now.Unix(), ExpiresAt: &exp,
		AttestedKeys: jwks, KeyStorage: keyStorage, UserAuthentication: userAuth,
		Nonce: req.Nonce, Status: in.Status.Claim(),
	})
	if err != nil {
		return KeyAttestationResult{}, fmt.Errorf("walletprovider: %w", err)
	}
	return result, nil
}

// checkKeys refuses an empty, oversized or repeating key list, or a key
// of a type the attestation can't carry.
func (p *Provider) checkKeys(keys []crypto.PublicKey) error {
	switch {
	case len(keys) == 0:
		return fmt.Errorf("%w: no keys", ErrInvalidRequest)
	case len(keys) > p.cfg.Policy.maxKeys():
		return fmt.Errorf("%w: %d keys, more than %d", ErrInvalidRequest, len(keys), p.cfg.Policy.maxKeys())
	}
	for i, k := range keys {
		if _, err := marshalKey(k); err != nil {
			return fmt.Errorf("key %d: %w", i, err)
		}
		if slices.ContainsFunc(keys[:i], func(prev crypto.PublicKey) bool { return certchain.SameKey(prev, k) }) {
			return fmt.Errorf("%w: key %d is listed twice", ErrInvalidRequest, i)
		}
	}
	return nil
}

// verifyHolderKeys verifies req's evidence for in and returns the keys
// to attest, in req.Keys' order, and the instance's new counter if an
// assertion advanced it. Evidence that fails, or comes from another
// platform or app than the instance's, vouches for nothing; a key its
// evidence places at a security level the Policy refuses is left out.
func (p *Provider) verifyHolderKeys(ctx context.Context, in Instance, challenge []byte, req KeyAttestationRequest) ([]AttestedKey, *uint64, error) {
	var vouched []AttestedKey
	var counter *uint64
	var lastErr error
	for _, e := range req.Evidence {
		ev, err := p.verify(ctx, EvidenceInput{Evidence: e, Challenge: challenge, Purpose: PurposeHolder, Keys: req.Keys, Instance: &in})
		if err == nil {
			err = p.checkHolderEvidence(in, ev)
		}
		if err != nil {
			lastErr = err
			continue
		}
		if ev.Counter != nil {
			if counter != nil {
				return nil, nil, fmt.Errorf("%w: more than one piece of evidence advances the instance's counter", ErrInvalidRequest)
			}
			if *ev.Counter <= in.Counter {
				return nil, nil, fmt.Errorf("%w: the counter %d doesn't exceed the instance's %d", ErrEvidenceRejected, *ev.Counter, in.Counter)
			}
			counter = ev.Counter
		}
		vouched = append(vouched, ev.Keys...)
	}
	levels := p.cfg.Policy.Platforms[in.Evidence.Platform].SecurityLevels
	var attested []AttestedKey
	for _, k := range req.Keys {
		// A key two pieces of evidence vouch for at different levels
		// takes the first.
		if a, ok := attestedKey(vouched, k); ok && slices.Contains(levels, a.SecurityLevel) {
			attested = append(attested, a)
		}
	}
	if len(attested) == 0 {
		if lastErr != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrNoKeyAttested, lastErr)
		}
		return nil, nil, ErrNoKeyAttested
	}
	return attested, counter, nil
}

// checkHolderEvidence refuses holder key evidence from another platform
// or app than the instance's, or that the Policy refuses.
func (p *Provider) checkHolderEvidence(in Instance, ev VerifiedEvidence) error {
	if ev.Platform != in.Evidence.Platform {
		return fmt.Errorf("%w: evidence from %q for an instance on %q", ErrEvidenceRejected, ev.Platform, in.Evidence.Platform)
	}
	if ev.AppID != in.Evidence.AppID {
		return fmt.Errorf("%w: evidence from app %q for an instance of %q", ErrEvidenceRejected, ev.AppID, in.Evidence.AppID)
	}
	_, err := p.cfg.Policy.checkEvidence(ev.Platform, ev.AppVersion, ev.BootState, ev.DeviceLocked)
	return err
}

// activeInstance returns the instance with id, refusing one that isn't
// active or whose registration evidence the Policy no longer accepts.
func (p *Provider) activeInstance(ctx context.Context, id string) (Instance, error) {
	in, err := p.getInstance(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	if err := stateError(in.State); err != nil {
		return Instance{}, err
	}
	if err := p.cfg.Policy.checkInstance(in); err != nil {
		return Instance{}, err
	}
	return in, nil
}

func (p *Provider) getInstance(ctx context.Context, id string) (Instance, error) {
	if id == "" {
		return Instance{}, ErrInstanceNotFound
	}
	in, err := p.deps.Instances.Get(ctx, id)
	switch {
	case errors.Is(err, ErrNotFound):
		return Instance{}, ErrInstanceNotFound
	case err != nil:
		return Instance{}, fmt.Errorf("walletprovider: reading instance: %w", err)
	}
	return in, nil
}

// maxUpdateAttempts is how many times update retries a compare-and-swap
// another update beat.
const maxUpdateAttempts = 8

// update applies fn to the stored instance with id and stores the
// result, reading it again and retrying when a concurrent update
// changed it in between. An error from fn stops it, unstored.
func (p *Provider) update(ctx context.Context, id string, fn func(*Instance) error) error {
	for range maxUpdateAttempts {
		in, err := p.getInstance(ctx, id)
		if err != nil {
			return err
		}
		if err := fn(&in); err != nil {
			return err
		}
		switch err := p.deps.Instances.Update(ctx, in); {
		case err == nil:
			return nil
		case !errors.Is(err, ErrConflict):
			return fmt.Errorf("walletprovider: updating instance: %w", err)
		}
	}
	return fmt.Errorf("walletprovider: updating instance: %w after %d attempts", ErrConflict, maxUpdateAttempts)
}

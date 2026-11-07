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
)

// WalletAttestationRequest asks for a Wallet Attestation. The HTTP
// layer has already checked the request was signed with the instance's
// registration key (VerifyRequest).
type WalletAttestationRequest struct {
	InstanceID string

	// ClientID is the client the Wallet Attestation authenticates: its
	// sub. One of Config.ClientIDs.
	ClientID string

	// InstanceKey is the instance key the Wallet Attestation's cnf
	// names: the wallet's key for one issuance, P-256 or Ed25519.
	// REQUIRED.
	InstanceKey crypto.PublicKey

	// Challenge, a challenge issued for PurposeInstance, and Evidence,
	// bound to it and vouching for InstanceKey, are REQUIRED the first
	// time the instance asks for a Wallet Attestation for InstanceKey.
	// Once the key is recorded for the instance they're ignored: not
	// verified, and the challenge not used up.
	Challenge string
	Evidence  Evidence
}

// WalletAttestation issues a Wallet Attestation (HAIP 1.0 §4.4.1,
// OID4VCI 1.0 Appendix E) for an active instance whose registration
// evidence the Policy still accepts: sub is the client ID, cnf the
// instance key, status the instance key's status list entry, and
// wallet_name and wallet_link are Config's. It expires after
// Config.WalletAttestationTTL, and carries Chain as x5c.
//
// The first time the instance asks for one for an instance key, it
// consumes the challenge and verifies the evidence for the key, as
// KeyAttestation does a holder key's: of the Kind the instance
// registered with, from its platform and app, accepted by the Policy,
// at a security level the Policy accepts for the platform. It stores
// the instance's new counter if the evidence advanced it (an App
// Attest assertion), refusing an assertion a concurrent request used
// meanwhile, and only then records the key for the instance
// (InstanceKeyStore) with a status list index of its own. Later
// requests for the key reuse the record, without evidence, and its
// index while it's on the current period's lists
// (Config.StatusListPeriod); in a later period, the key gets an index
// on that period's lists first. A key unused for
// Config.InstanceKeyRetention, whose record the InstanceKeyStore has
// deleted, is a new key again: evidence is required, and refused with
// ErrEvidenceRequired if missing.
// A key recorded for another instance, or that is the instance's
// registration key, is refused with ErrInstanceKeyRegistered.
func (p *Provider) WalletAttestation(ctx context.Context, req WalletAttestationRequest) (string, error) {
	if !slices.Contains(p.cfg.ClientIDs, req.ClientID) {
		return "", fmt.Errorf("%w: %q", ErrUnknownClient, req.ClientID)
	}
	key, err := marshalKey(req.InstanceKey)
	if err != nil {
		return "", err
	}
	in, err := p.activeInstance(ctx, req.InstanceID)
	if err != nil {
		return "", err
	}
	ik, err := p.instanceKeyFor(ctx, in, key, req)
	if err != nil {
		return "", err
	}
	now := p.now()
	if ik, err = p.inCurrentPeriod(ctx, ik, now); err != nil {
		return "", err
	}
	// The instance is updated after its instance key is recorded or
	// moved, and only while it's still active. Suspend and Revoke store
	// the state before they set the statuses of the instance's keys, so
	// either this request sees the new state and gets nothing, or they
	// find the key's record and set its statuses too.
	if err := p.recordUse(ctx, in, nil, func(cur *Instance) {
		cur.LastSeenAt = now
		cur.WalletAttestations++
	}); err != nil {
		return "", err
	}
	jwt, err := attestation.IssueWalletAttestation(p.deps.Signer, p.alg, p.header, attestation.WalletAttestationClaims{
		Issuer: p.cfg.Identifier, Subject: req.ClientID, InstanceKey: req.InstanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(p.cfg.WalletAttestationTTL).Unix(),
		Extra: attestation.WalletAttestationExtraClaims{
			WalletName: p.cfg.WalletName, WalletLink: p.cfg.WalletLink, Status: ik.Status.Claim(),
		},
	})
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	return jwt, nil
}

// instanceKeyFor returns the instance key key of in, recording it with
// req's evidence if it's new.
func (p *Provider) instanceKeyFor(ctx context.Context, in Instance, key marshaledKey, req WalletAttestationRequest) (InstanceKey, error) {
	if key.thumbprint == in.KeyThumbprint {
		return InstanceKey{}, fmt.Errorf("%w: the instance key is the instance's registration key", ErrInstanceKeyRegistered)
	}
	ik, err := p.deps.InstanceKeys.Get(ctx, key.thumbprint)
	switch {
	case errors.Is(err, ErrNotFound):
		return p.recordInstanceKey(ctx, in, key, req)
	case err != nil:
		return InstanceKey{}, fmt.Errorf("walletprovider: reading instance key: %w", err)
	case ik.InstanceID != in.ID:
		return InstanceKey{}, fmt.Errorf("%w: the instance key is another instance's", ErrInstanceKeyRegistered)
	}
	return ik, p.checkInstanceKey(in, ik)
}

// recordInstanceKey verifies req's evidence for the new instance key
// key of in, stores the instance's new counter if the evidence
// advanced it, reserves the key's status list index and records it.
func (p *Provider) recordInstanceKey(ctx context.Context, in Instance, key marshaledKey, req WalletAttestationRequest) (InstanceKey, error) {
	if req.Evidence.Kind == "" || len(req.Evidence.Data) == 0 {
		return InstanceKey{}, fmt.Errorf("%w: the instance key isn't recorded yet", ErrEvidenceRequired)
	}
	challenge, err := p.consumeChallenge(ctx, req.Challenge, PurposeInstance)
	if err != nil {
		return InstanceKey{}, err
	}
	ev, err := p.verify(ctx, EvidenceInput{
		Evidence: req.Evidence, Challenge: challenge, Purpose: PurposeInstance,
		Keys: []crypto.PublicKey{req.InstanceKey}, Instance: &in,
	})
	if err == nil {
		err = p.checkEvidenceFrom(in, req.Evidence.Kind, ev)
	}
	if err != nil {
		return InstanceKey{}, err
	}
	attested, ok := attestedKey(ev.Keys, req.InstanceKey)
	switch {
	case !ok:
		return InstanceKey{}, fmt.Errorf("%w: the evidence doesn't vouch for the instance key", ErrEvidenceRejected)
	case ev.Counter != nil && *ev.Counter <= in.Counter:
		return InstanceKey{}, fmt.Errorf("%w: the counter %d doesn't exceed the instance's %d", ErrEvidenceRejected, *ev.Counter, in.Counter)
	}
	ik := InstanceKey{
		Thumbprint: key.thumbprint, Key: key.json, InstanceID: in.ID,
		SecurityLevel: attested.SecurityLevel, Binding: attested.Binding, CreatedAt: p.now(),
	}
	if err := p.checkInstanceKey(in, ik); err != nil {
		return InstanceKey{}, err
	}
	// The counter is stored before the key is recorded, so a replayed
	// or concurrent assertion the compare-and-swap refuses leaves no
	// record behind for a later request to reuse without evidence. A
	// key then not recorded leaves the counter advanced, which costs
	// the wallet only a fresh assertion.
	if ev.Counter != nil {
		if err := p.recordUse(ctx, in, ev.Counter, func(*Instance) {}); err != nil {
			return InstanceKey{}, err
		}
	}
	// An index allocated for a key that then isn't recorded stays
	// reserved, as every allocated index does: it's never reused.
	if ik.Status, err = p.allocateStatus(ctx, ik.CreatedAt); err != nil {
		return InstanceKey{}, err
	}
	ik.RetainUntil = p.retainUntil(p.periodStart(ik.CreatedAt))
	switch err := p.deps.InstanceKeys.Create(ctx, ik); {
	case errors.Is(err, ErrExists):
		// Recorded meanwhile, by a concurrent request: this instance's
		// keeps its record, another's is refused.
		stored, err := p.deps.InstanceKeys.Get(ctx, ik.Thumbprint)
		switch {
		case err != nil:
			return InstanceKey{}, fmt.Errorf("walletprovider: reading instance key: %w", err)
		case stored.InstanceID != in.ID:
			return InstanceKey{}, fmt.Errorf("%w: the instance key is another instance's", ErrInstanceKeyRegistered)
		}
		return stored, nil
	case err != nil:
		return InstanceKey{}, fmt.Errorf("walletprovider: storing the instance key: %w", err)
	}
	return ik, nil
}

// checkInstanceKey refuses an instance key of in at a security level
// the Policy no longer accepts for in's platform.
func (p *Provider) checkInstanceKey(in Instance, ik InstanceKey) error {
	if !slices.Contains(p.cfg.Policy.Platforms[in.Evidence.Platform].SecurityLevels, ik.SecurityLevel) {
		return fmt.Errorf("%w: the instance key's security level %q isn't accepted for %q", ErrPolicy, ik.SecurityLevel, in.Evidence.Platform)
	}
	return nil
}

// recordedInstanceKey returns the instance key pub of in, refusing a
// key not recorded for in with ErrUnknownInstanceKey, or one the
// Policy no longer accepts.
func (p *Provider) recordedInstanceKey(ctx context.Context, in Instance, pub crypto.PublicKey) (InstanceKey, error) {
	key, err := marshalKey(pub)
	if err != nil {
		return InstanceKey{}, fmt.Errorf("the instance key: %w", err)
	}
	ik, err := p.deps.InstanceKeys.Get(ctx, key.thumbprint)
	switch {
	case errors.Is(err, ErrNotFound):
		return InstanceKey{}, ErrUnknownInstanceKey
	case err != nil:
		return InstanceKey{}, fmt.Errorf("walletprovider: reading instance key: %w", err)
	case ik.InstanceID != in.ID:
		// The same refusal as for an unknown key: whose it is isn't
		// this instance's business.
		return InstanceKey{}, ErrUnknownInstanceKey
	}
	return ik, p.checkInstanceKey(in, ik)
}

// recordUse updates the instance in with count, only while it's still
// active, and stores counter, if set, as its new counter with a
// compare-and-swap against the one the verifier was given (in's), so
// a replayed or concurrent assertion gets nothing.
func (p *Provider) recordUse(ctx context.Context, in Instance, counter *uint64, count func(*Instance)) error {
	return p.update(ctx, in.ID, func(cur *Instance) error {
		if err := stateError(cur.State); err != nil {
			return err
		}
		if counter != nil {
			if cur.Counter != in.Counter {
				return fmt.Errorf("%w: the instance's counter changed while its assertion was verified", ErrEvidenceRejected)
			}
			cur.Counter = *counter
		}
		count(cur)
		return nil
	})
}

// KeyAttestationRequest asks for a Key Attestation over holder keys.
// The HTTP layer has already checked the request was signed with the
// instance's registration key (VerifyRequest).
type KeyAttestationRequest struct {
	InstanceID string

	// InstanceKey is the instance key of the issuance the holder keys
	// are for, which a Wallet Attestation recorded for the instance: the
	// Key Attestation's status is the instance key's. REQUIRED.
	InstanceKey crypto.PublicKey

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
// evidence the Policy still accepts, for the issuance of one of its
// instance keys (ErrUnknownInstanceKey for a key a Wallet Attestation
// didn't record for the instance, or whose record retention deleted:
// Config.InstanceKeyRetention). It consumes the challenge and
// verifies each piece of evidence; evidence must be of the Kind the
// instance registered with, from its platform and app. attested_keys
// lists only the keys some evidence that passed vouches for at a
// security level the Policy accepts — a key without one is left out, and the request fails with
// ErrNoKeyAttested if that leaves none. key_storage and
// user_authentication come from Policy.KeyStorage alone. status is the
// instance key's status list entry, on the current period's lists as a
// Wallet Attestation's is, so suspending or revoking the instance
// withdraws its Key Attestations too. It expires after
// Config.KeyAttestationTTL.
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
	ik, err := p.recordedInstanceKey(ctx, in, req.InstanceKey)
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

	// The instance key moves to the current period's lists, and the
	// instance is updated, before the attestation is issued, and only
	// while it's still active, its counter stored first.
	now := p.now()
	if ik, err = p.inCurrentPeriod(ctx, ik, now); err != nil {
		return KeyAttestationResult{}, err
	}
	if err := p.recordUse(ctx, in, counter, func(cur *Instance) {
		cur.LastSeenAt = now
		cur.KeyAttestations++
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
		Nonce: req.Nonce, Status: ik.Status.Claim(),
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
// assertion advanced it. Evidence that fails, is of another Kind than
// the instance registered with, or comes from another platform or app
// than the instance's, vouches for nothing; a key its evidence places
// at a security level the Policy refuses is left out.
func (p *Provider) verifyHolderKeys(ctx context.Context, in Instance, challenge []byte, req KeyAttestationRequest) ([]AttestedKey, *uint64, error) {
	var vouched []AttestedKey
	var counter *uint64
	var lastErr error
	for _, e := range req.Evidence {
		ev, err := p.verify(ctx, EvidenceInput{Evidence: e, Challenge: challenge, Purpose: PurposeHolder, Keys: req.Keys, Instance: &in})
		if err == nil {
			err = p.checkEvidenceFrom(in, e.Kind, ev)
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

// checkEvidenceFrom refuses evidence of kind sent after registration —
// for holder keys or an instance key — of another Kind than the
// instance registered with, from another platform or app than the
// instance's, or that the Policy refuses. The Kind is checked as well
// as the platform: another verifier for the same platform would skip
// the checks the instance's own makes, such as App Attest's counter.
func (p *Provider) checkEvidenceFrom(in Instance, kind string, ev VerifiedEvidence) error {
	if kind != in.Evidence.Kind {
		return fmt.Errorf("%w: %q evidence for an instance registered with %q", ErrEvidenceRejected, kind, in.Evidence.Kind)
	}
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

package walletprovider

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// RegisterRequest asks to register a wallet instance.
type RegisterRequest struct {
	// Challenge is a challenge issued for PurposeInstance, which the
	// evidence is bound to.
	Challenge string

	// InstanceKey is the instance key: P-256 or Ed25519.
	InstanceKey crypto.PublicKey

	// Evidence is the platform evidence for the instance key. REQUIRED.
	Evidence Evidence
}

// Register registers a wallet instance: it consumes the challenge,
// verifies the evidence with the EvidenceVerifier for its Kind,
// requires it to vouch for the instance key, applies the Policy,
// reserves the instance's status list index, and stores the instance,
// active.
func (p *Provider) Register(ctx context.Context, req RegisterRequest) (Instance, error) {
	key, err := marshalKey(req.InstanceKey)
	if err != nil {
		return Instance{}, err
	}
	if req.Evidence.Kind == "" || len(req.Evidence.Data) == 0 {
		return Instance{}, ErrEvidenceRequired
	}
	challenge, err := p.consumeChallenge(ctx, req.Challenge, PurposeInstance)
	if err != nil {
		return Instance{}, err
	}
	ev, err := p.verify(ctx, EvidenceInput{
		Evidence: req.Evidence, Challenge: challenge, Purpose: PurposeInstance,
		Keys: []crypto.PublicKey{req.InstanceKey},
	})
	if err != nil {
		return Instance{}, err
	}
	attested, ok := attestedKey(ev.Keys, req.InstanceKey)
	if !ok {
		return Instance{}, fmt.Errorf("%w: the evidence doesn't vouch for the instance key", ErrEvidenceRejected)
	}

	now := p.now()
	in := Instance{
		KeyThumbprint: key.thumbprint, Key: key.json,
		Evidence: EvidenceSummary{
			Kind: req.Evidence.Kind, Platform: ev.Platform,
			SecurityLevel: attested.SecurityLevel, Binding: attested.Binding,
			AppID: ev.AppID, AppVersion: ev.AppVersion, BootState: ev.BootState, DeviceLocked: ev.DeviceLocked,
		},
		Credential: slices.Clone(ev.Credential),
		State:      StateActive, CreatedAt: now, LastSeenAt: now,
	}
	if ev.Counter != nil {
		in.Counter = *ev.Counter
	}
	if err := p.cfg.Policy.checkInstance(in); err != nil {
		return Instance{}, err
	}
	if in.ID, err = randomID(p.deps.Random); err != nil {
		return Instance{}, err
	}
	// An index allocated for a registration that then fails stays
	// reserved, as every allocated index does: it's never reused.
	if in.Status, err = p.allocator.Allocate(ctx); err != nil {
		if errors.Is(err, statuslist.ErrListsFull) {
			return Instance{}, fmt.Errorf("walletprovider: the status list is full: raise Config.StatusListSize: %w", err)
		}
		return Instance{}, fmt.Errorf("walletprovider: allocating a status index: %w", err)
	}
	if err := p.deps.Instances.Create(ctx, in); err != nil {
		return Instance{}, fmt.Errorf("walletprovider: storing the instance: %w", err)
	}
	in.Revision = 1
	return in, nil
}

// verify runs the EvidenceVerifier for in.Evidence's Kind and checks
// what it returns is well-formed: a platform, and only keys it was
// asked about, each with a security level and binding.
func (p *Provider) verify(ctx context.Context, in EvidenceInput) (VerifiedEvidence, error) {
	v, ok := p.verifiers[in.Evidence.Kind]
	if !ok {
		return VerifiedEvidence{}, fmt.Errorf("%w: %q", ErrEvidenceKind, in.Evidence.Kind)
	}
	ev, err := v.Verify(ctx, in)
	if err != nil {
		return VerifiedEvidence{}, fmt.Errorf("%w: %w", ErrEvidenceRejected, err)
	}
	if ev.Platform == "" {
		return VerifiedEvidence{}, fmt.Errorf("walletprovider: the %q verifier reported no platform", in.Evidence.Kind)
	}
	for _, k := range ev.Keys {
		switch {
		case !slices.ContainsFunc(in.Keys, func(want crypto.PublicKey) bool { return certchain.SameKey(want, k.Key) }):
			return VerifiedEvidence{}, fmt.Errorf("walletprovider: the %q verifier reported a key it wasn't asked about", in.Evidence.Kind)
		case k.SecurityLevel == "":
			return VerifiedEvidence{}, fmt.Errorf("walletprovider: the %q verifier reported a key without a security level", in.Evidence.Kind)
		case k.Binding != KeyBindingAttested && k.Binding != KeyBindingAppAssertion:
			return VerifiedEvidence{}, fmt.Errorf("walletprovider: the %q verifier reported a key with binding %q", in.Evidence.Kind, k.Binding)
		}
	}
	return ev, nil
}

// attestedKey returns the entry of keys for pub.
func attestedKey(keys []AttestedKey, pub crypto.PublicKey) (AttestedKey, bool) {
	i := slices.IndexFunc(keys, func(k AttestedKey) bool { return certchain.SameKey(k.Key, pub) })
	if i < 0 {
		return AttestedKey{}, false
	}
	return keys[i], true
}

type marshaledKey struct {
	json       json.RawMessage
	thumbprint string
}

// marshalKey encodes pub as a public JWK and its thumbprint, refusing a
// key type the attestations can't carry.
func marshalKey(pub crypto.PublicKey) (marshaledKey, error) {
	if pub == nil {
		return marshaledKey{}, fmt.Errorf("%w: a key is required", ErrInvalidRequest)
	}
	k, err := jwk.Marshal(pub)
	if err != nil {
		return marshaledKey{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	raw, err := json.Marshal(k)
	if err != nil {
		return marshaledKey{}, fmt.Errorf("walletprovider: marshal jwk: %w", err)
	}
	thumbprint, err := k.Thumbprint()
	if err != nil {
		return marshaledKey{}, fmt.Errorf("%w: %w", ErrInvalidRequest, err)
	}
	return marshaledKey{json: raw, thumbprint: thumbprint}, nil
}

// randomID returns 16 random bytes, base64url.
func randomID(r io.Reader) (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(r, raw); err != nil {
		return "", fmt.Errorf("walletprovider: generating an ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

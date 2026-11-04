// Package walletprovidertest helps test code built on walletprovider:
// contract tests any InstanceStore and ChallengeStore implementation
// must pass, and FakeVerifier, an EvidenceVerifier for tests and
// emulators.
package walletprovidertest

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// FakeKind is FakeVerifier's Kind when its KindName is empty.
const FakeKind = "fake"

// FakePlatform is the Platform FakeVerifier reports when its Result
// names none.
const FakePlatform walletprovider.Platform = "fake"

// FakeVerifier is an EvidenceVerifier for tests and emulators. NEVER
// USE IT IN PRODUCTION: its evidence (FakeEvidence) is a JSON document
// anyone can write, naming the challenge and the keys, and it reports
// whatever Result and the key fields say, so a provider configured with
// it attests any key for anyone. It exists so tests can drive
// registration and attestation without a device, while the provider
// itself keeps refusing requests with no evidence.
type FakeVerifier struct {
	// KindName is its Kind; empty means FakeKind.
	KindName string

	// Result is what it reports for evidence that names the challenge:
	// its Platform (empty means FakePlatform), AppID, AppVersion,
	// BootState and DeviceLocked. Keys, Credential and Counter are
	// ignored.
	Result walletprovider.VerifiedEvidence

	// SecurityLevel, Binding and UserAuthentication are what it reports
	// for each key the evidence names; empty SecurityLevel means
	// SecurityLevelSoftware and empty Binding KeyBindingAttested.
	SecurityLevel      walletprovider.SecurityLevel
	Binding            walletprovider.KeyBinding
	UserAuthentication walletprovider.UserAuthentication
}

var _ walletprovider.EvidenceVerifier = FakeVerifier{}

// Kind implements walletprovider.EvidenceVerifier.
func (v FakeVerifier) Kind() string {
	if v.KindName == "" {
		return FakeKind
	}
	return v.KindName
}

// fakeEvidence is FakeEvidence's Data.
type fakeEvidence struct {
	Challenge string   `json:"challenge"`
	Keys      []string `json:"keys"` // RFC 7638 thumbprints
	Counter   *uint64  `json:"counter,omitempty"`
}

// FakeEvidence is evidence of kind (a FakeVerifier's Kind) over the
// challenge's Value, vouching for keys.
func FakeEvidence(kind, challenge string, keys ...crypto.PublicKey) (walletprovider.Evidence, error) {
	return fake(kind, fakeEvidence{Challenge: challenge}, keys)
}

// FakeAssertion is like FakeEvidence, but also advances the instance's
// signature counter to counter, as an App Attest assertion does: the
// provider refuses it unless counter exceeds the instance's.
func FakeAssertion(kind, challenge string, counter uint64, keys ...crypto.PublicKey) (walletprovider.Evidence, error) {
	return fake(kind, fakeEvidence{Challenge: challenge, Counter: &counter}, keys)
}

func fake(kind string, ev fakeEvidence, keys []crypto.PublicKey) (walletprovider.Evidence, error) {
	for _, k := range keys {
		tp, err := thumbprint(k)
		if err != nil {
			return walletprovider.Evidence{}, err
		}
		ev.Keys = append(ev.Keys, tp)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return walletprovider.Evidence{}, fmt.Errorf("walletprovidertest: %w", err)
	}
	return walletprovider.Evidence{Kind: kind, Data: data}, nil
}

// Verify implements walletprovider.EvidenceVerifier: the evidence must
// name in.Challenge, and vouches for the keys of in.Keys it names.
func (v FakeVerifier) Verify(_ context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	var ev fakeEvidence
	if err := json.Unmarshal(in.Evidence.Data, &ev); err != nil {
		return walletprovider.VerifiedEvidence{}, fmt.Errorf("walletprovidertest: fake evidence: %w", err)
	}
	challenge, err := base64.RawURLEncoding.DecodeString(ev.Challenge)
	if err != nil || subtle.ConstantTimeCompare(challenge, in.Challenge) != 1 {
		return walletprovider.VerifiedEvidence{}, errors.New("walletprovidertest: fake evidence for another challenge")
	}
	out := v.Result
	out.Keys, out.Credential, out.Counter = nil, nil, ev.Counter
	if out.Platform == "" {
		out.Platform = FakePlatform
	}
	for _, k := range in.Keys {
		tp, err := thumbprint(k)
		if err != nil {
			return walletprovider.VerifiedEvidence{}, err
		}
		if slices.Contains(ev.Keys, tp) {
			out.Keys = append(out.Keys, walletprovider.AttestedKey{
				Key: k, SecurityLevel: v.securityLevel(), Binding: v.binding(), UserAuthentication: v.UserAuthentication,
			})
		}
	}
	if len(out.Keys) == 0 {
		return walletprovider.VerifiedEvidence{}, errors.New("walletprovidertest: fake evidence names none of the keys")
	}
	return out, nil
}

func (v FakeVerifier) securityLevel() walletprovider.SecurityLevel {
	if v.SecurityLevel == "" {
		return walletprovider.SecurityLevelSoftware
	}
	return v.SecurityLevel
}

func (v FakeVerifier) binding() walletprovider.KeyBinding {
	if v.Binding == "" {
		return walletprovider.KeyBindingAttested
	}
	return v.Binding
}

func thumbprint(pub crypto.PublicKey) (string, error) {
	raw, err := jwk.Thumbprint(pub)
	if err != nil {
		return "", fmt.Errorf("walletprovidertest: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

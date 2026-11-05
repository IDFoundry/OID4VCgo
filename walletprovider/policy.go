package walletprovider

import (
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/attestation"
)

// DefaultMaxKeys is the Policy.MaxKeys used when it's zero.
const DefaultMaxKeys = 10

// Policy decides what verified evidence the provider attests for. It
// is applied when an instance registers, to an instance key's evidence
// and each Key Attestation request's, and again to the instance's
// registration evidence and the instance key's security level at
// every attestation, so tightening it refuses existing instances too.
type Policy struct {
	// Platforms holds each accepted platform's requirements. Evidence
	// from a platform not in it is refused. At least one is REQUIRED.
	Platforms map[Platform]PlatformPolicy

	// KeyStorage decides a Key Attestation's key_storage and
	// user_authentication claims (OID4VCI 1.0 Appendix D.2): see
	// KeyStorageRule. Empty claims neither for any key.
	KeyStorage []KeyStorageRule

	// MaxKeys is how many keys one Key Attestation request may name;
	// zero means DefaultMaxKeys.
	MaxKeys int
}

// PlatformPolicy is what the provider requires of one platform's
// evidence.
type PlatformPolicy struct {
	// SecurityLevels are the security levels accepted for a
	// registration key, instance keys and holder keys. At least one is
	// REQUIRED.
	SecurityLevels []SecurityLevel

	// MinAppVersion, if set, is the lowest app version accepted.
	// Evidence that reports no version (App Attest) is then refused.
	MinAppVersion uint64

	// RequireVerifiedBoot refuses evidence whose device didn't boot
	// verified with a locked bootloader, and evidence that doesn't say.
	RequireVerifiedBoot bool
}

// KeyStorageRule is a row of Policy.KeyStorage: for a key whose
// verified evidence matches it, the key_storage and user_authentication
// values a Key Attestation may claim. A Key Attestation claims a value
// only if the first matching rule of each key it attests lists it, so
// list every level a key resists ("iso_18045_high" and the lower ones)
// for an attestation over keys of different levels to claim the levels
// they share. A key no rule matches leaves both claims out.
type KeyStorageRule struct {
	// Platform and SecurityLevel are the key's. REQUIRED.
	Platform      Platform
	SecurityLevel SecurityLevel

	// Binding is how the evidence vouched for the key; empty means
	// KeyBindingAttested. A key an app assertion vouched for (App
	// Attest) matches only a rule naming KeyBindingAppAssertion: that
	// rule is the integrator's explicit decision that a genuine app's
	// Secure Enclave keys may be claimed at a level, which no evidence
	// proves for the key itself.
	Binding KeyBinding

	// UserAuthentication, if set, is the user authentication the key's
	// evidence must show; empty matches any key, and then
	// UserAuthenticationLevels must be empty too.
	UserAuthentication UserAuthentication

	// KeyStorage and UserAuthenticationLevels are the values claimed.
	// At least one of them is REQUIRED.
	KeyStorage               []attestation.AttackPotentialResistance
	UserAuthenticationLevels []attestation.AttackPotentialResistance
}

func (r KeyStorageRule) binding() KeyBinding {
	if r.Binding == "" {
		return KeyBindingAttested
	}
	return r.Binding
}

func (r KeyStorageRule) matches(platform Platform, k AttestedKey) bool {
	return r.Platform == platform && r.SecurityLevel == k.SecurityLevel && r.binding() == k.Binding &&
		(r.UserAuthentication == "" || r.UserAuthentication == k.UserAuthentication)
}

func (p Policy) maxKeys() int {
	if p.MaxKeys == 0 {
		return DefaultMaxKeys
	}
	return p.MaxKeys
}

func (p Policy) validate() error {
	if len(p.Platforms) == 0 {
		return errors.New("Policy.Platforms needs at least one platform")
	}
	for name, pp := range p.Platforms {
		if name == "" {
			return errors.New("Policy.Platforms has an empty platform name")
		}
		if len(pp.SecurityLevels) == 0 {
			return fmt.Errorf("Policy.Platforms[%q].SecurityLevels needs at least one level", name)
		}
		if slices.Contains(pp.SecurityLevels, "") {
			return fmt.Errorf("Policy.Platforms[%q].SecurityLevels has an empty level", name)
		}
	}
	if p.MaxKeys < 0 {
		return fmt.Errorf("Policy.MaxKeys is %d, negative", p.MaxKeys)
	}
	for i, r := range p.KeyStorage {
		switch {
		case r.Platform == "" || r.SecurityLevel == "":
			return fmt.Errorf("Policy.KeyStorage[%d] needs a Platform and a SecurityLevel", i)
		case r.Binding != "" && r.Binding != KeyBindingAttested && r.Binding != KeyBindingAppAssertion:
			return fmt.Errorf("Policy.KeyStorage[%d].Binding %q is unknown", i, r.Binding)
		case len(r.KeyStorage) == 0 && len(r.UserAuthenticationLevels) == 0:
			return fmt.Errorf("Policy.KeyStorage[%d] claims nothing", i)
		case r.UserAuthentication == "" && len(r.UserAuthenticationLevels) > 0:
			return fmt.Errorf("Policy.KeyStorage[%d] claims user_authentication without requiring any UserAuthentication of the key", i)
		case slices.Contains(r.KeyStorage, "") || slices.Contains(r.UserAuthenticationLevels, ""):
			return fmt.Errorf("Policy.KeyStorage[%d] lists an empty value", i)
		}
	}
	return nil
}

// checkEvidence applies the policy for ev's platform to its app version
// and root of trust.
func (p Policy) checkEvidence(platform Platform, appVersion uint64, boot BootState, locked bool) (PlatformPolicy, error) {
	pp, ok := p.Platforms[platform]
	switch {
	case !ok:
		return PlatformPolicy{}, fmt.Errorf("%w: platform %q isn't accepted", ErrPolicy, platform)
	case pp.MinAppVersion != 0 && appVersion < pp.MinAppVersion:
		if appVersion == 0 {
			return PlatformPolicy{}, fmt.Errorf("%w: the evidence reports no app version, and %q requires at least %d", ErrPolicy, platform, pp.MinAppVersion)
		}
		return PlatformPolicy{}, fmt.Errorf("%w: app version %d is below %q's minimum %d", ErrPolicy, appVersion, platform, pp.MinAppVersion)
	case pp.RequireVerifiedBoot && (boot != BootStateVerified || !locked):
		return PlatformPolicy{}, fmt.Errorf("%w: the device didn't boot verified with a locked bootloader (boot state %q, locked %t)", ErrPolicy, boot, locked)
	}
	return pp, nil
}

// checkInstance applies the policy to an instance's registration
// evidence.
func (p Policy) checkInstance(in Instance) error {
	e := in.Evidence
	pp, err := p.checkEvidence(e.Platform, e.AppVersion, e.BootState, e.DeviceLocked)
	if err != nil {
		return err
	}
	if !slices.Contains(pp.SecurityLevels, e.SecurityLevel) {
		return fmt.Errorf("%w: the registration key's security level %q isn't accepted for %q", ErrPolicy, e.SecurityLevel, e.Platform)
	}
	return nil
}

// claims returns the key_storage and user_authentication values a Key
// Attestation over keys, all from platform, may claim: the values the
// first matching rule of every key lists.
func (p Policy) claims(platform Platform, keys []AttestedKey) (keyStorage, userAuth []attestation.AttackPotentialResistance) {
	for i, k := range keys {
		idx := slices.IndexFunc(p.KeyStorage, func(r KeyStorageRule) bool { return r.matches(platform, k) })
		if idx < 0 {
			return nil, nil
		}
		r := p.KeyStorage[idx]
		if i == 0 {
			keyStorage, userAuth = slices.Clone(r.KeyStorage), slices.Clone(r.UserAuthenticationLevels)
			continue
		}
		keyStorage = intersect(keyStorage, r.KeyStorage)
		userAuth = intersect(userAuth, r.UserAuthenticationLevels)
	}
	return nonEmpty(keyStorage), nonEmpty(userAuth)
}

func intersect[T comparable](a, b []T) []T {
	return slices.DeleteFunc(a, func(v T) bool { return !slices.Contains(b, v) })
}

func nonEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}
	return s
}

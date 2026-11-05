package androidkey

import (
	"encoding/asn1"
	"fmt"
	"slices"
)

// ExtensionOID is the object identifier of the Android Key Attestation
// certificate extension, whose value is a KeyDescription.
var ExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// KnownAttestationVersions are the attestation schema versions this
// package was written against: 1 to 4 for Keymaster 2.0, 3.0, 4.0 and
// 4.1, then 100, 200, 300, 400 and 500 for KeyMint 1.0 to 5.0. Each
// version only adds AuthorizationList fields, so a later version parses
// too: its new fields are skipped. Version 500 adds mlDsaVariant ([11]),
// for ML-DSA keys, which this package skips: a Verifier accepts EC keys
// alone. Verifier.MinAttestationVersion sets the oldest one a Verifier
// takes.
var KnownAttestationVersions = []int{1, 2, 3, 4, 100, 200, 300, 400, 500}

// MaxExtensionBytes bounds the key description extension's value.
const MaxExtensionBytes = 8 << 10

// maxVersion bounds the attestation and KeyMint versions, far past any
// that exists, so a version always fits an int.
const maxVersion = 1 << 20

// MaxChallengeBytes is the longest attestation challenge Android
// Keystore accepts.
const MaxChallengeBytes = 128

// SecurityLevel is where Android says a key, or its attestation, lives.
type SecurityLevel int

// SecurityLevel values, as KeyDescription's SecurityLevel ENUMERATED
// numbers them.
const (
	Software           SecurityLevel = 0
	TrustedEnvironment SecurityLevel = 1
	StrongBox          SecurityLevel = 2
)

// Hardware reports whether l is the TEE or StrongBox.
func (l SecurityLevel) Hardware() bool { return l == TrustedEnvironment || l == StrongBox }

func (l SecurityLevel) String() string {
	return enumName(int64(l), "SecurityLevel", "Software", "TrustedEnvironment", "StrongBox")
}

// VerifiedBootState is the device's boot state as its bootloader
// reported it to the secure hardware.
type VerifiedBootState int

// VerifiedBootState values: Verified is a locked bootloader booting the
// manufacturer's signed image; SelfSigned a locked bootloader booting
// an image signed with a user-installed key (VerifiedBootKey names it);
// Unverified an unlocked bootloader; Failed a failed verification.
const (
	Verified   VerifiedBootState = 0
	SelfSigned VerifiedBootState = 1
	Unverified VerifiedBootState = 2
	Failed     VerifiedBootState = 3
)

func (s VerifiedBootState) String() string {
	return enumName(int64(s), "VerifiedBootState", "Verified", "SelfSigned", "Unverified", "Failed")
}

func enumName(v int64, typ string, names ...string) string {
	if v >= 0 && v < int64(len(names)) {
		return names[v]
	}
	return fmt.Sprintf("%s(%d)", typ, v)
}

// KeyDescription is the attestation extension's content: the
// KeyDescription SEQUENCE Android documents at
// https://source.android.com/docs/security/features/keystore/attestation#schema.
type KeyDescription struct {
	// AttestationVersion is the schema version (KnownAttestationVersions).
	AttestationVersion int
	// AttestationSecurityLevel is where the attestation was made.
	AttestationSecurityLevel SecurityLevel
	// KeyMintVersion is the Keymaster or KeyMint implementation's
	// version (keymasterVersion before KeyMint).
	KeyMintVersion int
	// KeyMintSecurityLevel is where the key lives.
	KeyMintSecurityLevel SecurityLevel
	// AttestationChallenge is the challenge the app gave Keystore.
	AttestationChallenge []byte
	// UniqueID is the privacy-sensitive per-device ID, empty unless a
	// system app asked for it.
	UniqueID []byte
	// SoftwareEnforced holds what Android's software enforces, or
	// merely reports: the app's identity is here.
	SoftwareEnforced AuthorizationList
	// HardwareEnforced holds what the TEE or StrongBox enforces.
	HardwareEnforced AuthorizationList
}

// ParseKeyDescription parses der, the attestation extension's value.
// Malformed input is an error wrapping ErrMalformed; it never panics.
func ParseKeyDescription(der []byte) (*KeyDescription, error) {
	kd, err := parseKeyDescription(der)
	if err != nil {
		return nil, fmt.Errorf("%w: key description: %w", ErrMalformed, err)
	}
	return kd, nil
}

func parseKeyDescription(der []byte) (*KeyDescription, error) {
	if len(der) > MaxExtensionBytes {
		return nil, fmt.Errorf("%d bytes, more than %d", len(der), MaxExtensionBytes)
	}
	top, err := single(der)
	if err != nil {
		return nil, err
	}
	f, err := constructed(top, asn1.TagSequence, "KeyDescription")
	if err != nil {
		return nil, err
	}
	if len(f) != 8 {
		return nil, fmt.Errorf("%d fields, want 8", len(f))
	}
	var kd KeyDescription
	var levels [2]SecurityLevel
	var versions [2]int
	for i, at := range [2]int{0, 2} {
		n, err := integer(f[at], asn1.TagInteger)
		if err != nil {
			return nil, fmt.Errorf("field %d: %w", at, err)
		}
		if n < 1 || n > maxVersion {
			return nil, fmt.Errorf("field %d: version %d", at, n)
		}
		versions[i] = int(n)
		if levels[i], err = securityLevel(f[at+1]); err != nil {
			return nil, fmt.Errorf("field %d: %w", at+1, err)
		}
	}
	kd.AttestationVersion, kd.KeyMintVersion = versions[0], versions[1]
	kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel = levels[0], levels[1]
	if kd.AttestationChallenge, err = octets(f[4]); err != nil {
		return nil, fmt.Errorf("attestationChallenge: %w", err)
	}
	if len(kd.AttestationChallenge) > MaxChallengeBytes {
		return nil, fmt.Errorf("a %d-byte challenge", len(kd.AttestationChallenge))
	}
	if kd.UniqueID, err = octets(f[5]); err != nil {
		return nil, fmt.Errorf("uniqueId: %w", err)
	}
	if kd.SoftwareEnforced, err = parseAuthorizationList(f[6]); err != nil {
		return nil, fmt.Errorf("softwareEnforced: %w", err)
	}
	if kd.HardwareEnforced, err = parseAuthorizationList(f[7]); err != nil {
		return nil, fmt.Errorf("hardwareEnforced: %w", err)
	}
	kd.AttestationChallenge = slices.Clone(kd.AttestationChallenge)
	kd.UniqueID = slices.Clone(kd.UniqueID)
	return &kd, nil
}

func securityLevel(v asn1.RawValue) (SecurityLevel, error) {
	n, err := integer(v, asn1.TagEnum)
	if err != nil {
		return 0, err
	}
	if n < int64(Software) || n > int64(StrongBox) {
		return 0, fmt.Errorf("unknown security level %d", n)
	}
	return SecurityLevel(n), nil
}

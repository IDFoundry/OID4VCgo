// Package androidattest verifies Android Key Attestation certificate
// chains for the passport-vdc demo's Wallet Provider: the chain Android
// Keystore gives for a key made with an attestation challenge
// (KeyGenParameterSpec.setAttestationChallenge), whose leaf carries the
// key description extension.
//
// It reads only what the demo's provider checks — the attestation
// version, both security levels and the challenge — not the
// authorization lists (the key's purposes, origin, root of trust, the
// app that made it), which a production Wallet Provider must check too:
// see the Kotlin library's Going to production guide. Nor does it
// consult Google's attestation status list for revoked certificates.
package androidattest

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// OID is the Android Key Attestation extension's object identifier,
// whose value is a KeyDescription.
var OID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel is where Android says a key, or its attestation, lives.
type SecurityLevel int

// The SecurityLevel values (KeyDescription's SecurityLevel ENUMERATED).
const (
	Software           SecurityLevel = 0
	TrustedEnvironment SecurityLevel = 1
	StrongBox          SecurityLevel = 2
)

// Hardware reports whether l is a hardware level: the TEE or StrongBox.
func (l SecurityLevel) Hardware() bool { return l == TrustedEnvironment || l == StrongBox }

func (l SecurityLevel) String() string {
	switch l {
	case Software:
		return "Software"
	case TrustedEnvironment:
		return "TrustedEnvironment"
	case StrongBox:
		return "StrongBox"
	}
	return fmt.Sprintf("SecurityLevel(%d)", int(l))
}

// KeyDescription is the part of the attestation extension the demo
// reads.
type KeyDescription struct {
	// AttestationVersion is the attestation schema's version: 1 to 4
	// for Keymaster 2.0 to 4.1, 100, 200, ... for KeyMint 1.0, 2.0, ...
	AttestationVersion int
	// AttestationSecurityLevel is where the attestation was made.
	AttestationSecurityLevel SecurityLevel
	// KeyMintSecurityLevel (keymasterSecurityLevel before KeyMint) is
	// where the key lives.
	KeyMintSecurityLevel SecurityLevel
	// AttestationChallenge is the challenge the key was made over.
	AttestationChallenge []byte
}

// maxChallenge is the longest challenge Android Keystore takes.
const maxChallenge = 128

// keyDescription is KeyDescription's ASN.1 form, as Android documents
// it (https://source.android.com/docs/security/features/keystore/attestation#schema):
//
//	KeyDescription ::= SEQUENCE {
//	    attestationVersion        INTEGER,
//	    attestationSecurityLevel  SecurityLevel,
//	    keyMintVersion            INTEGER,
//	    keyMintSecurityLevel      SecurityLevel,
//	    attestationChallenge      OCTET_STRING,
//	    uniqueId                  OCTET_STRING,
//	    softwareEnforced          AuthorizationList,
//	    hardwareEnforced          AuthorizationList,
//	}
//
// The authorization lists, SEQUENCEs of context-tagged fields, are kept
// raw: the demo doesn't read them.
type keyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

// ParseKeyDescription parses der, the attestation extension's value.
func ParseKeyDescription(der []byte) (KeyDescription, error) {
	var kd keyDescription
	rest, err := asn1.Unmarshal(der, &kd)
	if err != nil {
		return KeyDescription{}, fmt.Errorf("androidattest: key description: %w", err)
	}
	if len(rest) != 0 {
		return KeyDescription{}, errors.New("androidattest: key description: data after it")
	}
	if kd.AttestationVersion < 1 {
		return KeyDescription{}, fmt.Errorf("androidattest: key description: attestation version %d", kd.AttestationVersion)
	}
	levels := [2]SecurityLevel{}
	for i, l := range []asn1.Enumerated{kd.AttestationSecurityLevel, kd.KeyMintSecurityLevel} {
		if l < asn1.Enumerated(Software) || l > asn1.Enumerated(StrongBox) {
			return KeyDescription{}, fmt.Errorf("androidattest: key description: unknown security level %d", l)
		}
		levels[i] = SecurityLevel(l)
	}
	if len(kd.AttestationChallenge) > maxChallenge {
		return KeyDescription{}, fmt.Errorf("androidattest: key description: a %d-byte challenge", len(kd.AttestationChallenge))
	}
	for _, list := range []asn1.RawValue{kd.SoftwareEnforced, kd.HardwareEnforced} {
		if list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence || !list.IsCompound {
			return KeyDescription{}, errors.New("androidattest: key description: an authorization list isn't a SEQUENCE")
		}
	}
	return KeyDescription{
		AttestationVersion:       kd.AttestationVersion,
		AttestationSecurityLevel: levels[0],
		KeyMintSecurityLevel:     levels[1],
		AttestationChallenge:     kd.AttestationChallenge,
	}, nil
}

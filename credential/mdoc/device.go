package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/hkdf"
)

// DeviceAuthType identifies which of §12.4's two mdoc authentication
// mechanisms a DeviceSigned uses.
type DeviceAuthType int

const (
	// DeviceAuthSignature is ECDSA/EdDSA device authentication (§12.4.6).
	DeviceAuthSignature DeviceAuthType = iota + 1

	// DeviceAuthMAC is ECDH-agreed MAC device authentication (§12.4.5).
	DeviceAuthMAC
)

// DeviceSigned is §10.3.3's DeviceSigned: the Holder's own proof of
// possession of the mdoc authentication key, over a namespace/data
// element tree it discloses itself — distinct from IssuerSigned's
// namespaces, which the Issuer already committed to at issuance.
//
// SignDeviceSignature and ComputeDeviceMAC are DeviceSigned's real
// constructors, and — together with UnmarshalDeviceSigned — cache the
// exact DeviceNameSpacesBytes internally (nameSpacesBytes) the same
// way IssuerSigned caches rawItems, and for the same reason: a native
// Go map's encoding isn't stable across repeated calls, so Marshal
// must reuse the bytes that were actually authenticated rather than
// re-derive them. See IssuerSigned's own doc comment for the full
// rationale.
type DeviceSigned struct {
	NameSpaces map[string]map[string]interface{}
	DeviceAuth []byte // an encoded, detached COSE_Sign1 or COSE_Mac0 — see AuthType
	AuthType   DeviceAuthType

	nameSpacesBytes []byte
}

func (s DeviceSigned) deviceNameSpacesBytes() ([]byte, error) {
	if s.nameSpacesBytes != nil {
		return s.nameSpacesBytes, nil
	}
	b, err := wrapTag24(s.NameSpaces)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceNameSpacesBytes: %w", err)
	}
	return b, nil
}

// deviceAuthBytes is VerifyDeviceSignature/VerifyDeviceMAC's shared
// preamble: check s's AuthType matches want, and rebuild
// DeviceAuthenticationBytes from its cached (or re-derived — see
// deviceNameSpacesBytes) nameSpacesBytes.
func (s DeviceSigned) deviceAuthBytes(want DeviceAuthType, sessionTranscriptBytes []byte, docType string) ([]byte, error) {
	if s.AuthType != want {
		return nil, fmt.Errorf("mdoc: DeviceSigned.AuthType is %d, want %d", s.AuthType, want)
	}
	nameSpacesBytes, err := s.deviceNameSpacesBytes()
	if err != nil {
		return nil, err
	}
	return deviceAuthenticationBytes(sessionTranscriptBytes, docType, nameSpacesBytes)
}

// wireDeviceSigned is §10.3.3's own DeviceSigned CDDL:
//
//	DeviceSigned = {
//	    "nameSpaces" : DeviceNameSpacesBytes,
//	    "deviceAuth" : DeviceAuth,
//	}
type wireDeviceSigned struct {
	NameSpaces cbor.RawMessage `cbor:"nameSpaces"`
	DeviceAuth wireDeviceAuth  `cbor:"deviceAuth"`
}

// wireDeviceAuth is §12.4's DeviceAuth: exactly one of deviceSignature
// or deviceMac, per its CDDL's "//" (OR).
type wireDeviceAuth struct {
	DeviceSignature cbor.RawMessage `cbor:"deviceSignature,omitempty"`
	DeviceMac       cbor.RawMessage `cbor:"deviceMac,omitempty"`
}

// Marshal encodes s as §10.3.3's DeviceSigned CBOR map.
func (s DeviceSigned) Marshal() ([]byte, error) {
	nameSpacesBytes, err := s.deviceNameSpacesBytes()
	if err != nil {
		return nil, err
	}
	var auth wireDeviceAuth
	switch s.AuthType {
	case DeviceAuthSignature:
		auth.DeviceSignature = s.DeviceAuth
	case DeviceAuthMAC:
		auth.DeviceMac = s.DeviceAuth
	default:
		return nil, fmt.Errorf("mdoc: DeviceSigned.AuthType is %d, want DeviceAuthSignature or DeviceAuthMAC", s.AuthType)
	}
	wire := wireDeviceSigned{NameSpaces: nameSpacesBytes, DeviceAuth: auth}
	b, err := encMode.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("mdoc: marshal DeviceSigned: %w", err)
	}
	return b, nil
}

// UnmarshalDeviceSigned decodes data as §10.3.3's DeviceSigned CBOR
// map — Marshal's inverse. It performs no signature or MAC
// verification; use VerifyDeviceSignature or VerifyDeviceMAC for that.
func UnmarshalDeviceSigned(data []byte) (DeviceSigned, error) {
	var wire wireDeviceSigned
	if err := decMode.Unmarshal(data, &wire); err != nil {
		return DeviceSigned{}, fmt.Errorf("mdoc: unmarshal DeviceSigned: %w", err)
	}
	var nameSpaces map[string]map[string]interface{}
	if err := unwrapTag24(wire.NameSpaces, &nameSpaces); err != nil {
		return DeviceSigned{}, fmt.Errorf("mdoc: decode DeviceNameSpaces: %w", err)
	}
	switch {
	case len(wire.DeviceAuth.DeviceSignature) > 0:
		return DeviceSigned{
			NameSpaces: nameSpaces, DeviceAuth: []byte(wire.DeviceAuth.DeviceSignature),
			AuthType: DeviceAuthSignature, nameSpacesBytes: []byte(wire.NameSpaces),
		}, nil
	case len(wire.DeviceAuth.DeviceMac) > 0:
		return DeviceSigned{
			NameSpaces: nameSpaces, DeviceAuth: []byte(wire.DeviceAuth.DeviceMac),
			AuthType: DeviceAuthMAC, nameSpacesBytes: []byte(wire.NameSpaces),
		}, nil
	default:
		return DeviceSigned{}, fmt.Errorf("mdoc: deviceAuth has neither deviceSignature nor deviceMac")
	}
}

// deviceAuthenticationBytes builds DeviceAuthenticationBytes (§12.4.4:
// #6.24(bstr .cbor DeviceAuthentication)) — the detached content both
// DeviceSignature and DeviceMac authenticate.
//
// sessionTranscriptBytes is SessionTranscriptBytes (§12.7.1:
// #6.24(bstr .cbor SessionTranscript)) — an opaque, caller-supplied
// value; see the package doc comment for why building SessionTranscript
// itself (DeviceEngagement, EReaderKey, Handover) is out of scope here.
// This function unwraps its outer tag 24 to embed the bare
// SessionTranscript value where DeviceAuthentication's own CDDL
// requires it unwrapped — SessionTranscriptBytes' other use, as an
// HKDF salt input in deriveEMacKey, uses the tag-24-wrapped form
// directly instead. (§12.7.1's own note: "This document uses both
// SessionTranscript and SessionTranscriptBytes in cryptographic
// structures.")
func deviceAuthenticationBytes(sessionTranscriptBytes []byte, docType string, deviceNameSpacesBytes []byte) ([]byte, error) {
	var sessionTranscript cbor.RawMessage
	if err := unwrapTag24(sessionTranscriptBytes, &sessionTranscript); err != nil {
		return nil, fmt.Errorf("mdoc: unwrap SessionTranscriptBytes: %w", err)
	}
	deviceAuthentication := []interface{}{
		"DeviceAuthentication",
		sessionTranscript,
		docType,
		cbor.RawMessage(deviceNameSpacesBytes),
	}
	b, err := wrapTag24(deviceAuthentication)
	if err != nil {
		return nil, fmt.Errorf("mdoc: encode DeviceAuthenticationBytes: %w", err)
	}
	return b, nil
}

// deviceSignedInput is SignDeviceSignature/ComputeDeviceMAC's shared
// preparation: encode nameSpaces exactly once, so the same bytes are
// used both to authenticate and — via the returned DeviceSigned's
// nameSpacesBytes cache — to marshal.
func deviceSignedInput(
	sessionTranscriptBytes []byte, docType string, nameSpaces map[string]map[string]interface{},
) (nameSpacesBytes, authBytes []byte, err error) {
	nameSpacesBytes, err = wrapTag24(nameSpaces)
	if err != nil {
		return nil, nil, fmt.Errorf("mdoc: encode DeviceNameSpacesBytes: %w", err)
	}
	authBytes, err = deviceAuthenticationBytes(sessionTranscriptBytes, docType, nameSpacesBytes)
	if err != nil {
		return nil, nil, err
	}
	return nameSpacesBytes, authBytes, nil
}

// SignDeviceSignature builds DeviceSigned using ECDSA/EdDSA device
// authentication (§12.4.6): it computes DeviceAuthenticationBytes from
// sessionTranscriptBytes/docType/nameSpaces and signs it as a detached
// COSE_Sign1 via internal/cose, under signer's mdoc authentication
// private key (SDeviceKey.Priv).
func SignDeviceSignature(
	signer crypto.Signer, alg cose.Alg,
	sessionTranscriptBytes []byte, docType string,
	nameSpaces map[string]map[string]interface{},
) (DeviceSigned, error) {
	nameSpacesBytes, authBytes, err := deviceSignedInput(sessionTranscriptBytes, docType, nameSpaces)
	if err != nil {
		return DeviceSigned{}, err
	}

	// §12.4.6: "The 'external_aad' fields shall be a bytestring of
	// size zero."
	sig, err := cose.SignDetached(alg, signer, cose.Headers{}, cose.Headers{}, authBytes, []byte{})
	if err != nil {
		return DeviceSigned{}, fmt.Errorf("mdoc: sign DeviceSignature: %w", err)
	}

	return DeviceSigned{
		NameSpaces: nameSpaces, DeviceAuth: sig,
		AuthType: DeviceAuthSignature, nameSpacesBytes: nameSpacesBytes,
	}, nil
}

// VerifyDeviceSignature checks a DeviceSigned's ECDSA/EdDSA
// authentication against deviceKey — DeviceKeyInfo.DeviceKey from the
// already-verified MSO (VerifiedMSO.DeviceKey, from a prior call to
// Verify) — using the same sessionTranscriptBytes/docType the Holder
// authenticated over.
func VerifyDeviceSignature(
	signed DeviceSigned, deviceKey crypto.PublicKey, alg cose.Alg,
	sessionTranscriptBytes []byte, docType string,
) error {
	authBytes, err := signed.deviceAuthBytes(DeviceAuthSignature, sessionTranscriptBytes, docType)
	if err != nil {
		return err
	}
	if _, _, err := cose.VerifyDetached(alg, deviceKey, signed.DeviceAuth, authBytes, []byte{}); err != nil {
		return fmt.Errorf("mdoc: verify DeviceSignature: %w", err)
	}
	return nil
}

// ComputeDeviceMAC builds DeviceSigned using ECDH-agreed MAC device
// authentication (§12.4.5): it derives EMacKey from devicePriv
// (SDeviceKey.Priv) and readerPub (EReaderKey.Pub) via ECKA-DH and
// HKDF, then computes a detached COSE_Mac0 over DeviceAuthenticationBytes.
// Only P-256 is supported (see deriveEMacKey).
func ComputeDeviceMAC(
	devicePriv *ecdsa.PrivateKey, readerPub *ecdsa.PublicKey,
	sessionTranscriptBytes []byte, docType string,
	nameSpaces map[string]map[string]interface{},
) (DeviceSigned, error) {
	nameSpacesBytes, authBytes, err := deviceSignedInput(sessionTranscriptBytes, docType, nameSpaces)
	if err != nil {
		return DeviceSigned{}, err
	}

	key, err := deriveEMacKey(devicePriv, readerPub, sessionTranscriptBytes)
	if err != nil {
		return DeviceSigned{}, err
	}

	// §12.4.5: "The external_aad field...shall be a bytestring of size zero."
	mac0, err := cose.ComputeMAC(key, cose.Headers{}, cose.Headers{}, authBytes, []byte{})
	if err != nil {
		return DeviceSigned{}, fmt.Errorf("mdoc: compute DeviceMac: %w", err)
	}

	return DeviceSigned{
		NameSpaces: nameSpaces, DeviceAuth: mac0,
		AuthType: DeviceAuthMAC, nameSpacesBytes: nameSpacesBytes,
	}, nil
}

// VerifyDeviceMAC checks a DeviceSigned's ECDH-agreed MAC
// authentication: it re-derives EMacKey from readerPriv
// (EReaderKey.Priv) and deviceKey (DeviceKeyInfo.DeviceKey from the
// already-verified MSO, VerifiedMSO.DeviceKey — ECDH is symmetric, so
// this reproduces the same key ComputeDeviceMAC derived from the
// device's own private key and the reader's public key) and recomputes
// the MAC over the same sessionTranscriptBytes/docType.
func VerifyDeviceMAC(
	signed DeviceSigned, deviceKey *ecdsa.PublicKey, readerPriv *ecdsa.PrivateKey,
	sessionTranscriptBytes []byte, docType string,
) error {
	authBytes, err := signed.deviceAuthBytes(DeviceAuthMAC, sessionTranscriptBytes, docType)
	if err != nil {
		return err
	}
	key, err := deriveEMacKey(readerPriv, deviceKey, sessionTranscriptBytes)
	if err != nil {
		return err
	}
	if _, _, err := cose.VerifyMAC(key, signed.DeviceAuth, authBytes, []byte{}); err != nil {
		return fmt.Errorf("mdoc: verify DeviceMac: %w", err)
	}
	return nil
}

// deriveEMacKey computes §12.4.5's EMacKey: ECKA-DH (BSI TR-03111) —
// which, for the P-256 curve this package supports, is exactly Go's
// crypto/ecdh Unified Model shared secret (the SEC1 x-coordinate) —
// between priv and peerPub, then HKDF-SHA256 (RFC 5869, internal/hkdf)
// with salt=SHA-256(sessionTranscriptBytes), info="EMacKey", L=32
// octets. Only P-256 is supported: §12.4.5's own NOTE says MAC
// authentication "can only be used when the mdoc authentication key
// and the mdoc reader ephemeral key use the same curve," and this
// package's DeviceKey/COSE support (see CoseKey) is limited to P-256
// (EC2) and Ed25519 (OKP) — Ed25519 keys have no standard ECDH
// counterpart, so MAC authentication isn't available for them here.
func deriveEMacKey(priv *ecdsa.PrivateKey, peerPub *ecdsa.PublicKey, sessionTranscriptBytes []byte) ([]byte, error) {
	if priv.Curve != elliptic.P256() || peerPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("mdoc: DeviceMac requires P-256 keys (got %s and %s)", priv.Curve.Params().Name, peerPub.Curve.Params().Name)
	}
	ecdhPriv, err := priv.ECDH()
	if err != nil {
		return nil, fmt.Errorf("mdoc: convert private key to ECDH: %w", err)
	}
	ecdhPub, err := peerPub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("mdoc: convert peer public key to ECDH: %w", err)
	}
	z, err := ecdhPriv.ECDH(ecdhPub)
	if err != nil {
		return nil, fmt.Errorf("mdoc: ECDH key agreement: %w", err)
	}

	salt := sha256.Sum256(sessionTranscriptBytes)
	key, err := hkdf.Key(salt[:], z, []byte("EMacKey"), 32)
	if err != nil {
		return nil, fmt.Errorf("mdoc: derive EMacKey: %w", err)
	}
	return key, nil
}

// CheckKeyAuthorizations implements §12.8.2 step 1: every data element
// (or its whole namespace) disclosed in a DeviceSigned's NameSpaces
// must be covered by the mdoc authentication key's KeyAuthorizations,
// from the already-verified MSO's DeviceKeyInfo (§12.3.4) — "if any
// data elements are returned as part of DeviceSigned, verify that all
// those data elements or their namespace are included in the
// keyAuthorizations map in the DeviceKeyInfo map in the MSO." A nil
// auth (KeyAuthorizations absent) authorizes nothing, so any non-empty
// deviceNameSpaces is rejected in that case.
func CheckKeyAuthorizations(deviceNameSpaces map[string]map[string]interface{}, auth *KeyAuthorizations) error {
	for namespace, elements := range deviceNameSpaces {
		if len(elements) == 0 {
			continue
		}
		if auth == nil {
			return fmt.Errorf("mdoc: namespace %q is not authorized for the mdoc authentication key (no keyAuthorizations present)", namespace)
		}
		if containsString(auth.NameSpaces, namespace) {
			continue
		}
		authorizedElements := auth.DataElements[namespace]
		for identifier := range elements {
			if !containsString(authorizedElements, identifier) {
				return fmt.Errorf("mdoc: namespace %q element %q is not authorized for the mdoc authentication key", namespace, identifier)
			}
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

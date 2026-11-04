// Package cose implements small, self-contained COSE_Sign1 (RFC 9052
// §4.2) and COSE_Mac0 (RFC 9052 §6.2) signers/verifiers, used
// internally by credential/mdoc (IssuerAuth, DeviceSignature,
// DeviceMac — ISO/IEC 18013-5) and statuslist (CWT-encoded Status List
// Tokens).
//
// It signs and verifies with ES256 (P-256/SHA-256, COSE algorithm -7),
// ES384 (P-384/SHA-384, -35), ES512 (P-521/SHA-512, -36) and EdDSA
// (Ed25519, -8), RFC 9053 §2, each ECDSA algorithm with its own curve
// only; a header marked with the fully-specified ESP256 (-9), ESP384
// (-51) or ESP512 (-52) of RFC 9864 verifies as ES256, ES384 or ES512.
// ISO/IEC 18013-5 has an mdoc reader verify all of ES256, ES384, ES512
// and EdDSA (§9.1.2.4, §9.1.3.6, §9.1.4); AlgForKey picks the one a
// key verifies with. The brainpool curves and Ed448 it also lists
// aren't in Go's standard library, and aren't supported: a key on one
// is refused. internal/jose, for SD-JWT VC, stays at ES256 and EdDSA.
// HMAC256 ("HMAC 256/256", COSE algorithm 5, mac0.go) is the only MAC
// algorithm supported, since it's the only one mdoc's DeviceMac uses.
//
// This package only builds and verifies the COSE_Sign1/COSE_Mac0
// envelopes themselves — the four-element [protected, unprotected,
// payload, signature/tag] arrays RFC 9052 §4.2/§6.2 define.
// Sign/Verify/DecodeUnverified handle the untagged COSE_Sign1 form
// (mdoc's own CDDL, "IssuerAuth = COSE_Sign1", uses this form, not
// COSE_Sign1_Tagged); SignTagged/VerifyTagged/DecodeUnverifiedTagged
// handle #6.18(COSE_Sign1) instead, for a context that doesn't
// otherwise establish the bytes are a COSE_Sign1
// (draft-ietf-oauth-status-list-14 §5.2's CWT-format Status List Token
// uses the tagged form). SignDetached/VerifyDetached handle a detached
// COSE_Sign1 payload (mdoc's DeviceSignature, §12.4.6); ComputeMAC/
// VerifyMAC are COSE_Mac0's only form here, since mdoc's DeviceMac
// (§12.4.5) always uses a detached payload. It knows nothing about
// IssuerSigned, the Mobile Security Object, DeviceAuthentication,
// StatusList, or any other caller-specific CBOR structure, nor about
// key agreement (ComputeMAC/VerifyMAC take an already-derived HMAC key
// — deriving mdoc's EMacKey via ECKA-DH/HKDF is credential/mdoc's job)
// — those are credential/mdoc's and statuslist's job to define with
// their own CBOR struct tags on top of github.com/fxamacker/cbor/v2,
// the same layering credential/sdjwtvc uses on top of internal/jose
// (jose knows JWS, sdjwtvc knows SD-JWT VC's claims).
package cose

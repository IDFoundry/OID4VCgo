package walletprovider

import (
	"context"
	"crypto"
)

// Platform names the platform evidence comes from. PlatformAndroid and
// PlatformIOS are the two the provider's own verifiers report; an
// integrator's verifier may report another.
type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
)

// SecurityLevel is where verified evidence shows a key is held.
type SecurityLevel string

const (
	// SecurityLevelSoftware: the key is in software (an Android
	// attestation with software security level, an emulator).
	SecurityLevelSoftware SecurityLevel = "software"

	// SecurityLevelTEE: an Android key in a Trusted Execution
	// Environment.
	SecurityLevelTEE SecurityLevel = "tee"

	// SecurityLevelStrongBox: an Android key in a StrongBox secure
	// element.
	SecurityLevelStrongBox SecurityLevel = "strongbox"

	// SecurityLevelSecureEnclave: an Apple Secure Enclave key, as a
	// genuine copy of the app reports it. App Attest proves the app,
	// not where its other keys are (see KeyBindingAppAssertion).
	SecurityLevelSecureEnclave SecurityLevel = "secure-enclave"
)

// KeyBinding is how evidence vouches for a key.
type KeyBinding string

const (
	// KeyBindingAttested: the platform attested the key itself — an
	// Android Key Attestation chain whose leaf is the key.
	KeyBindingAttested KeyBinding = "attested"

	// KeyBindingAppAssertion: a genuine copy of the app, which the
	// platform attested (Apple App Attest), signed for the key. Nothing
	// proves the key itself is in hardware: HAIP's key_storage is
	// claimed for such a key only by a KeyStorageRule naming this
	// binding.
	KeyBindingAppAssertion KeyBinding = "app-assertion"
)

// UserAuthentication is what verified evidence shows gates a key's
// use. Empty means the evidence doesn't say.
type UserAuthentication string

const (
	// UserAuthenticationNone: the key can be used without the user
	// authenticating.
	UserAuthenticationNone UserAuthentication = "none"

	// UserAuthenticationRequired: each use of the key, or each use
	// within a short timeout, requires the user to authenticate (an
	// Android key with userAuthenticationRequired). The verifier
	// decides how short: androidkey.EvidenceVerifier.MaxAuthTimeout.
	UserAuthenticationRequired UserAuthentication = "required"
)

// BootState is a device's verified boot state, where evidence reports
// it (Android's root of trust). Empty means unknown.
type BootState string

const (
	BootStateVerified   BootState = "verified"
	BootStateSelfSigned BootState = "self-signed"
	BootStateUnverified BootState = "unverified"
	BootStateFailed     BootState = "failed"
)

// Evidence is platform evidence as a wallet sends it: its Kind names
// the EvidenceVerifier that reads Data, which is opaque here — an
// Android certificate chain, an App Attest attestation object or
// assertion.
type Evidence struct {
	Kind string
	Data []byte
}

// EvidenceInput is what an EvidenceVerifier checks evidence against.
type EvidenceInput struct {
	// Evidence is the evidence to verify.
	Evidence Evidence

	// Challenge is the challenge the evidence must be bound to: the raw
	// bytes Challenge.Value encodes, already consumed, so the verifier
	// needn't (and mustn't) consume it again.
	Challenge []byte

	// Purpose is what the challenge was issued for.
	Purpose Purpose

	// Keys are the keys the request asks the evidence to vouch for: the
	// registration key at registration, the instance key at its first
	// Wallet Attestation, the holder keys of a Key Attestation request.
	// Evidence that attests keys itself (Android)
	// reports which of them it covers; evidence over the app (App
	// Attest) binds them through its signed client data.
	Keys []crypto.PublicKey

	// Instance is the registered instance a later request comes from
	// (an instance key's or holder keys' evidence), nil at
	// registration: an App Attest verifier checks an assertion against
	// its Credential and Counter.
	Instance *Instance
}

// AttestedKey is one key verified evidence vouches for, and what it
// proves of it.
type AttestedKey struct {
	// Key is one of EvidenceInput.Keys.
	Key crypto.PublicKey

	// SecurityLevel is where the evidence shows the key is held.
	// REQUIRED.
	SecurityLevel SecurityLevel

	// Binding is how the evidence vouches for the key. REQUIRED: the
	// provider refuses evidence that leaves it empty, so a verifier
	// can't claim a key attested by forgetting to say otherwise.
	Binding KeyBinding

	// UserAuthentication is what the evidence proves gates the key's
	// use; empty when it doesn't say.
	UserAuthentication UserAuthentication
}

// VerifiedEvidence is what an EvidenceVerifier proved. Every field is
// from the evidence, never from what the app reports alongside it.
type VerifiedEvidence struct {
	// Platform is the platform the evidence is from. REQUIRED.
	Platform Platform

	// AppID identifies the app: an Android package name, an Apple App ID
	// (team ID and bundle ID). Empty when the evidence doesn't say.
	AppID string

	// AppVersion is the app's version as the evidence reports it (an
	// Android versionCode); zero when it doesn't, as App Attest doesn't.
	// A Policy minimum refuses evidence without one.
	AppVersion uint64

	// BootState and DeviceLocked are the device's root of trust, where
	// the evidence reports it (Android); BootState is empty when it
	// doesn't.
	BootState    BootState
	DeviceLocked bool

	// Keys are the keys of EvidenceInput.Keys the evidence vouches for.
	// A key not listed isn't attested.
	Keys []AttestedKey

	// Credential is state a verifier keeps for the instance from its
	// registration evidence (an App Attest public key and key ID), and
	// reads back from EvidenceInput.Instance on later requests. The
	// provider stores it in Instance.Credential at registration and
	// ignores it afterwards.
	Credential []byte

	// CredentialID, if set, identifies the credential Credential holds
	// (an App Attest key's key ID), which registers one instance only:
	// the provider stores it in Instance.CredentialID, and refuses a
	// registration whose CredentialID another instance has with
	// ErrInstanceKeyRegistered. It's an identifier no other credential,
	// of any Kind, has. Set only at registration; ignored afterwards.
	CredentialID string

	// Facts, if set, are what the verifier wants kept of the
	// registration evidence: the facts its checks rested on, in a
	// format of its own (androidkey's: the chain's certificate serial
	// numbers, the app's signing certificates, the patch level and the
	// root of trust). The provider stores them in Instance.EvidenceFacts
	// at registration and ignores them afterwards, so an operator can
	// find the instances whose evidence a later finding taints
	// (Provider.RevokeWhere), and an EvidenceRechecker can check them
	// again. Opaque here.
	Facts []byte

	// Counter, if set, is the instance's new signature counter (App
	// Attest). The provider stores it with a compare-and-swap against
	// the Counter the verifier was given, so two requests can't both
	// use one assertion; the verifier refuses an assertion whose
	// counter doesn't exceed Instance.Counter.
	Counter *uint64
}

// EvidenceVerifier verifies one Kind of platform evidence. Verify
// returns an error for evidence it can't verify, isn't bound to
// in.Challenge, or that a fresh challenge can't make fresh; the
// provider applies its Policy to what it returns.
//
// An Android Key Attestation verifier checks each key's chain to the
// attestation roots, its challenge and authorization lists, and returns
// the chain's leaf key with KeyBindingAttested. An Apple App Attest
// verifier checks the attestation object (registration) or an assertion
// (an instance key's or holder keys' evidence, against in.Instance) and
// returns in.Keys with KeyBindingAppAssertion; see the package doc
// comment.
type EvidenceVerifier interface {
	// Kind is the Evidence.Kind it reads ("android-key",
	// "apple-app-attest", ...). Each configured verifier's is distinct.
	Kind() string

	Verify(ctx context.Context, in EvidenceInput) (VerifiedEvidence, error)
}

// EvidenceRechecker is an EvidenceVerifier that can check a registered
// instance's evidence again: against what it knows now, such as a
// revocation list that has since named a certificate of the instance's
// chain, or a policy it has since been configured with. The provider
// calls Recheck with the instance, for the verifier of the Kind it
// registered with, before each Wallet Attestation and Key Attestation:
// Android Key Attestation evidence is verified only for a key the
// instance hasn't used before, so a recorded instance key would
// otherwise never be checked again. androidkey.EvidenceVerifier is
// one.
type EvidenceRechecker interface {
	EvidenceVerifier

	// Recheck checks in's registration evidence again, from what Verify
	// reported of it (Instance.EvidenceFacts; empty for an instance
	// registered before the provider kept them, which it then can't
	// check, and should accept). It returns nil to accept the instance,
	// an error wrapping ErrPolicy or ErrEvidenceRejected to refuse it,
	// and any other error when it couldn't check: the request then
	// fails as the provider's own failure. A refusal because the
	// evidence's issuer has revoked or suspended its attestation wraps
	// ErrEvidenceRevoked or ErrEvidenceSuspended too, and the provider
	// revokes or suspends the instance; any other refusal only refuses
	// the request, since the operator can undo what caused it.
	Recheck(ctx context.Context, in Instance) error
}

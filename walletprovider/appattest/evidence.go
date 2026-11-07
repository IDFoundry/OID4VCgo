package appattest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// EvidenceKind is the walletprovider.Evidence Kind an EvidenceVerifier
// reads.
const EvidenceKind = "apple-app-attest"

// Evidence is the walletprovider.Evidence for an attestation object
// (at registration) or an assertion (after it), the bytes
// DCAppAttestService returned, unchanged.
func Evidence(data []byte) walletprovider.Evidence {
	return walletprovider.Evidence{Kind: EvidenceKind, Data: data}
}

// EvidenceVerifier makes a Verifier a walletprovider.EvidenceVerifier
// for evidence of EvidenceKind. App Attest attests the app, not the
// wallet's keys, so the evidence binds the keys through its client
// data (ClientData) instead:
//
//   - at registration (walletprovider.PurposeRegistration), the
//     evidence is an attestation object of a new App Attest key, over
//     ClientDataHash of the registration challenge and the registration
//     key. Verify runs Verifier.VerifyAttestation and returns the
//     attested App Attest key, and its environment, as
//     VerifiedEvidence.Credential, with Counter 0, and its key ID
//     (base64, as DCAppAttestService gives it) as CredentialID, which
//     the provider stores in the Instance: it refuses a key ID another
//     instance registered with, so one App Attest key is one instance;
//   - after it — an instance key's first Wallet Attestation
//     (PurposeInstance), a Key Attestation (PurposeHolder) — the
//     evidence is an assertion by that App Attest key, over
//     ClientDataHash of the request's challenge and every key it
//     names, in its order. Verify runs Verifier.VerifyAssertion
//     against the Instance's Credential and Counter and returns the
//     assertion's counter, which the provider stores with a
//     compare-and-swap, so each assertion is accepted once.
//
// Either way it reports walletprovider.PlatformIOS, the App ID as
// AppID, no app version (App Attest has none: a Policy MinAppVersion
// refuses iOS evidence), no boot state, and every key of the request
// at SecurityLevelSecureEnclave with KeyBindingAppAssertion: a genuine
// copy of the app vouches for them, which proves nothing about where
// the keys themselves are. The provider's Policy claims key_storage
// for such a key only by a KeyStorageRule naming KeyBindingAppAssertion.
type EvidenceVerifier struct {
	// Verifier checks the attestation and assertions. REQUIRED.
	Verifier *Verifier
}

var _ walletprovider.EvidenceVerifier = EvidenceVerifier{}

// Kind implements walletprovider.EvidenceVerifier: EvidenceKind.
func (EvidenceVerifier) Kind() string { return EvidenceKind }

// Verify implements walletprovider.EvidenceVerifier.
func (e EvidenceVerifier) Verify(_ context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	if e.Verifier == nil {
		return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "EvidenceVerifier has no Verifier")
	}
	hash, err := ClientDataHash(in.Purpose, base64.RawURLEncoding.EncodeToString(in.Challenge), in.Keys)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	out := walletprovider.VerifiedEvidence{Platform: walletprovider.PlatformIOS}
	for _, k := range in.Keys {
		out.Keys = append(out.Keys, walletprovider.AttestedKey{
			Key: k, SecurityLevel: walletprovider.SecurityLevelSecureEnclave, Binding: walletprovider.KeyBindingAppAssertion,
		})
	}
	var counter uint64
	if in.Instance == nil {
		if in.Purpose != walletprovider.PurposeRegistration {
			return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "an attestation for purpose %q, without a registered instance", in.Purpose)
		}
		att, err := e.Verifier.VerifyAttestation(in.Evidence.Data, hash)
		if err != nil {
			return walletprovider.VerifiedEvidence{}, err
		}
		if out.Credential, err = encodeCredential(att.PublicKey, att.Environment); err != nil {
			return walletprovider.VerifiedEvidence{}, err
		}
		out.AppID, out.CredentialID = att.AppID, base64.StdEncoding.EncodeToString(att.KeyID)
	} else {
		if in.Purpose == walletprovider.PurposeRegistration {
			return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "an assertion for registration")
		}
		pub, env, err := decodeCredential(in.Instance.Credential)
		if err != nil {
			return walletprovider.VerifiedEvidence{}, err
		}
		// The Verifier's setting now, not at registration, decides: a
		// provider that stops accepting development keys stops their
		// instances too.
		if env == EnvironmentDevelopment && !e.Verifier.AllowDevelopment {
			return walletprovider.VerifiedEvidence{}, fail(ErrEnvironment, "the instance's key is a development environment key, and AllowDevelopment isn't set")
		}
		if in.Instance.Counter > math.MaxUint32 {
			return walletprovider.VerifiedEvidence{}, fail(ErrCounter, "the instance's counter %d is beyond App Attest's", in.Instance.Counter)
		}
		a, err := e.Verifier.VerifyAssertion(in.Evidence.Data, hash, pub, uint32(in.Instance.Counter))
		if err != nil {
			return walletprovider.VerifiedEvidence{}, err
		}
		out.AppID, counter = a.AppID, uint64(a.Counter)
	}
	out.Counter = &counter
	return out, nil
}

// The Credential an EvidenceVerifier stores: a version byte, the
// environment (credentialProduction or credentialDevelopment) and the
// App Attest key's 65-byte uncompressed point.
const (
	credentialVersion     = 1
	credentialProduction  = 0
	credentialDevelopment = 1
	credentialBytes       = 2 + 65
)

func encodeCredential(pub *ecdsa.PublicKey, env Environment) ([]byte, error) {
	point, err := pub.Bytes()
	if err != nil {
		return nil, fail(ErrMalformed, "the attested key: %v", err)
	}
	e := byte(credentialProduction)
	if env == EnvironmentDevelopment {
		e = credentialDevelopment
	}
	return append([]byte{credentialVersion, e}, point...), nil
}

func decodeCredential(b []byte) (*ecdsa.PublicKey, Environment, error) {
	if len(b) != credentialBytes || b[0] != credentialVersion || b[1] > credentialDevelopment {
		return nil, "", fail(ErrConfig, "the instance holds no App Attest key: was it registered with %q evidence?", EvidenceKind)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), b[2:])
	if err != nil {
		return nil, "", fail(ErrConfig, "the instance's App Attest key: %v", err)
	}
	env := EnvironmentProduction
	if b[1] == credentialDevelopment {
		env = EnvironmentDevelopment
	}
	return pub, env, nil
}

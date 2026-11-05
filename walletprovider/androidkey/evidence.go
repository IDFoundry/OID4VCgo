package androidkey

import (
	"context"
	"crypto"
	"encoding/asn1"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// EvidenceKind is the walletprovider.Evidence Kind an EvidenceVerifier
// reads.
const EvidenceKind = "android-key"

// Evidence is the walletprovider.Evidence for a key's attestation
// chain, DER certificates leaf first as Keystore returns them: its Data
// is the certificates' DER concatenated, which is what an Android app
// sends (each certificate's getEncoded(), appended in order).
func Evidence(chain [][]byte) walletprovider.Evidence {
	return walletprovider.Evidence{Kind: EvidenceKind, Data: slices.Concat(chain...)}
}

// EvidenceVerifier makes a Verifier a walletprovider.EvidenceVerifier
// for evidence of EvidenceKind: one key's attestation chain (Evidence),
// over the provider's challenge. Verify runs Verifier.Verify, so every
// check and policy setting of the Verifier applies; the chain's key
// must be one of the keys the request names (ErrKeyNotRequested). It
// reports:
//
//   - the platform, walletprovider.PlatformAndroid;
//   - the app: its package name as AppID and its versionCode as
//     AppVersion. Evidence naming more than one package (apps sharing
//     a user ID) is refused: an instance belongs to one app;
//   - the root of trust, where the chain carries one;
//   - the key, with KeyBindingAttested, at SecurityLevelStrongBox when
//     both the key and its attestation are in StrongBox,
//     SecurityLevelTEE when both are in secure hardware, and
//     SecurityLevelSoftware otherwise (which the Verifier refuses
//     unless AllowSoftware); and its user authentication: none when
//     the key may be used without it, required when an authenticator
//     gates its use, and unreported otherwise.
type EvidenceVerifier struct {
	// Verifier checks the chain. REQUIRED.
	Verifier *Verifier
}

var _ walletprovider.EvidenceVerifier = EvidenceVerifier{}

// Kind implements walletprovider.EvidenceVerifier: EvidenceKind.
func (EvidenceVerifier) Kind() string { return EvidenceKind }

// Verify implements walletprovider.EvidenceVerifier.
func (e EvidenceVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	if e.Verifier == nil {
		return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "EvidenceVerifier has no Verifier")
	}
	chain, err := splitChain(in.Evidence.Data)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	r, err := e.Verifier.Verify(ctx, chain, in.Challenge)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	i := slices.IndexFunc(in.Keys, func(k crypto.PublicKey) bool { return certchain.SameKey(k, r.PublicKey) })
	if i < 0 {
		return walletprovider.VerifiedEvidence{}, fail(ErrKeyNotRequested, "the chain's key isn't among the request's %d keys", len(in.Keys))
	}
	if len(r.App.Packages) != 1 {
		return walletprovider.VerifiedEvidence{}, fail(ErrAppNotAllowed, "%d packages share the key's user ID, want one", len(r.App.Packages))
	}
	pkg := r.App.Packages[0]
	out := walletprovider.VerifiedEvidence{
		Platform: walletprovider.PlatformAndroid,
		AppID:    pkg.Name,
		Keys: []walletprovider.AttestedKey{{
			Key: in.Keys[i], SecurityLevel: evidenceSecurityLevel(r), Binding: walletprovider.KeyBindingAttested,
			UserAuthentication: userAuthentication(r.Enforced),
		}},
	}
	if pkg.Version > 0 {
		out.AppVersion = uint64(pkg.Version)
	}
	if rot := r.Enforced.RootOfTrust; rot != nil {
		out.BootState, out.DeviceLocked = bootState(rot.VerifiedBootState), rot.DeviceLocked
	}
	return out, nil
}

// splitChain splits concatenated DER certificates, bounded as Verify
// bounds the chain.
func splitChain(data []byte) ([][]byte, error) {
	var chain [][]byte
	for rest := data; len(rest) > 0; {
		if len(chain) == MaxChainLength {
			return nil, fail(ErrMalformed, "more than %d certificates", MaxChainLength)
		}
		var raw asn1.RawValue
		next, err := asn1.Unmarshal(rest, &raw)
		if err != nil {
			return nil, fail(ErrMalformed, "certificate %d: %v", len(chain), err)
		}
		if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
			return nil, fail(ErrMalformed, "certificate %d isn't a DER SEQUENCE", len(chain))
		}
		chain = append(chain, raw.FullBytes)
		rest = next
	}
	if len(chain) == 0 {
		return nil, fail(ErrMalformed, "no certificates")
	}
	return chain, nil
}

func evidenceSecurityLevel(r *Result) walletprovider.SecurityLevel {
	kd := r.KeyDescription
	switch {
	case r.StrongBox():
		return walletprovider.SecurityLevelStrongBox
	case kd.KeyMintSecurityLevel.Hardware() && kd.AttestationSecurityLevel.Hardware():
		return walletprovider.SecurityLevelTEE
	}
	return walletprovider.SecurityLevelSoftware
}

func userAuthentication(l *AuthorizationList) walletprovider.UserAuthentication {
	switch {
	case l.NoAuthRequired:
		return walletprovider.UserAuthenticationNone
	case l.UserAuthType != nil && *l.UserAuthType != 0:
		return walletprovider.UserAuthenticationRequired
	}
	return ""
}

func bootState(s VerifiedBootState) walletprovider.BootState {
	switch s {
	case Verified:
		return walletprovider.BootStateVerified
	case SelfSigned:
		return walletprovider.BootStateSelfSigned
	case Unverified:
		return walletprovider.BootStateUnverified
	case Failed:
		return walletprovider.BootStateFailed
	}
	// A state no version defines: unknown, which a policy requiring
	// verified boot refuses.
	return ""
}

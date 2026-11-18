package androidkey

import (
	"context"
	"crypto"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

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
// must be one of the keys the request names (ErrKeyNotRequested). A
// chain Google's status list names REVOKED or SUSPENDED is refused
// with walletprovider.ErrEvidenceRevoked or ErrEvidenceSuspended
// wrapped, as Recheck refuses it, so the provider revokes or suspends a
// registered instance sending it. It reports:
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
//     gates each use, or each use within MaxAuthTimeout of one
//     authentication, and unreported otherwise.
type EvidenceVerifier struct {
	// Verifier checks the chain. REQUIRED.
	Verifier *Verifier

	// MaxAuthTimeout is the longest a key may stay usable after one
	// user authentication (its authorization list's authTimeout) and
	// still be reported as requiring the user. Any code in the app can
	// use such a key until its timeout ends, not only for what the user
	// saw, so a key usable for longer is reported as unreported, and
	// the provider's Policy claims no user authentication for it. Zero
	// means DefaultMaxAuthTimeout; negative, that only a key needing an
	// authentication for every use is reported as requiring the user.
	MaxAuthTimeout time.Duration

	// AllowUncheckedLegacyEvidence accepts, in Recheck and
	// RecheckInstanceKey, the records an earlier version kept that they
	// can't fully judge: an instance with no Facts (registered with
	// OID4VCgo v0.75.3 and before), an instance key with none (recorded
	// with v0.80.0 and before), and Facts without the certificates'
	// validity periods (saved by v0.80.0 and before), whose expiry is
	// then not checked; whatever else such Facts hold — the root, the
	// status list, the policy — is still judged. Unset, the strict
	// choice, they're refused with ErrLegacyFacts, and the instance must
	// register again, or its instance key be attested anew. Set it for
	// an upgrade window only, while the wallets in the field move to
	// fresh evidence (Facts.ValidityRecorded and InstanceFacts find
	// the instances still needing to), or in development, where a
	// provider's stores outlive its upgrades. Each record it lets
	// through is logged, at slog.LevelWarn, to Logger, so the operator
	// can see when none is left to turn it off.
	AllowUncheckedLegacyEvidence bool

	// Logger receives a warning for each record AllowUncheckedLegacyEvidence
	// lets through unjudged, naming the instance (and instance key) and
	// what wasn't checked. Nil means slog.Default().
	Logger *slog.Logger
}

// DefaultMaxAuthTimeout is EvidenceVerifier.MaxAuthTimeout's default:
// the window the EUDI reference wallet gives its holder keys.
const DefaultMaxAuthTimeout = 30 * time.Second

var (
	_ walletprovider.EvidenceRechecker    = EvidenceVerifier{}
	_ walletprovider.InstanceKeyRechecker = EvidenceVerifier{}
)

// Kind implements walletprovider.EvidenceVerifier: EvidenceKind.
func (EvidenceVerifier) Kind() string { return EvidenceKind }

// Verify implements walletprovider.EvidenceVerifier.
func (e EvidenceVerifier) Verify(ctx context.Context, in walletprovider.EvidenceInput) (walletprovider.VerifiedEvidence, error) {
	if e.Verifier == nil {
		return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "EvidenceVerifier has no Verifier")
	}
	if in.Evidence.Kind != EvidenceKind {
		// Served under a Kind of the integrator's own: the instances it
		// registered would fail every recheck (ownKind), so it registers
		// none.
		return walletprovider.VerifiedEvidence{}, fail(ErrConfig, "evidence of Kind %q, not %q: don't serve the adapter under a Kind of your own", in.Evidence.Kind, EvidenceKind)
	}
	chain, err := splitChain(in.Evidence.Data)
	if err != nil {
		return walletprovider.VerifiedEvidence{}, err
	}
	r, err := e.Verifier.Verify(ctx, chain, in.Challenge)
	switch {
	case errors.Is(err, ErrRevoked):
		// Google's verdict on the device's attestation key: the
		// provider revokes or suspends a registered instance sending it.
		return walletprovider.VerifiedEvidence{}, fmt.Errorf("%w: %w", revocationVerdict(err), err)
	case err != nil:
		return walletprovider.VerifiedEvidence{}, undecided(err)
	}
	i := slices.IndexFunc(in.Keys, func(k crypto.PublicKey) bool { return certchain.SameKey(k, r.PublicKey) })
	if i < 0 {
		return walletprovider.VerifiedEvidence{}, fail(ErrKeyNotRequested, "the chain's key isn't among the request's %d keys", len(in.Keys))
	}
	if len(r.App.Packages) != 1 {
		return walletprovider.VerifiedEvidence{}, fail(ErrAppNotAllowed, "%d packages share the key's user ID, want one", len(r.App.Packages))
	}
	pkg := r.App.Packages[0]
	facts, err := json.Marshal(FactsOf(r))
	if err != nil {
		return walletprovider.VerifiedEvidence{}, fmt.Errorf("androidkey: encoding the chain's facts: %w", err)
	}
	out := walletprovider.VerifiedEvidence{
		Facts:    facts,
		Platform: walletprovider.PlatformAndroid,
		AppID:    pkg.Name,
		Keys: []walletprovider.AttestedKey{{
			Key: in.Keys[i], SecurityLevel: evidenceSecurityLevel(r), Binding: walletprovider.KeyBindingAttested,
			UserAuthentication: userAuthentication(r.Enforced, e.maxAuthTimeout()),
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

func (e EvidenceVerifier) maxAuthTimeout() time.Duration {
	if e.MaxAuthTimeout == 0 {
		return DefaultMaxAuthTimeout
	}
	return e.MaxAuthTimeout
}

// userAuthentication is what l shows gates the key's use: none, the
// user for each use or each use within maxTimeout of an authentication, or
// unreported.
func userAuthentication(l *AuthorizationList, maxTimeout time.Duration) walletprovider.UserAuthentication {
	switch {
	case l.NoAuthRequired:
		return walletprovider.UserAuthenticationNone
	case l.UserAuthType == nil || *l.UserAuthType == 0:
		return ""
	// Without authTimeout, every use needs an authentication.
	case l.AuthTimeout == nil || *l.AuthTimeout <= 0:
		return walletprovider.UserAuthenticationRequired
	case maxTimeout > 0 && *l.AuthTimeout <= int64(maxTimeout/time.Second):
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

package androidkey

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// Facts are what a verified chain proved that a Verifier's checks rest
// on, kept so the chain can be judged again once the chain itself is
// gone: EvidenceVerifier reports them as walletprovider.VerifiedEvidence.Facts,
// which the provider keeps as the registration chain's
// walletprovider.Instance.EvidenceFacts (InstanceFacts decodes them)
// and as a recorded instance key's own chain's
// walletprovider.InstanceKey.EvidenceFacts (InstanceKeyFacts).
// They hold no device identifier, only what the chain and its
// attestation extension carry.
type Facts struct {
	// Certificates are the chain's certificates, leaf first.
	Certificates []CertificateFacts `json:"certificates"`

	// RootKeyDigest is the SHA-256 digest of the SubjectPublicKeyInfo of
	// the configured root the chain is anchored at.
	RootKeyDigest []byte `json:"root_key_digest"`

	AttestationVersion       int           `json:"attestation_version"`
	AttestationSecurityLevel SecurityLevel `json:"attestation_security_level"`
	KeyMintSecurityLevel     SecurityLevel `json:"keymint_security_level"`

	// RootOfTrust, OSPatchLevel, VendorPatchLevel and BootPatchLevel are
	// from the enforced authorization list (Result.Enforced); nil when
	// it doesn't carry them.
	RootOfTrust      *RootOfTrust `json:"root_of_trust,omitempty"`
	OSPatchLevel     *int64       `json:"os_patch_level,omitempty"`
	VendorPatchLevel *int64       `json:"vendor_patch_level,omitempty"`
	BootPatchLevel   *int64       `json:"boot_patch_level,omitempty"`

	// App is the attesting app's identity (Result.App): its package and
	// the digests of its signing certificates.
	App *ApplicationID `json:"app,omitempty"`
}

// CertificateFacts are a chain certificate's serial number, as Google's
// status list keys it (lowercase hexadecimal without leading zeros),
// its issuer's name, as crypto/x509/pkix.Name.String writes it, and its
// validity period.
type CertificateFacts struct {
	Serial string `json:"serial"`
	Issuer string `json:"issuer"`

	// NotBefore and NotAfter are the certificate's validity period, in
	// UTC. Both are zero in Facts saved by OID4VCgo v0.80.0 and before,
	// which didn't keep them (Facts.ValidityRecorded).
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`

	// RootKey reports that the certificate has the key of the root the
	// chain is anchored at: it is that root, or a re-issue of it, and,
	// as Verify judges it, the configured root's validity counts, not
	// its own (Google's 2016 root certificate has expired, while its key
	// lives on in the 2022 one).
	RootKey bool `json:"root_key,omitempty"`
}

// ValidityRecorded reports whether f holds every certificate's validity
// period, which Facts saved by OID4VCgo v0.80.0 and before don't:
// Recheck can't tell whether such a chain has expired, and refuses it
// (ErrLegacyFacts), as EvidenceVerifier does unless
// AllowUncheckedLegacyEvidence.
func (f *Facts) ValidityRecorded() bool {
	return len(f.Certificates) > 0 && !slices.ContainsFunc(f.Certificates, func(c CertificateFacts) bool {
		return c.NotBefore.IsZero() || c.NotAfter.IsZero()
	})
}

// Expiry is when the first of f's certificates to expire does, those
// with the root's key (CertificateFacts.RootKey) aside: from then on
// Recheck refuses the chain, and the instance, or instance key, it
// attested needs fresh evidence. It's zero when f doesn't hold the
// certificates' validity periods (ValidityRecorded).
func (f *Facts) Expiry() time.Time {
	if !f.ValidityRecorded() {
		return time.Time{}
	}
	var first time.Time
	for _, c := range f.Certificates {
		if !c.RootKey && (first.IsZero() || c.NotAfter.Before(first)) {
			first = c.NotAfter
		}
	}
	return first
}

// FactsOf returns the Facts of r.
func FactsOf(r *Result) Facts {
	f := Facts{
		AttestationVersion:       r.KeyDescription.AttestationVersion,
		AttestationSecurityLevel: r.KeyDescription.AttestationSecurityLevel,
		KeyMintSecurityLevel:     r.KeyDescription.KeyMintSecurityLevel,
		App:                      r.App,
	}
	for _, c := range r.Chain {
		f.Certificates = append(f.Certificates, CertificateFacts{
			Serial: serialKey(c.SerialNumber), Issuer: c.Issuer.String(),
			NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(),
			RootKey: r.Root != nil && bytes.Equal(c.RawSubjectPublicKeyInfo, r.Root.RawSubjectPublicKeyInfo),
		})
	}
	if r.Root != nil {
		digest := sha256.Sum256(r.Root.RawSubjectPublicKeyInfo)
		f.RootKeyDigest = digest[:]
	}
	if l := r.Enforced; l != nil {
		f.RootOfTrust, f.OSPatchLevel, f.VendorPatchLevel, f.BootPatchLevel = l.RootOfTrust, l.OSPatchLevel, l.VendorPatchLevel, l.BootPatchLevel
	}
	return f
}

// InstanceFacts decodes the Facts kept for an instance registered with
// EvidenceKind evidence, reporting false for an instance with none: one
// registered with another Kind, or before the provider kept them
// (OID4VCgo v0.75.3 and before). A Provider.RevokeWhere match function
// can use it to find the instances a revoked attestation key, or a
// vulnerable patch level, taints, and those EvidenceVerifier.Recheck
// refuses as legacy records: an EvidenceKind instance with no Facts, or
// Facts without validity periods (Facts.ValidityRecorded).
func InstanceFacts(in walletprovider.Instance) (Facts, bool, error) {
	if in.Evidence.Kind != EvidenceKind || len(in.EvidenceFacts) == 0 {
		return Facts{}, false, nil
	}
	var f Facts
	if err := json.Unmarshal(in.EvidenceFacts, &f); err != nil {
		return Facts{}, false, fmt.Errorf("androidkey: instance %q's evidence facts: %w", in.ID, err)
	}
	return f, true, nil
}

// Recheck judges f, the Facts of a chain Verify accepted, by v as it is
// now: the chain's root must still be one of Roots, and valid at v.Now;
// the attestation version, the security levels, the root of trust, the
// OS patch level and the app must still pass v's policy; no certificate
// may be on the status list; and every certificate must still be within
// its validity period at v.Now, a certificate with the root's key
// (CertificateFacts.RootKey) aside, as Verify judges them. Attestation
// certificates Remote Key Provisioning issues live for weeks, so a
// chain Verify accepted expires long before the instance does: its
// instance must then register again, or its instance key be attested
// anew, with fresh evidence. Facts saved without the validity periods
// (by OID4VCgo v0.80.0 and before: Facts.ValidityRecorded) are refused
// with ErrLegacyFacts. The status list is consulted first: a
// certificate it names refuses the Facts with ErrRevoked whatever else
// would refuse them too, so Google's verdict is never masked by a root
// since removed or a policy since tightened. What only the chain itself
// can show — signatures, the challenge, the key's properties — was
// judged by Verify and isn't again. Errors wrap the Err values Verify's
// do.
func (v *Verifier) Recheck(ctx context.Context, f *Facts) error {
	return v.recheck(ctx, f, false)
}

// recheck is Recheck, accepting Facts without validity periods, whose
// validity it then can't judge, when allowUnrecordedValidity.
func (v *Verifier) recheck(ctx context.Context, f *Facts, allowUnrecordedValidity bool) error {
	if err := v.checkPolicyConfig(); err != nil {
		return err
	}
	serials, err := f.serials()
	if err != nil {
		return err
	}
	// Revocation first: Google's verdict on a chain is the one the
	// provider acts on, revoking or suspending the instance, even when
	// the chain's root is no longer trusted, the policy has since been
	// tightened to refuse it, or it has expired, as may all follow the
	// same compromise. A status list that can't be had doesn't stop a
	// refusal the Facts alone decide.
	_, revErr := v.checkRevocation(ctx, serials)
	if errors.Is(revErr, ErrRevoked) {
		return revErr
	}
	root, err := v.recheckRootAndPolicy(f)
	if err != nil {
		return err
	}
	if revErr != nil {
		return revErr
	}
	return v.recheckValidity(f, root, allowUnrecordedValidity)
}

// recheckRootAndPolicy returns the configured root f's chain is
// anchored at, refusing Facts whose root is no longer configured or
// that v's policy refuses.
func (v *Verifier) recheckRootAndPolicy(f *Facts) (*x509.Certificate, error) {
	roots := v.roots()
	i := slices.IndexFunc(roots, func(r *x509.Certificate) bool {
		digest := sha256.Sum256(r.RawSubjectPublicKeyInfo)
		return bytes.Equal(digest[:], f.RootKeyDigest)
	})
	if i < 0 {
		return nil, fail(ErrUntrustedRoot, "the chain's root isn't among the configured roots")
	}
	if err := v.recheckPolicy(f); err != nil {
		return nil, err
	}
	return roots[i], nil
}

// recheckPolicy judges f's attestation version, security levels, root
// of trust, OS patch level and app by v's policy.
func (v *Verifier) recheckPolicy(f *Facts) error {
	enforced := AuthorizationList{RootOfTrust: f.RootOfTrust, OSPatchLevel: f.OSPatchLevel, ApplicationID: f.App}
	r := &Result{KeyDescription: &KeyDescription{
		AttestationVersion:       f.AttestationVersion,
		AttestationSecurityLevel: f.AttestationSecurityLevel,
		KeyMintSecurityLevel:     f.KeyMintSecurityLevel,
		HardwareEnforced:         enforced,
		SoftwareEnforced:         enforced,
	}}
	for _, check := range []func(*Result) error{v.checkLevels, v.checkBoot, v.checkApp} {
		if err := check(r); err != nil {
			return err
		}
	}
	return nil
}

// recheckValidity checks root, the configured root f's chain is
// anchored at, and every certificate of f but one with root's key, are
// valid now, as anchor does a chain's.
func (v *Verifier) recheckValidity(f *Facts, root *x509.Certificate, allowUnrecorded bool) error {
	now := v.now()
	if !within(root, now) {
		return fail(ErrCertificateValidity, "root %q isn't valid at %s", root.Subject.String(), now.UTC().Format(time.RFC3339))
	}
	if !f.ValidityRecorded() {
		if allowUnrecorded {
			return nil
		}
		return fail(ErrLegacyFacts, "the facts don't hold the certificates' validity periods (saved by OID4VCgo v0.80.0 or before)")
	}
	for i, c := range f.Certificates {
		if !c.RootKey && (now.Before(c.NotBefore) || now.After(c.NotAfter)) {
			return outsideValidity(i, c.NotBefore, c.NotAfter, now)
		}
	}
	return nil
}

// serials are f's certificates' serial numbers, leaf first.
func (f *Facts) serials() ([]*big.Int, error) {
	serials := make([]*big.Int, len(f.Certificates))
	for i, c := range f.Certificates {
		serial, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok {
			return nil, fail(ErrMalformed, "certificate %d's serial %q isn't hexadecimal", i, c.Serial)
		}
		serials[i] = serial
	}
	return serials, nil
}

// What a wallet must do once a recheck refuses its evidence as expired
// or uncheckable: send fresh evidence, for a new registration or a new
// instance key.
const (
	remedyRegister    = "the instance must register again, with fresh evidence"
	remedyInstanceKey = "the wallet must attest a new instance key, with fresh evidence"
)

// Recheck implements walletprovider.EvidenceRechecker: it judges the
// Facts kept for the instance's registration chain by the Verifier as
// it is now (Verifier.Recheck), so an instance whose attestation key
// Google has since revoked, whose chain has since expired, or that the
// Verifier's policy has since been tightened to refuse, gets no more
// attestations, even for an instance key it recorded before. A refusal
// wraps walletprovider.ErrEvidenceRejected for a certificate the status
// list names, a root no longer trusted, a certificate outside its
// validity period (ErrCertificateValidity) or a record it can't judge
// (ErrLegacyFacts) — these two with walletprovider.ErrEvidenceExpired
// as well, which the provider answers as registration_expired, or, from
// RecheckInstanceKey, instance_key_expired, so the wallet knows to send
// fresh evidence — and walletprovider.ErrPolicy otherwise; a status
// list it couldn't get, or a misconfigured Verifier, is returned as it
// is, for the provider to fail the request as its own failure.
//
// An instance registered with evidence of another Kind than
// EvidenceKind is refused with ErrConfig, which the provider fails the
// request for as its own failure: the adapter is serving a Kind it
// doesn't judge. An instance with no Facts kept (InstanceFacts: one
// registered with OID4VCgo v0.75.3 and before) can't be judged, and Facts saved by
// OID4VCgo v0.80.0 and before hold no validity periods
// (Facts.ValidityRecorded), so whether its chain has expired can't be:
// both are refused, with ErrLegacyFacts, unless
// AllowUncheckedLegacyEvidence, and the instance must register again.
//
// Google's status list naming a certificate of the chain is Google's
// verdict on the device's attestation key, not a change the operator
// can undo, so a REVOKED entry's refusal wraps
// walletprovider.ErrEvidenceRevoked as well, for the provider to revoke
// the instance, and a SUSPENDED entry's walletprovider.ErrEvidenceSuspended,
// for it to suspend it (Provider.Resume makes it active again, once
// Google lifts the suspension). An entry with another status only
// refuses, as a root removed from Roots, a tightened policy, an expired
// certificate or a legacy record does: the provider neither revokes nor
// suspends the instance for those, which may register again.
//
// Recheck judges the registration chain alone. An instance key's chain
// needn't share its certificates: Remote Key Provisioning rotates a
// device's attestation keys, so an instance key may be attested under
// another intermediate than the registration key, and
// RecheckInstanceKey judges its own Facts. A holder key's chain is
// used once, for the Key Attestation it's sent with, and isn't kept.
func (e EvidenceVerifier) Recheck(ctx context.Context, in walletprovider.Instance) error {
	if err := ownKind(in); err != nil {
		return err
	}
	f, ok, err := InstanceFacts(in)
	switch {
	case err != nil:
		return err
	case !ok:
		return e.unchecked("the instance has no evidence facts (registered with OID4VCgo v0.75.3 or before)", remedyRegister)
	}
	return e.recheck(ctx, &f, remedyRegister)
}

// RecheckInstanceKey implements walletprovider.InstanceKeyRechecker: it
// judges the Facts kept for the instance key k's own chain
// (InstanceKeyFacts) as Recheck does the registration chain's, with
// the same verdicts, so a certificate of k's chain that Google's status
// list names REVOKED or SUSPENDED revokes or suspends the instance,
// though the registration chain's certificates are unnamed, and a
// certificate of k's chain that has expired refuses k alone: the
// wallet attests a new instance key, with fresh evidence, while the
// instance's registration chain is still valid. A key with no Facts
// kept (recorded with OID4VCgo v0.80.0 and before), or Facts without
// validity periods, is refused as Recheck refuses such an instance,
// unless AllowUncheckedLegacyEvidence.
func (e EvidenceVerifier) RecheckInstanceKey(ctx context.Context, in walletprovider.Instance, k walletprovider.InstanceKey) error {
	if err := ownKind(in); err != nil {
		return err
	}
	f, ok, err := InstanceKeyFacts(in, k)
	switch {
	case err != nil:
		return err
	case !ok:
		return e.unchecked("the instance key has no evidence facts (recorded with OID4VCgo v0.80.0 or before)", remedyInstanceKey)
	}
	return e.recheck(ctx, &f, remedyInstanceKey)
}

// ownKind refuses, as a configuration error, to recheck an instance
// registered with evidence of another Kind than EvidenceKind: its
// Facts, if any, aren't this package's, and accepting it unjudged would
// skip every recheck, as serving the adapter under a Kind of the
// integrator's own otherwise would.
func ownKind(in walletprovider.Instance) error {
	if in.Evidence.Kind != EvidenceKind {
		return fail(ErrConfig, "instance %q was registered with %q evidence, not %q", in.ID, in.Evidence.Kind, EvidenceKind)
	}
	return nil
}

// InstanceKeyFacts decodes the Facts kept for k, an instance key of the
// instance in, registered with EvidenceKind evidence, reporting false
// for a key with none: one of an instance registered with another
// Kind, or recorded before the provider kept them (OID4VCgo v0.80.0
// and before).
func InstanceKeyFacts(in walletprovider.Instance, k walletprovider.InstanceKey) (Facts, bool, error) {
	if in.Evidence.Kind != EvidenceKind || len(k.EvidenceFacts) == 0 {
		return Facts{}, false, nil
	}
	var f Facts
	if err := json.Unmarshal(k.EvidenceFacts, &f); err != nil {
		return Facts{}, false, fmt.Errorf("androidkey: instance key %q's evidence facts: %w", k.Thumbprint, err)
	}
	return f, true, nil
}

// unchecked is the verdict on a record with no Facts kept: nil when
// AllowUncheckedLegacyEvidence, a refusal saying what, and remedy,
// otherwise.
func (e EvidenceVerifier) unchecked(what, remedy string) error {
	if e.AllowUncheckedLegacyEvidence {
		return nil
	}
	return fmt.Errorf("%w: %w: %w; %s", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceExpired, fail(ErrLegacyFacts, "%s", what), remedy)
}

// recheck judges f by the Verifier as it is now, wrapping a refusal as
// Recheck describes; remedy says what the wallet must do once f's chain
// has expired or can't be judged.
func (e EvidenceVerifier) recheck(ctx context.Context, f *Facts, remedy string) error {
	if e.Verifier == nil {
		return fail(ErrConfig, "EvidenceVerifier has no Verifier")
	}
	switch err := e.Verifier.recheck(ctx, f, e.AllowUncheckedLegacyEvidence); {
	case err == nil:
		return nil
	case errors.Is(err, ErrStatusUnavailable), errors.Is(err, ErrConfig), errors.Is(err, ErrMalformed):
		return err
	case errors.Is(err, ErrRevoked):
		return fmt.Errorf("%w: %w", revocationVerdict(err), err)
	case errors.Is(err, ErrCertificateValidity), errors.Is(err, ErrLegacyFacts):
		return fmt.Errorf("%w: %w: %w; %s", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceExpired, err, remedy)
	case errors.Is(err, ErrUntrustedRoot):
		return fmt.Errorf("%w: %w", walletprovider.ErrEvidenceRejected, err)
	default:
		return fmt.Errorf("%w: %w", walletprovider.ErrPolicy, err)
	}
}

// revocationVerdict is what a recheck refused for ErrRevoked wraps:
// walletprovider.ErrEvidenceRejected, with ErrEvidenceRevoked or
// ErrEvidenceSuspended for the status list entry's REVOKED or
// SUSPENDED status.
func revocationVerdict(err error) error {
	var revoked *RevokedError
	if errors.As(err, &revoked) {
		switch revoked.Entry.Status {
		case StatusRevoked:
			return fmt.Errorf("%w: %w", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceRevoked)
		case StatusSuspended:
			return fmt.Errorf("%w: %w", walletprovider.ErrEvidenceRejected, walletprovider.ErrEvidenceSuspended)
		}
	}
	return walletprovider.ErrEvidenceRejected
}

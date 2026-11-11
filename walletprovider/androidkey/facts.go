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

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// Facts are what a verified chain proved that a Verifier's checks rest
// on, kept so the chain can be judged again once the chain itself is
// gone: EvidenceVerifier reports them as the registration evidence's
// walletprovider.VerifiedEvidence.Facts, which the provider keeps as
// walletprovider.Instance.EvidenceFacts (InstanceFacts decodes them).
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
// and its issuer's name, as crypto/x509/pkix.Name.String writes it.
type CertificateFacts struct {
	Serial string `json:"serial"`
	Issuer string `json:"issuer"`
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
		f.Certificates = append(f.Certificates, CertificateFacts{Serial: serialKey(c.SerialNumber), Issuer: c.Issuer.String()})
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
// vulnerable patch level, taints.
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
// now: the chain's root must still be one of Roots, no certificate may
// be on the status list, and the attestation version, the security
// levels, the root of trust, the OS patch level and the app must still
// pass v's policy. What only the chain itself can show — signatures,
// validity periods, the challenge, the key's properties — was judged by
// Verify and isn't again. Errors wrap the Err values Verify's do.
func (v *Verifier) Recheck(ctx context.Context, f *Facts) error {
	if err := v.checkPolicyConfig(); err != nil {
		return err
	}
	if !slices.ContainsFunc(v.roots(), func(r *x509.Certificate) bool {
		digest := sha256.Sum256(r.RawSubjectPublicKeyInfo)
		return bytes.Equal(digest[:], f.RootKeyDigest)
	}) {
		return fail(ErrUntrustedRoot, "the chain's root isn't among the configured roots")
	}
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
	serials := make([]*big.Int, len(f.Certificates))
	for i, c := range f.Certificates {
		serial, ok := new(big.Int).SetString(c.Serial, 16)
		if !ok {
			return fail(ErrMalformed, "certificate %d's serial %q isn't hexadecimal", i, c.Serial)
		}
		serials[i] = serial
	}
	_, err := v.checkRevocation(ctx, serials)
	return err
}

// Recheck implements walletprovider.EvidenceRechecker: it judges the
// Facts kept for the instance's registration chain by the Verifier as
// it is now (Verifier.Recheck), so an instance whose attestation key
// Google has since revoked, or that the Verifier's policy has since
// been tightened to refuse, gets no more attestations, even for an
// instance key it recorded before. It accepts an instance with no Facts
// kept (InstanceFacts), which it can't judge. A refusal wraps
// walletprovider.ErrEvidenceRejected for a certificate the status list
// names or a root no longer trusted, and walletprovider.ErrPolicy
// otherwise; a status list it couldn't get, or a misconfigured
// Verifier, is returned as it is, for the provider to fail the request
// as its own failure.
//
// Google's status list naming a certificate of the chain is Google's
// verdict on the device's attestation key, not a change the operator
// can undo, so a REVOKED entry's refusal wraps
// walletprovider.ErrEvidenceRevoked as well, for the provider to revoke
// the instance, and a SUSPENDED entry's walletprovider.ErrEvidenceSuspended,
// for it to suspend it (Provider.Resume makes it active again, once
// Google lifts the suspension). An entry with another status only
// refuses, as a root removed from Roots or a tightened policy does.
//
// Only the registration chain's Facts are kept: an instance key's or a
// holder key's chain, verified once, comes from the same device and
// attestation key.
func (e EvidenceVerifier) Recheck(ctx context.Context, in walletprovider.Instance) error {
	f, ok, err := InstanceFacts(in)
	if err != nil || !ok {
		return err
	}
	if e.Verifier == nil {
		return fail(ErrConfig, "EvidenceVerifier has no Verifier")
	}
	switch err := e.Verifier.Recheck(ctx, &f); {
	case err == nil:
		return nil
	case errors.Is(err, ErrStatusUnavailable), errors.Is(err, ErrConfig), errors.Is(err, ErrMalformed):
		return err
	case errors.Is(err, ErrRevoked):
		return fmt.Errorf("%w: %w", revocationVerdict(err), err)
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

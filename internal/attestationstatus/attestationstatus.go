// Package attestationstatus checks an attestation's Token Status List
// "status" claim, with the list's signer bound to the attestation's: the
// engine behind issuer.StatusListAttestationStatus (key attestations),
// and through it haip.WalletAttestationStatusList (Wallet Attestations),
// given the attestation's signer as each receives it and the error that
// says it's refused.
package attestationstatus

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// Policy is how an attestation's status is checked.
type Policy struct {
	// Checker fetches and verifies the Status List Token. Its
	// Options.Issuer, IssuerKey and UnboundSigner are set from the
	// attestation by each check, so must be left unset.
	Checker statuslist.Checker

	// RequireStatus refuses an attestation without a status claim.
	RequireStatus bool

	// ListSignerUnderAttesterCA also accepts a list signed under the CA
	// that issued the attestation's signing certificate; otherwise only
	// a list signed with the attestation's own key is.
	ListSignerUnderAttesterCA bool
}

// Attestation is what a check is given of a verified attestation.
type Attestation struct {
	// Status is its "status" claim's value, decoded from JSON; HasStatus
	// says whether it has one.
	Status    any
	HasStatus bool

	// SignerKey is the key its signature verified with. Required.
	SignerKey crypto.PublicKey

	// SignerCertificates is its signer's certificate chain, leaf first
	// (holding SignerKey), with or without the trust anchor; nil when it
	// was verified by key alone.
	SignerCertificates []*x509.Certificate
}

// Validate refuses a policy that can't be used, and under production
// one whose Fetcher may reach the deployment's own network, that hasn't
// decided its list signers' revocation, or that would fetch the list
// afresh on every request. Errors name the field as Checker.
func (p Policy) Validate(production bool) error {
	const prefix = "Checker"
	o := p.Checker.Options
	switch {
	case p.Checker.Roots == nil:
		return fmt.Errorf("%s.Roots is required: the trust anchors for status list signers", prefix)
	case o.Issuer != "" || o.IssuerKey != nil || o.UnboundSigner != nil:
		return fmt.Errorf("%s.Options's Issuer, IssuerKey and UnboundSigner must be unset: each check binds the list's signer to the attestation's", prefix)
	case !production:
		return nil
	case !p.Checker.Fetcher.HardenedForProduction():
		return fmt.Errorf("under production assurance, %s.Fetcher must be HardenedForProduction: none of AllowLoopback, AllowPrivate, AllowProxy and UncheckedTransport", prefix)
	case o.Revocation == nil:
		return fmt.Errorf("under production assurance, %s.Options.Revocation is required: pass certrevocation.CRLs{...}, your own certrevocation.Checker, or certrevocation.NoCheck{} to decline", prefix)
	case p.Checker.Cache == nil:
		return fmt.Errorf("under production assurance, %s.Cache is required (statuslist.NewCache): without one every request fetches the attester's status list again, ignoring its ttl", prefix)
	}
	if v, ok := o.Revocation.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("%s.Options.Revocation: %w", prefix, err)
		}
	}
	return nil
}

// Check checks a's status as p says: nil when it's VALID, or has no
// status and p doesn't require one; an error wrapping refused when its
// status isn't VALID (also wrapping the *statuslist.NotValidError), or
// its status claim is missing where required or can't be read; any
// other error when the status couldn't be determined.
func (p Policy) Check(ctx context.Context, a Attestation, refused error) error {
	if err := p.Validate(false); err != nil {
		return fmt.Errorf("attestation status: %w", err)
	}
	if a.SignerKey == nil {
		return errors.New("attestation status: the attestation's signer key is unknown, so its status list's signer can't be bound to it")
	}
	if !a.HasStatus {
		if p.RequireStatus {
			return fmt.Errorf("%w: the attestation carries no status claim, and one is required", refused)
		}
		return nil
	}
	claim, ok := a.Status.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: the attestation's status claim is a %T, not an object", refused, a.Status)
	}
	ref, err := statuslist.ParseStatusClaim(claim)
	if err != nil {
		return fmt.Errorf("%w: the attestation's status claim: %w", refused, err)
	}
	c := p.Checker
	if ca := p.issuingCA(a.SignerCertificates); ca != nil {
		c.Options.UnboundSigner = signedByKeyOrUnderCA(a.SignerKey, ca)
	} else {
		c.Options.IssuerKey = a.SignerKey
	}
	err = c.RequireValid(ctx, ref, false)
	if notValid := (*statuslist.NotValidError)(nil); errors.As(err, &notValid) {
		return fmt.Errorf("%w: %w", refused, err)
	}
	return err
}

// issuingCA is the certificate that issued chain's leaf, when p accepts
// lists signed under it and chain names it: its second certificate. A
// chain of the leaf alone names none; nor does one whose second
// certificate didn't sign the leaf.
func (p Policy) issuingCA(chain []*x509.Certificate) *x509.Certificate {
	if !p.ListSignerUnderAttesterCA || len(chain) < 2 || chain[0] == nil || chain[1] == nil {
		return nil
	}
	if chain[0].CheckSignatureFrom(chain[1]) != nil {
		return nil
	}
	return chain[1]
}

// signedByKeyOrUnderCA is a statuslist.VerifyOptions.UnboundSigner
// accepting a list signer that holds key, or whose verified path passes
// through ca: the same certificate, or the same CA certified again (the
// same subject and key, a renewal or cross-certificate).
func signedByKeyOrUnderCA(key crypto.PublicKey, ca *x509.Certificate) func(*x509.Certificate, [][]*x509.Certificate) error {
	isCA := func(cert *x509.Certificate) bool {
		return bytes.Equal(cert.Raw, ca.Raw) ||
			bytes.Equal(cert.RawSubject, ca.RawSubject) && bytes.Equal(cert.RawSubjectPublicKeyInfo, ca.RawSubjectPublicKeyInfo)
	}
	return func(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
		if certchain.SameKey(leaf.PublicKey, key) {
			return nil
		}
		for _, chain := range chains {
			if slices.ContainsFunc(chain, isCA) {
				return nil
			}
		}
		return fmt.Errorf("the status list's signer neither holds the attestation's key nor is under %q, the CA that issued the attestation's certificate", ca.Subject)
	}
}

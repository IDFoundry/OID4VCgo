package issuer

import (
	"context"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/attestationstatus"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListAttestationStatus is an AttestationStatusChecker for key
// attestations whose "status" claim is a Token Status List reference
// (OID4VCI 1.0 Appendix D.1, draft-ietf-oauth-status-list): it fetches
// the Status List Token the claim names with Checker and refuses the
// attestation unless its entry is VALID.
//
//	statusCache := statuslist.NewCache(statuslist.CacheOptions{}) // one for the process
//	...
//	AttestationStatus: issuer.StatusListAttestationStatus{
//		Checker: statuslist.Checker{
//			Roots:   walletProviderRoots,
//			Options: statuslist.VerifyOptions{Revocation: certrevocation.CRLs{...}},
//			Cache:   statusCache,
//		},
//		RequireStatus: true,
//	},
//
// The Status List Token's signer is bound to the attestation's, so
// that under roots several Wallet Providers share none can decide
// another's attestations: by default the list must be signed with the
// very key that signed the attestation (VerifiedKeyAttestation's
// SignerKey; draft-ietf-oauth-status-list §11.3's same-key
// arrangement). ListSignerUnderAttesterCA widens that to a list signed
// under the CA that issued the attestation's signing certificate. The
// attestation's iss doesn't bind the list: it's whatever its signer
// wrote (see AttestationStatusChecker).
//
// What the Wallet sees: an attestation whose status is anything but
// VALID (INVALID, SUSPENDED or an application-specific value), whose
// status claim can't be read, or that has none where RequireStatus
// requires one, is refused with an error wrapping
// ErrKeyAttestationRevoked — invalid_proof for a Credential Request,
// and a denied deferred transaction. A status that can't be determined
// — a list that couldn't be fetched, whose signature, signer or
// freshness doesn't verify, or signed by someone the binding refuses —
// is any other error: a server error the Wallet retries, and a deferred
// transaction left pending (ErrDeferredAttestationStatusUnknown).
//
// Checker.Fetcher connects only to public https addresses, so an
// attestation's status uri can't point the issuer at its own network;
// New refuses one that isn't HardenedForProduction under
// AssuranceProduction (see CheckConfiguration).
type StatusListAttestationStatus struct {
	// Checker fetches and verifies each Status List Token, with its
	// Fetcher, Roots (REQUIRED: the anchors of the Wallet Providers'
	// status list signers), Options and Cache. Leave Options.Issuer,
	// IssuerKey and UnboundSigner unset: each check binds the list's
	// signer to the attestation's itself, and New refuses a Checker
	// setting them. Options.LeafPolicy still applies to every signer.
	// Share one statuslist.Cache across the process, so a Wallet
	// Provider's list is fetched once per its ttl rather than once per
	// Credential Request.
	Checker statuslist.Checker

	// RequireStatus refuses a key attestation with no status claim:
	// one its Wallet Provider couldn't revoke before it expires. Unset,
	// such an attestation passes.
	RequireStatus bool

	// ListSignerUnderAttesterCA also accepts a Status List Token whose
	// signer's verified path passes through the CA that issued the
	// attestation's signing certificate — the x5c header's second
	// certificate, or that CA certified again under the same subject
	// and key — for a Wallet Provider that signs its lists with a
	// certificate of their own. Set it only where that CA is a single
	// Wallet Provider's: a CA issuing certificates to several would let
	// each decide the others' attestations. An attestation verified by
	// key alone, or whose x5c is its leaf alone, still needs a list
	// signed with its own key.
	ListSignerUnderAttesterCA bool
}

// CheckAttestationStatus implements AttestationStatusChecker.
func (s StatusListAttestationStatus) CheckAttestationStatus(ctx context.Context, a VerifiedKeyAttestation) error {
	return s.policy().Check(ctx, attestationstatus.Attestation{
		Status: a.Claims.Status, HasStatus: a.Claims.Status != nil,
		SignerKey: a.SignerKey, SignerCertificates: a.SignerCertificates,
	}, ErrKeyAttestationRevoked)
}

// CheckConfiguration implements ConfigurationCheck: New refuses a
// Checker without Roots, or setting Options.Issuer, IssuerKey or
// UnboundSigner. Under AssuranceProduction it also refuses a
// Checker.Fetcher that isn't HardenedForProduction, a nil
// Options.Revocation (certrevocation.NoCheck{} declines checking the
// list signers' certificates explicitly), and a nil Cache: without one,
// every Credential Request a Wallet sends has the issuer fetch its
// Wallet Provider's list again, whatever the list's ttl says.
func (s StatusListAttestationStatus) CheckConfiguration(assurance AssuranceLevel) error {
	if err := s.policy().Validate(assurance == AssuranceProduction); err != nil {
		return fmt.Errorf("StatusListAttestationStatus: %w", err)
	}
	return nil
}

func (s StatusListAttestationStatus) policy() attestationstatus.Policy {
	return attestationstatus.Policy{Checker: s.Checker, RequireStatus: s.RequireStatus, ListSignerUnderAttesterCA: s.ListSignerUnderAttesterCA}
}

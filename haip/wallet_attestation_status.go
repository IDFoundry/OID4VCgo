package haip

import (
	"context"
	"errors"
	"fmt"

	"github.com/idfoundry/fapigo/server"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// WalletAttestationStatusList is a fapigo/server
// ClientAttestationStatusChecker for Wallet Attestations whose "status"
// claim (OID4VCI 1.0 Appendix E) is a Token Status List reference
// (draft-ietf-oauth-status-list): set it as the Authorization Server's
// server.Dependencies.ClientAttestationStatus. It fetches the Status
// List Token the claim names with Checker and refuses the attestation
// unless its entry is VALID.
//
//	statusCache := statuslist.NewCache(statuslist.CacheOptions{}) // one for the process
//	walletStatus := haip.WalletAttestationStatusList{
//		Checker: statuslist.Checker{
//			Roots:   walletProviderRoots,
//			Options: statuslist.VerifyOptions{Revocation: certrevocation.CRLs{...}},
//			Cache:   statusCache,
//		},
//		RequireStatus: true,
//	}
//	if err := walletStatus.CheckConfiguration(server.AssuranceProduction); err != nil { ... }
//	deps.ClientAttestationStatus = walletStatus
//
// The Status List Token's signer is bound to the attester that signed
// the attestation, as fapigo/server requires: by default the list must
// be signed with the attestation's own key (VerifiedClientAttestation's
// SignerKey; draft-ietf-oauth-status-list §11.3's same-key
// arrangement), so a Wallet Provider sharing the trust list can't
// decide another's attestations. ListSignerUnderAttesterCA widens that
// to a list signed under the CA that issued the attestation's signing
// certificate.
//
// What the Wallet sees: an attestation whose status is anything but
// VALID (INVALID, SUSPENDED or an application-specific value), whose
// status claim can't be read, or that has none where RequireStatus
// requires one, is refused with an error wrapping
// server.ErrClientAttestationRevoked: invalid_client (401). A status
// that can't be determined — a list that couldn't be fetched, whose
// signature, signer or freshness doesn't verify, or signed by someone
// the binding refuses — is any other error: server_error (500), which
// the Wallet retries with a fresh PoP.
//
// The status uri is the attester's to choose, so fapigo/server asks for
// it to be fetched as fapihttp's hardened fetcher does. Checker.Fetcher
// (statuslist.Fetcher) applies the same policy itself: https only,
// every connection — each redirect's included, at most
// statuslist.MaxStatusListRedirects of them, each to https — dialled
// only to a public address, and a size-bounded response of the Status
// List Token media type. Set its HTTP to a client from fapihttp.NewClient
// to have its TLS settings too; statuslist.Fetcher then applies its
// address policy to a copy of that client's transport. Keep the Fetcher
// HardenedForProduction, as CheckConfiguration requires under
// server.AssuranceProduction.
type WalletAttestationStatusList struct {
	// Checker fetches and verifies each Status List Token, with its
	// Fetcher, Roots (REQUIRED: the anchors of the Wallet Providers'
	// status list signers), Options and Cache. Leave Options.Issuer,
	// IssuerKey and UnboundSigner unset: each check binds the list's
	// signer to the attestation's itself, and refuses a Checker setting
	// them. Options.LeafPolicy still applies to every signer. Share one
	// statuslist.Cache across the process: this runs on every
	// attestation-authenticated request, and a list is then fetched once
	// per its ttl rather than once per request.
	Checker statuslist.Checker

	// RequireStatus refuses a Wallet Attestation with no status claim:
	// one its Wallet Provider couldn't revoke before it expires. Unset,
	// such an attestation passes.
	RequireStatus bool

	// ListSignerUnderAttesterCA also accepts a Status List Token whose
	// signer's verified path passes through the CA that issued the
	// attestation's signing certificate (VerifiedClientAttestation's
	// SignerCertificates[1], or that CA certified again under the same
	// subject and key), for a Wallet Provider that signs its lists with
	// a certificate of their own. SignerCertificates ends at the trust
	// anchor, so for a signing certificate the anchor issued directly
	// that CA is the anchor. Set it only where that CA is a single
	// Wallet Provider's — a per-provider intermediate, or an anchor
	// server.AttesterIssuerBoundToAnchor binds to one provider alone: a
	// CA issuing certificates to several would let each decide the
	// others' attestations. An attestation verified under
	// server.RegisteredAttesterKeys still needs a list signed with its
	// own key.
	ListSignerUnderAttesterCA bool
}

// CheckClientAttestationStatus implements
// server.ClientAttestationStatusChecker. It checks the attestation as
// issuer.StatusListAttestationStatus checks a key attestation, so the
// error for a status other than VALID, or for no status where one is
// required, wraps issuer.ErrKeyAttestationRevoked as well as
// server.ErrClientAttestationRevoked.
func (s WalletAttestationStatusList) CheckClientAttestationStatus(ctx context.Context, a server.VerifiedClientAttestation) error {
	verified := issuer.VerifiedKeyAttestation{SignerKey: a.SignerKey, SignerCertificates: a.SignerCertificates}
	if raw, ok := a.Claims["status"]; ok {
		// A status that can't be read isn't "no status".
		ref, err := statuslist.ParseStatusClaimJSON(raw)
		if err != nil {
			return fmt.Errorf("%w: the attestation's status claim: %w", server.ErrClientAttestationRevoked, err)
		}
		// The claim as decoded from JSON, as a key attestation's is:
		// ParseStatusClaim bounds idx to what a float64 holds exactly.
		verified.Claims.Status = map[string]any{"status_list": map[string]any{"idx": float64(ref.Idx), "uri": ref.URI}}
	}
	err := s.checker().CheckAttestationStatus(ctx, verified)
	if errors.Is(err, issuer.ErrKeyAttestationRevoked) {
		return fmt.Errorf("%w: %w", server.ErrClientAttestationRevoked, err)
	}
	return err
}

// CheckConfiguration refuses a Checker without Roots, or setting
// Options.Issuer, IssuerKey or UnboundSigner, and under
// server.AssuranceProduction a Checker.Fetcher that isn't
// HardenedForProduction, a nil Options.Revocation
// (certrevocation.NoCheck{} declines checking the list signers'
// certificates explicitly) and a nil Cache. server.New doesn't call
// it: call it with the Authorization Server's Config.Assurance before
// server.New.
func (s WalletAttestationStatusList) CheckConfiguration(assurance server.AssuranceLevel) error {
	level := issuer.AssuranceDevelopment
	if assurance == server.AssuranceProduction {
		level = issuer.AssuranceProduction
	}
	if err := s.checker().CheckConfiguration(level); err != nil {
		return fmt.Errorf("haip: WalletAttestationStatusList: %w", err)
	}
	return nil
}

// checker is the key attestation checker this one's checks are made
// with: the same binding and status rules, for a Wallet Attestation.
func (s WalletAttestationStatusList) checker() issuer.StatusListAttestationStatus {
	return issuer.StatusListAttestationStatus{Checker: s.Checker, RequireStatus: s.RequireStatus, ListSignerUnderAttesterCA: s.ListSignerUnderAttesterCA}
}

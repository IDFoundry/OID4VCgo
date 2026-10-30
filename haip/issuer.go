package haip

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// RecommendedJWTProofType returns a jwt proof type's own
// ProofTypeConfiguration (OID4VCI 1.0 Appendix F.1), accepting
// RecommendedJOSEAlgorithm (HAIP 1.0 §7) and requiring no Key
// Attestation. See RecommendedAttestationProofType for HAIP §4.5.1's
// Key-Attestation posture instead.
func RecommendedJWTProofType() oid4vci.ProofTypeConfiguration {
	return oid4vci.ProofTypeConfiguration{
		ProofSigningAlgValuesSupported: []string{string(RecommendedJOSEAlgorithm)},
	}
}

// RecommendedAttestationProofType returns an attestation proof type's
// own ProofTypeConfiguration (OID4VCI 1.0 Appendix F.3), accepting
// RecommendedJOSEAlgorithm (HAIP 1.0 §7) and requiring a Key
// Attestation with no further constraint — HAIP 1.0 §4.5.1's own
// recommended posture: "Ecosystems that desire wallet-issuer
// interoperability on the level of key attestations SHOULD require
// Wallets to support the format specified in Appendix D ... in
// combination with ... attestation proof type."
//
// RecommendedJWTKeyAttestationProofType is §4.5.1's other combination,
// and the one to prefer where the issuer chooses its proof types: an
// attestation proof names no audience, so its only binding to this
// issuer is a c_nonce from the unauthenticated Nonce Endpoint, and a
// key attestation can be relayed between issuers (see
// oid4vci.ProofTypeAttestation), whereas a jwt proof is signed by an
// attested key and names the issuer in aud. issuer.New refuses this
// proof type under AssuranceProduction unless
// issuer.Config.AllowAttestationProofType takes it.
func RecommendedAttestationProofType() oid4vci.ProofTypeConfiguration {
	return oid4vci.ProofTypeConfiguration{
		ProofSigningAlgValuesSupported: []string{string(RecommendedJOSEAlgorithm)},
		KeyAttestationsRequired:        &oid4vci.KeyAttestationRequirement{},
	}
}

// RecommendedJWTKeyAttestationProofType returns a jwt proof type's
// ProofTypeConfiguration (OID4VCI 1.0 Appendix F.1) requiring a Key
// Attestation in each proof's key_attestation header, accepting
// RecommendedJOSEAlgorithm: HAIP 1.0 §4.5.1's "jwt proof type using
// key_attestation", the other combination beside
// RecommendedAttestationProofType. The issuer verifies the header with
// Dependencies.AttestationVerifier, which issuer.New then requires.
func RecommendedJWTKeyAttestationProofType() oid4vci.ProofTypeConfiguration {
	return oid4vci.ProofTypeConfiguration{
		ProofSigningAlgValuesSupported: []string{string(RecommendedJOSEAlgorithm)},
		KeyAttestationsRequired:        &oid4vci.KeyAttestationRequirement{},
	}
}

// IssuerRecommendations is what RecommendedIssuerConfig returns: the
// pieces of an issuer.Config/issuer.CredentialConfiguration that HAIP
// 1.0 actually grounds a specific recommendation for. It is not a
// complete issuer.Config — see the package doc comment for what's
// deliberately left out and why.
type IssuerRecommendations struct {
	// ProofTypesSupported is ready to assign directly to a
	// CredentialConfiguration that requires cryptographic key binding
	// (i.e. one that also sets CryptographicBindingMethodsSupported):
	// jwt proofs carrying a Key Attestation in their key_attestation
	// header (RecommendedJWTKeyAttestationProofType), HAIP 1.0 §4.5.1's
	// combination that binds each proof to this issuer by its aud.
	ProofTypesSupported map[string]oid4vci.ProofTypeConfiguration
}

// RecommendedIssuerConfig returns HAIP 1.0's own recommendations for
// the parts of an issuer.Config/issuer.CredentialConfiguration it
// actually grounds a specific value for. As with FAPIgo's own
// RecommendedLimits/RecommendedAlgorithms, this is a starting point to
// call and override, not something issuer.New applies on its own.
//
// Its proof types require a Key Attestation (Wallets MUST support them,
// §4.5.1) in jwt proofs only: the attestation proof type
// (RecommendedAttestationProofType) names no audience, so another
// issuer could relay a Wallet's key attestation here, and issuer.New
// refuses it under AssuranceProduction without
// issuer.Config.AllowAttestationProofType.
func RecommendedIssuerConfig() IssuerRecommendations {
	return IssuerRecommendations{
		ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: RecommendedJWTKeyAttestationProofType(),
		},
	}
}

// IssuerProfile is HAIP 1.0 as an issuer.Profile: with
// issuer.Config.Profile set to it, issuer.New runs ValidateIssuerConfig
// along with its own checks, under either assurance level, and reports
// what it finds with them.
type IssuerProfile struct{}

// CheckIssuer implements issuer.Profile with ValidateIssuerConfig.
func (IssuerProfile) CheckIssuer(cfg issuer.Config, deps issuer.Dependencies) error {
	return ValidateIssuerConfig(cfg, deps)
}

// ValidateIssuerConfig checks cfg and deps against HAIP 1.0's own
// additional requirements on an issuer on top of plain OID4VCI, and
// reports every one they miss (errors.Join):
//
//   - every Credential Configuration must declare a Scope (§4.1: "The
//     Credential Issuer metadata MUST include a scope for every
//     Credential Configuration it supports"), mapping to one Credential
//     Type and one key attestation requirement (§4.3).
//   - Endpoints.Nonce must be configured whenever any Credential
//     Configuration requires cryptographic key binding (§4.1: "If the
//     Issuer supports Credential Configurations that require key
//     binding, as indicated by the presence of
//     cryptographic_binding_methods_supported, the nonce_endpoint MUST
//     be present in the Credential Issuer Metadata"). Every key proof is
//     then single-use, and Limits.MaxProofAge plays no part.
//   - every proof type must accept ES256 (§7: issuers MUST support it
//     for validating proofs and key attestations), or HAIP Wallets,
//     which may sign with nothing else, are refused.
//   - pre-authorized codes, when deps.PreAuthorizedCodes redeems them,
//     must be redeemed with client authentication (§4.4.1: "Wallets
//     MUST use, and Issuers MUST require, an OAuth2 Client
//     authentication mechanism at OAuth2 Endpoints that support client
//     authentication"): PreAuthorizedCodeClientAuthentication is
//     issuer.VerifiedPreAuthorizedCode{}, its Authorization Server
//     having authenticated the client and verified the DPoP proof.
//     issuer.AnonymousPreAuthorizedCode{} redeems without it, and so
//     does nil under development assurance.
//
// They are HAIP-specific profiling on top of plain OID4VCI (base OID4VCI
// leaves scope, the Nonce Endpoint and client authentication at the
// Token Endpoint optional), so issuer.New runs them only when
// issuer.Config.Profile is IssuerProfile{}. Called directly, it takes
// the Config and Dependencies passed to issuer.New.
func ValidateIssuerConfig(cfg issuer.Config, deps issuer.Dependencies) error {
	var errs []error
	if err := checkPreAuthorizedCodeClientAuthentication(cfg, deps); err != nil {
		errs = append(errs, err)
	}
	// HAIP 1.0 §4.3: "The scope value MUST map to a specific Credential
	// Type": configurations sharing a scope must be of one type, or a
	// token for it grants more than one. They must ask for the same key
	// attestations too, or a token for the stricter one is good for the
	// other, whose Credential a Verifier can't tell from it.
	types, attestations := map[string]string{}, map[string]string{}
	for _, id := range slices.Sorted(maps.Keys(cfg.CredentialConfigurationsSupported)) {
		c := cfg.CredentialConfigurationsSupported[id]
		errs = append(errs, checkCredentialConfiguration(cfg, id, c)...)
		if c.Scope == "" {
			continue
		}
		credentialType := c.Format + " " + c.VCT + c.DocType
		if seen, ok := types[c.Scope]; ok && seen != credentialType {
			errs = append(errs, fmt.Errorf("haip: credential_configurations_supported[%q]: scope %q is another configuration's, of another Credential Type (HAIP 1.0 §4.3)", id, c.Scope))
		}
		required := keyAttestationsRequired(c)
		if seen, ok := attestations[c.Scope]; ok && seen != required {
			errs = append(errs, fmt.Errorf("haip: credential_configurations_supported[%q]: scope %q is another configuration's that requires other key attestations, so a token for either is good for both (HAIP 1.0 §4.3, §4.5.1)", id, c.Scope))
		}
		types[c.Scope], attestations[c.Scope] = credentialType, required
	}
	return errors.Join(errs...)
}

// checkPreAuthorizedCodeClientAuthentication refuses pre-authorized
// code redemption without client authentication (HAIP 1.0 §4.4.1).
func checkPreAuthorizedCodeClientAuthentication(cfg issuer.Config, deps issuer.Dependencies) error {
	switch cfg.PreAuthorizedCodeClientAuthentication.(type) {
	case issuer.AnonymousPreAuthorizedCode, *issuer.AnonymousPreAuthorizedCode:
		return fmt.Errorf("haip: pre_authorized_code_client_authentication: anonymous pre-authorized code redemption has no client authentication at the Token Endpoint, which HAIP 1.0 §4.4.1 requires")
	case nil:
		if deps.PreAuthorizedCodes != nil {
			return fmt.Errorf("haip: pre_authorized_code_client_authentication: with none set, dependencies.pre_authorized_codes redeems pre-authorized codes without client authentication at the Token Endpoint, which HAIP 1.0 §4.4.1 requires: set issuer.VerifiedPreAuthorizedCode{}")
		}
	}
	return nil
}

// checkCredentialConfiguration checks one Credential Configuration's
// own HAIP requirements: a scope (§4.1), the Nonce Endpoint when it
// binds a key (§4.1), and ES256 for every proof type (§7).
func checkCredentialConfiguration(cfg issuer.Config, id string, c issuer.CredentialConfiguration) []error {
	var errs []error
	if c.Scope == "" {
		errs = append(errs, fmt.Errorf("haip: credential_configurations_supported[%q]: scope is required (HAIP 1.0 §4.1)", id))
	}
	if len(c.CryptographicBindingMethodsSupported) > 0 && cfg.Endpoints.Nonce.IsZero() {
		errs = append(errs, fmt.Errorf("haip: credential_configurations_supported[%q]: requires cryptographic key binding, so endpoints.nonce is required (HAIP 1.0 §4.1)", id))
	}
	for _, proofType := range slices.Sorted(maps.Keys(c.ProofTypesSupported)) {
		if !slices.Contains(c.ProofTypesSupported[proofType].ProofSigningAlgValuesSupported, string(RecommendedJOSEAlgorithm)) {
			errs = append(errs, fmt.Errorf("haip: credential_configurations_supported[%q]: proof type %q must accept %s in proof_signing_alg_values_supported (HAIP 1.0 §7)", id, proofType, RecommendedJOSEAlgorithm))
		}
	}
	return errs
}

// keyAttestationsRequired is what c's proof types require of a key
// attestation, each one's key_attestations_required (none for a proof
// type that takes a proof without one, and for a configuration that
// takes no proofs), as a string comparable across configurations
// whichever proof types they take, and however their levels are
// ordered or repeated.
func keyAttestationsRequired(c issuer.CredentialConfiguration) string {
	seen := map[string]bool{}
	for _, ptc := range c.ProofTypesSupported {
		r := ptc.KeyAttestationsRequired
		if r == nil {
			seen["none"] = true
			continue
		}
		seen[fmt.Sprintf("%q/%q", levelSet(r.KeyStorage), levelSet(r.UserAuthentication))] = true
	}
	if len(seen) == 0 {
		return "none"
	}
	return strings.Join(slices.Sorted(maps.Keys(seen)), ";")
}

// levelSet is levels sorted, without repeats.
func levelSet(levels []string) []string {
	return slices.Compact(slices.Sorted(slices.Values(levels)))
}

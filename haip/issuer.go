package haip

import (
	"fmt"

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
// §4.5.1 also names a second combination, "jwt proof type using
// key_attestation" — deliberately not offered here: issuer's own
// resolveJWTProofKeys rejects any ProofTypeConfiguration with
// KeyAttestationsRequired set on the jwt proof type outright (not
// supported yet — see its own doc comment), so recommending that
// combination today would describe a configuration issuer can't
// actually serve.
func RecommendedAttestationProofType() oid4vci.ProofTypeConfiguration {
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
	// (i.e. one that also sets CryptographicBindingMethodsSupported) —
	// see RecommendedJWTProofType/RecommendedAttestationProofType's
	// own doc comments for each entry's citation.
	ProofTypesSupported map[string]oid4vci.ProofTypeConfiguration
}

// RecommendedIssuerConfig returns HAIP 1.0's own recommendations for
// the parts of an issuer.Config/issuer.CredentialConfiguration it
// actually grounds a specific value for. As with FAPIgo's own
// RecommendedLimits/RecommendedAlgorithms, this is a starting point to
// call and override, not something issuer.New applies on its own.
func RecommendedIssuerConfig() IssuerRecommendations {
	return IssuerRecommendations{
		ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT:         RecommendedJWTProofType(),
			oid4vci.ProofTypeAttestation: RecommendedAttestationProofType(),
		},
	}
}

// ValidateIssuerConfig checks cfg against HAIP 1.0 §4.1's own
// additional requirements on top of plain OID4VCI:
//
//   - every Credential Configuration must declare a Scope ("The
//     Credential Issuer metadata MUST include a scope for every
//     Credential Configuration it supports").
//   - Endpoints.Nonce must be configured whenever any Credential
//     Configuration requires cryptographic key binding ("If the Issuer
//     supports Credential Configurations that require key binding, as
//     indicated by the presence of cryptographic_binding_methods_supported,
//     the nonce_endpoint MUST be present in the Credential Issuer
//     Metadata").
//
// issuer.New never runs these checks itself: they are HAIP-specific
// profiling on top of plain OID4VCI (base OID4VCI leaves both scope and
// the Nonce Endpoint optional), not something the protocol-generic
// issuer package can assume every deployment wants. Call this after
// issuer.New succeeds, on the same Config passed to it.
func ValidateIssuerConfig(cfg issuer.Config) error {
	for id, c := range cfg.CredentialConfigurationsSupported {
		if c.Scope == "" {
			return fmt.Errorf("haip: credential_configurations_supported[%q]: scope is required", id)
		}
		if len(c.CryptographicBindingMethodsSupported) > 0 && cfg.Endpoints.Nonce.IsZero() {
			return fmt.Errorf("haip: credential_configurations_supported[%q]: requires cryptographic key binding, so endpoints.nonce is required", id)
		}
	}
	return nil
}

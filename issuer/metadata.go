package issuer

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"
)

// Proof type identifiers (Appendix F). Only the two OID4VCIgo's
// credential formats actually use are defined here — di_vp (W3C VCDM)
// is out of scope; see SPECIFICATIONS.md.
const (
	// ProofTypeJWT is the "jwt" proof type (Appendix F.1): a JWT proves
	// possession of the key the issued Credential is bound to.
	ProofTypeJWT = "jwt"

	// ProofTypeAttestation is the "attestation" proof type (Appendix
	// F.3): a Key Attestation JWT (see the attestation package)
	// conveys attested keys without itself proving possession of any
	// one of them.
	ProofTypeAttestation = "attestation"
)

// KeyAttestationRequirement is a proof type's key_attestations_required
// object (§12.2.4): "the Credential Issuer expects the Wallet to send"
// a Key Attestation meeting these constraints. A present-but-empty
// value (both fields nil) means a key attestation is required with no
// further constraint — set KeyAttestationsRequired to a non-nil
// *KeyAttestationRequirement to require one at all; leave it nil to
// not require one.
type KeyAttestationRequirement struct {
	// KeyStorage/UserAuthentication constrain which
	// attestation.AttackPotentialResistance values (Appendix D.2) this
	// issuer accepts, mirroring the Key Attestation claims of the same
	// name. Both OPTIONAL; non-empty if present.
	KeyStorage         []string
	UserAuthentication []string
}

// ProofTypeConfiguration is one entry in a CredentialConfiguration's
// ProofTypesSupported (§12.2.4).
type ProofTypeConfiguration struct {
	// ProofSigningAlgValuesSupported is REQUIRED: the algorithms this
	// issuer accepts a proof of this type to be signed with.
	ProofSigningAlgValuesSupported []string

	// KeyAttestationsRequired, if non-nil, requires every proof of this
	// type to carry a Key Attestation — see the type's own doc comment.
	KeyAttestationsRequired *KeyAttestationRequirement
}

func (p ProofTypeConfiguration) validate() error {
	if len(p.ProofSigningAlgValuesSupported) == 0 {
		return fmt.Errorf("proof_signing_alg_values_supported must not be empty")
	}
	return nil
}

// CredentialConfiguration describes one Credential this issuer
// supports (§12.2.4's credential_configurations_supported entries) —
// deliberately only what SD-JWT VC issuance needs so far: no display,
// credential_metadata, or format-specific claims-description support
// yet (see ARCHITECTURE.md).
type CredentialConfiguration struct {
	// Format is REQUIRED — a Credential Format Identifier such as
	// credential/sdjwtvc.CredentialFormat ("dc+sd-jwt").
	Format string

	// Scope is OPTIONAL: the Authorization Request scope value that
	// selects this Credential.
	Scope string

	// CryptographicBindingMethodsSupported is REQUIRED when
	// Cryptographic Key Binding applies to this Credential ("jwk" for
	// key material in JWK format — the only value OID4VCIgo currently
	// has a use for, since credential/sdjwtvc's holder binding is
	// JWK-based); omitted otherwise.
	CryptographicBindingMethodsSupported []string

	// CredentialSigningAlgValuesSupported is OPTIONAL: the algorithms
	// this issuer signs this Credential with.
	CredentialSigningAlgValuesSupported []string

	// ProofTypesSupported is REQUIRED exactly when
	// CryptographicBindingMethodsSupported is present, keyed by proof
	// type identifier (ProofTypeJWT, ProofTypeAttestation).
	ProofTypesSupported map[string]ProofTypeConfiguration

	// VCT is credential/sdjwtvc's own format-specific metadata
	// parameter (Appendix A.3.2): REQUIRED when Format is
	// credential/sdjwtvc.CredentialFormat, and meaningless otherwise.
	VCT string
}

func (c CredentialConfiguration) validate() error {
	if c.Format == "" {
		return fmt.Errorf("format is required")
	}
	if len(c.CryptographicBindingMethodsSupported) > 0 && len(c.ProofTypesSupported) == 0 {
		return fmt.Errorf("proof_types_supported is required when cryptographic_binding_methods_supported is present")
	}
	if len(c.ProofTypesSupported) > 0 && len(c.CryptographicBindingMethodsSupported) == 0 {
		return fmt.Errorf("cryptographic_binding_methods_supported is required when proof_types_supported is present")
	}
	for id, p := range c.ProofTypesSupported {
		if err := p.validate(); err != nil {
			return fmt.Errorf("proof_types_supported[%q]: %w", id, err)
		}
	}
	return nil
}

// Metadata is this issuer's Credential Issuer Metadata (§12.2.4) —
// deliberately only the REQUIRED members plus what
// CredentialConfigurationsSupported needs so far; see
// ARCHITECTURE.md for what's still missing (encryption, batch
// issuance, display, authorization_servers).
type Metadata struct {
	CredentialIssuer                  fapi.URL                            `json:"credential_issuer"`
	CredentialEndpoint                fapi.URL                            `json:"credential_endpoint"`
	NonceEndpoint                     *fapi.URL                           `json:"nonce_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]metadataCredentialConfig `json:"credential_configurations_supported"`
}

// metadataCredentialConfig is CredentialConfiguration's JSON wire
// shape.
type metadataCredentialConfig struct {
	Format                               string                             `json:"format"`
	Scope                                string                             `json:"scope,omitempty"`
	CryptographicBindingMethodsSupported []string                           `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported  []string                           `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported                  map[string]metadataProofTypeConfig `json:"proof_types_supported,omitempty"`
	VCT                                  string                             `json:"vct,omitempty"`
}

type metadataProofTypeConfig struct {
	ProofSigningAlgValuesSupported []string                    `json:"proof_signing_alg_values_supported"`
	KeyAttestationsRequired        *metadataKeyAttestationReqs `json:"key_attestations_required,omitempty"`
}

type metadataKeyAttestationReqs struct {
	KeyStorage         []string `json:"key_storage,omitempty"`
	UserAuthentication []string `json:"user_authentication,omitempty"`
}

// Metadata returns this issuer's Credential Issuer Metadata document.
func (iss *Issuer) Metadata() Metadata {
	md := Metadata{
		CredentialIssuer:                  iss.cfg.Issuer,
		CredentialEndpoint:                iss.cfg.Endpoints.Credential,
		CredentialConfigurationsSupported: make(map[string]metadataCredentialConfig, len(iss.cfg.CredentialConfigurationsSupported)),
	}
	if !iss.cfg.Endpoints.Nonce.IsZero() {
		nonce := iss.cfg.Endpoints.Nonce
		md.NonceEndpoint = &nonce
	}
	for id, c := range iss.cfg.CredentialConfigurationsSupported {
		wire := metadataCredentialConfig{
			Format: c.Format, Scope: c.Scope,
			CryptographicBindingMethodsSupported: c.CryptographicBindingMethodsSupported,
			CredentialSigningAlgValuesSupported:  c.CredentialSigningAlgValuesSupported,
			VCT:                                  c.VCT,
		}
		if len(c.ProofTypesSupported) > 0 {
			wire.ProofTypesSupported = make(map[string]metadataProofTypeConfig, len(c.ProofTypesSupported))
			for pid, p := range c.ProofTypesSupported {
				wp := metadataProofTypeConfig{ProofSigningAlgValuesSupported: p.ProofSigningAlgValuesSupported}
				if p.KeyAttestationsRequired != nil {
					wp.KeyAttestationsRequired = &metadataKeyAttestationReqs{
						KeyStorage: p.KeyAttestationsRequired.KeyStorage, UserAuthentication: p.KeyAttestationsRequired.UserAuthentication,
					}
				}
				wire.ProofTypesSupported[pid] = wp
			}
		}
		md.CredentialConfigurationsSupported[id] = wire
	}
	return md
}

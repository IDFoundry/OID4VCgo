package issuer

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/cose"
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
	// type identifier (oid4vci.ProofTypeJWT, oid4vci.ProofTypeAttestation).
	ProofTypesSupported map[string]ProofTypeConfiguration

	// VCT is credential/sdjwtvc's own format-specific metadata
	// parameter (Appendix A.3.2): REQUIRED when Format is
	// credential/sdjwtvc.CredentialFormat, and meaningless otherwise.
	VCT string

	// DocType is credential/mdoc's own format-specific metadata
	// parameter (Appendix A.2.2): REQUIRED when Format is
	// credential/mdoc.CredentialFormat, and meaningless otherwise.
	DocType string

	// CredentialSigningAlgValuesSupportedCOSE is
	// CredentialSigningAlgValuesSupported's mdoc counterpart (Appendix
	// A.2.2): the numeric COSE algorithm identifiers (e.g. -7 for
	// ES256) an mdoc's IssuerAuth is signed with, wire-encoded as bare
	// JSON numbers rather than JOSE alg strings. Set this instead of
	// CredentialSigningAlgValuesSupported when Format is
	// credential/mdoc.CredentialFormat — setting both is rejected.
	CredentialSigningAlgValuesSupportedCOSE []cose.Alg
}

func (c CredentialConfiguration) validate() error {
	if c.Format == "" {
		return fmt.Errorf("format is required")
	}
	if len(c.CredentialSigningAlgValuesSupported) > 0 && len(c.CredentialSigningAlgValuesSupportedCOSE) > 0 {
		return fmt.Errorf("credential_signing_alg_values_supported must not be set in both its JOSE-alg-string and COSE-alg-number forms")
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
	DeferredCredentialEndpoint        *fapi.URL                           `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              *fapi.URL                           `json:"notification_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]metadataCredentialConfig `json:"credential_configurations_supported"`
}

// metadataCredentialConfig is CredentialConfiguration's JSON wire
// shape. CredentialSigningAlgValuesSupported is interface{} rather than
// []string because it carries either JOSE alg strings or COSE alg
// numbers depending on the format (see CredentialConfiguration's own
// doc comments) — Metadata sets it from whichever of
// CredentialConfiguration's two typed fields is non-empty, leaving it
// as the zero nil interface{} (correctly omitted by omitempty) when
// neither is.
type metadataCredentialConfig struct {
	Format                               string                             `json:"format"`
	Scope                                string                             `json:"scope,omitempty"`
	CryptographicBindingMethodsSupported []string                           `json:"cryptographic_binding_methods_supported,omitempty"`
	CredentialSigningAlgValuesSupported  interface{}                        `json:"credential_signing_alg_values_supported,omitempty"`
	ProofTypesSupported                  map[string]metadataProofTypeConfig `json:"proof_types_supported,omitempty"`
	VCT                                  string                             `json:"vct,omitempty"`
	DocType                              string                             `json:"doctype,omitempty"`
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
	if !iss.cfg.Endpoints.DeferredCredential.IsZero() {
		deferred := iss.cfg.Endpoints.DeferredCredential
		md.DeferredCredentialEndpoint = &deferred
	}
	if !iss.cfg.Endpoints.Notification.IsZero() {
		notification := iss.cfg.Endpoints.Notification
		md.NotificationEndpoint = &notification
	}
	for id, c := range iss.cfg.CredentialConfigurationsSupported {
		wire := metadataCredentialConfig{
			Format: c.Format, Scope: c.Scope,
			CryptographicBindingMethodsSupported: c.CryptographicBindingMethodsSupported,
			VCT:                                  c.VCT,
			DocType:                              c.DocType,
		}
		// CredentialSigningAlgValuesSupported is only assigned when one
		// of the two typed fields is actually non-empty — otherwise
		// assigning a nil []string/[]cose.Alg would leave the wire
		// interface{} field non-nil (wrapping a nil slice), which
		// omitempty does not treat as empty.
		switch {
		case len(c.CredentialSigningAlgValuesSupportedCOSE) > 0:
			wire.CredentialSigningAlgValuesSupported = c.CredentialSigningAlgValuesSupportedCOSE
		case len(c.CredentialSigningAlgValuesSupported) > 0:
			wire.CredentialSigningAlgValuesSupported = c.CredentialSigningAlgValuesSupported
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

package issuer

import (
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// CredentialConfiguration describes one Credential this issuer
// supports (§12.2.4's credential_configurations_supported entries) —
// this package's own Go-ergonomic *input* shape (Config's own
// CredentialConfigurationsSupported field), distinct from
// oid4vci.CredentialConfigurationMetadata (the wire shape Metadata()
// builds one of these into): CredentialSigningAlgValuesSupported/
// CredentialSigningAlgValuesSupportedCOSE are two separate typed
// fields here, for the same build-time type safety RequestCredential's
// own typed fields want, where the wire shape instead needs one
// untyped field to carry either.
type CredentialConfiguration struct {
	// Format is REQUIRED — a Credential Format Identifier such as
	// credential/sdjwtvc.CredentialFormat ("dc+sd-jwt").
	Format string

	// Scope is OPTIONAL: the Authorization Request scope value that
	// selects this Credential.
	Scope string

	// CryptographicBindingMethodsSupported is REQUIRED when
	// Cryptographic Key Binding applies to this Credential ("jwk" for
	// key material in JWK format — the only value OID4VCgo currently
	// has a use for, since credential/sdjwtvc's holder binding is
	// JWK-based); omitted otherwise.
	CryptographicBindingMethodsSupported []string

	// CredentialSigningAlgValuesSupported is OPTIONAL: the algorithms
	// this issuer signs this Credential with.
	CredentialSigningAlgValuesSupported []string

	// ProofTypesSupported is REQUIRED exactly when
	// CryptographicBindingMethodsSupported is present, keyed by proof
	// type identifier (oid4vci.ProofTypeJWT, oid4vci.ProofTypeAttestation).
	ProofTypesSupported map[string]oid4vci.ProofTypeConfiguration

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

	// CredentialMetadata is OPTIONAL (Appendix A): display/claims
	// metadata for this Credential — see oid4vci.CredentialMetadata's
	// own doc comment for the "format-specific mechanisms take
	// precedence" caveat.
	CredentialMetadata *oid4vci.CredentialMetadata
}

func (c CredentialConfiguration) validate() error {
	if c.Format == "" {
		return fmt.Errorf("format is required")
	}
	if len(c.CredentialSigningAlgValuesSupported) > 0 && len(c.CredentialSigningAlgValuesSupportedCOSE) > 0 {
		return fmt.Errorf("credential_signing_alg_values_supported must not be set in both its JOSE-alg-string and COSE-alg-number forms")
	}
	if err := c.validateFormatSpecific(); err != nil {
		return err
	}
	if err := c.validateBindingAndProofTypes(); err != nil {
		return err
	}
	if c.CredentialMetadata != nil {
		if err := c.CredentialMetadata.Validate(); err != nil {
			return fmt.Errorf("credential_metadata: %w", err)
		}
	}
	return nil
}

// validateFormatSpecific checks that VCT/DocType/the alg-form fields —
// each documented as REQUIRED/format-specific on their own doc comments
// (see VCT's own) — actually agree with Format, which nothing
// previously checked — found in a repo-wide integrator-misconfiguration
// scan. Metadata() serializes VCT/DocType and whichever alg-form field
// is set unconditionally, with json:",omitempty" on both — leaving VCT
// empty on an sdjwtvc-format config, or setting the JOSE-alg-string
// form for an mdoc-format one, silently produces a spec-non-conformant
// Credential Issuer Metadata document (missing vct, or
// credential_signing_alg_values_supported in the wrong wire shape)
// rather than failing at New().
func (c CredentialConfiguration) validateFormatSpecific() error {
	switch c.Format {
	case sdjwtvc.CredentialFormat:
		if c.VCT == "" {
			return fmt.Errorf("vct is required when format is %q", sdjwtvc.CredentialFormat)
		}
		if len(c.CredentialSigningAlgValuesSupportedCOSE) > 0 {
			return fmt.Errorf("credential_signing_alg_values_supported_cose must not be set when format is %q; use credential_signing_alg_values_supported instead", sdjwtvc.CredentialFormat)
		}
	case mdoc.CredentialFormat:
		if c.DocType == "" {
			return fmt.Errorf("doctype is required when format is %q", mdoc.CredentialFormat)
		}
		if len(c.CredentialSigningAlgValuesSupported) > 0 {
			return fmt.Errorf("credential_signing_alg_values_supported must not be set when format is %q; use credential_signing_alg_values_supported_cose instead", mdoc.CredentialFormat)
		}
	}
	return nil
}

// validateBindingAndProofTypes checks CryptographicBindingMethodsSupported
// and ProofTypesSupported are set together or not at all, and delegates
// each proof type's own validation.
func (c CredentialConfiguration) validateBindingAndProofTypes() error {
	if len(c.CryptographicBindingMethodsSupported) > 0 && len(c.ProofTypesSupported) == 0 {
		return fmt.Errorf("proof_types_supported is required when cryptographic_binding_methods_supported is present")
	}
	if len(c.ProofTypesSupported) > 0 && len(c.CryptographicBindingMethodsSupported) == 0 {
		return fmt.Errorf("cryptographic_binding_methods_supported is required when proof_types_supported is present")
	}
	for id, p := range c.ProofTypesSupported {
		if err := p.Validate(); err != nil {
			return fmt.Errorf("proof_types_supported[%q]: %w", id, err)
		}
	}
	return nil
}

// Metadata returns this issuer's Credential Issuer Metadata document.
func (iss *Issuer) Metadata() oid4vci.Metadata {
	md := oid4vci.Metadata{
		CredentialIssuer:                  iss.cfg.Issuer,
		AuthorizationServers:              slices.Clone(iss.cfg.AuthorizationServers),
		CredentialEndpoint:                iss.cfg.Endpoints.Credential,
		CredentialConfigurationsSupported: make(map[string]oid4vci.CredentialConfigurationMetadata, len(iss.cfg.CredentialConfigurationsSupported)),
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
	if rs := iss.cfg.RequestEncryption; rs != nil {
		jwks := make([]oid4vci.JWK, len(rs.Keys))
		for i, k := range rs.Keys {
			// New already validated every key is P-256, so this can't
			// fail.
			wireJWK, _ := jwk.Marshal(&k.PrivateKey.PublicKey)
			jwks[i] = oid4vci.JWK{JWK: wireJWK, Kid: k.KeyID, Alg: jwe.ECDHES}
		}
		md.CredentialRequestEncryption = &oid4vci.RequestEncryptionMetadata{
			JWKS: oid4vci.JWKSet{Keys: jwks}, EncValuesSupported: rs.EncValuesSupported,
			ZipValuesSupported: rs.ZipValuesSupported, EncryptionRequired: rs.Required,
		}
	}
	if rs := iss.cfg.ResponseEncryption; rs != nil {
		md.CredentialResponseEncryption = &oid4vci.ResponseEncryptionMetadata{
			AlgValuesSupported: []jwe.Alg{jwe.ECDHES},
			EncValuesSupported: rs.EncValuesSupported, ZipValuesSupported: rs.ZipValuesSupported, EncryptionRequired: rs.Required,
		}
	}
	if b := iss.cfg.BatchCredentialIssuance; b != nil {
		md.BatchCredentialIssuance = b
	}
	md.Display = iss.cfg.Display
	for id, c := range iss.cfg.CredentialConfigurationsSupported {
		wire := oid4vci.CredentialConfigurationMetadata{
			Format: c.Format, Scope: c.Scope,
			CryptographicBindingMethodsSupported: c.CryptographicBindingMethodsSupported,
			VCT:                                  c.VCT,
			DocType:                              c.DocType,
			CredentialMetadata:                   c.CredentialMetadata,
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
			wire.ProofTypesSupported = c.ProofTypesSupported
		}
		md.CredentialConfigurationsSupported[id] = wire
	}
	return md
}

package issuer

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
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

// Logo is a "logo" object (§12.2.4/Appendix A) — the shared shape
// both Display's own Logo and CredentialDisplay's own Logo use.
type Logo struct {
	// URI is REQUIRED: where the Wallet can obtain the logo — any
	// scheme ("https:", "data:", ...); this package never fetches it.
	URI string

	// AltText is OPTIONAL: alternative text for the logo image.
	AltText string
}

func (l Logo) validate() error {
	if l.URI == "" {
		return fmt.Errorf("uri is required")
	}
	return nil
}

// Display is one entry in Config's own top-level "display" metadata
// (§12.2.4) — this Credential Issuer's own display properties for one
// language. At most one Display per distinct Locale (including
// "") is meaningful; this package doesn't reject a duplicate itself
// (§12.2.4 doesn't make it a MUST either), the same "describe, don't
// police every SHOULD" restraint the rest of this package's own
// metadata fields already take.
type Display struct {
	// Name is OPTIONAL: a display name for the Credential Issuer.
	Name string

	// Locale is OPTIONAL: a BCP47 language tag.
	Locale string

	// Logo is OPTIONAL.
	Logo *Logo
}

func (d Display) validate() error {
	if d.Logo != nil {
		if err := d.Logo.validate(); err != nil {
			return fmt.Errorf("logo: %w", err)
		}
	}
	return nil
}

// BatchCredentialIssuance is Config's own optional
// "batch_credential_issuance" metadata (§12.2.4): advertises this
// issuer's own support for more than one key proof per Credential
// Request, and — via RequestCredential's own checkBatchSize — is the
// enforced cap on a Credential Request's own "proofs" array size: nil
// caps at exactly 1 (§12.2.4's own "the presence of this parameter
// means the issuer supports more than one key proof" read as implying
// absence means it doesn't), non-nil caps at BatchSize. The cap applies
// to the proofs array's own size, not the number of Credentials
// ultimately issued — an attestation proof's own attested_keys can
// still fan out to more Credentials than that (Appendix F.3's own "one
// Credential per attested key"), since that fan-out happens within a
// single array entry, not across it.
type BatchCredentialIssuance struct {
	// BatchSize is REQUIRED: the maximum array size for a Credential
	// Request's own "proofs" parameter this issuer advertises and
	// enforces. Must be 2 or greater.
	BatchSize int
}

func (b BatchCredentialIssuance) validate() error {
	if b.BatchSize < 2 {
		return fmt.Errorf("batch_size must be 2 or greater")
	}
	return nil
}

// BackgroundImage is CredentialDisplay's own "background_image"
// object (Appendix A).
type BackgroundImage struct {
	// URI is REQUIRED: where the Wallet can obtain the background
	// image.
	URI string
}

// CredentialDisplay is one entry in CredentialMetadata's own
// "display" array (Appendix A) — a CredentialConfiguration's own
// display properties for one language. Distinct from Display (this
// package's own Credential-*Issuer*-level display type): Name is
// REQUIRED here, unlike there.
type CredentialDisplay struct {
	// Name is REQUIRED: a display name for the Credential.
	Name string

	Locale          string
	Logo            *Logo
	Description     string
	BackgroundColor string
	BackgroundImage *BackgroundImage
	TextColor       string
}

func (cd CredentialDisplay) validate() error {
	if cd.Name == "" {
		return fmt.Errorf("name is required")
	}
	if cd.Logo != nil {
		if err := cd.Logo.validate(); err != nil {
			return fmt.Errorf("logo: %w", err)
		}
	}
	if cd.BackgroundImage != nil && cd.BackgroundImage.URI == "" {
		return fmt.Errorf("background_image: uri is required")
	}
	return nil
}

// ClaimDisplay is one entry in a ClaimsDescription's own "display"
// array (Appendix B.2).
type ClaimDisplay struct {
	// Name and Locale are both OPTIONAL.
	Name   string
	Locale string
}

// ClaimsDescription is one entry in CredentialMetadata's own "claims"
// array (Appendix B.2): how one claim in the issued Credential is
// displayed to the End-User. Path is a Claims Path Pointer (Appendix
// C) — the exact same wire shape OID4VP's own dcql.Path implements
// (§7.1 there: a non-empty array of strings, nulls, and non-negative
// integers), kept here as a plain []any rather than importing that
// OID4VP-specific package: describing display metadata never needs
// dcql.Path's own Select/evaluation behavior, only its wire shape, and
// this OID4VCI-side package has no reason to depend on an OID4VP one
// for that.
type ClaimsDescription struct {
	// Path is REQUIRED: each element a string, nil (wire null, "select
	// every array element"), or non-negative int.
	Path []any

	// Mandatory is OPTIONAL, default false — use IsMandatory to read
	// the effective value.
	Mandatory *bool

	// Display is OPTIONAL.
	Display []ClaimDisplay
}

// IsMandatory reports c's own effective value — false unless Mandatory
// was explicitly set to true (Appendix B.2's own default).
func (c ClaimsDescription) IsMandatory() bool {
	return c.Mandatory != nil && *c.Mandatory
}

func (c ClaimsDescription) validate() error {
	if len(c.Path) == 0 {
		return fmt.Errorf("path must be non-empty")
	}
	for i, elem := range c.Path {
		switch v := elem.(type) {
		case string, nil:
		case int:
			if v < 0 {
				return fmt.Errorf("path[%d]: negative integer not allowed", i)
			}
		default:
			return fmt.Errorf("path[%d]: must be a string, null, or non-negative integer, got %T", i, elem)
		}
	}
	return nil
}

// CredentialMetadata is a CredentialConfiguration's own optional
// "credential_metadata" object (Appendix A): display/claims metadata
// for the issued Credential. Format-specific mechanisms (e.g. SD-JWT
// VC's own type metadata) are always preferred by the Wallet over
// this, which serves only as a fallback default (Appendix A's own
// text) — this package makes no attempt to keep the two in sync.
type CredentialMetadata struct {
	// Display and Claims are both OPTIONAL; non-empty if present.
	Display []CredentialDisplay
	Claims  []ClaimsDescription
}

func (cm CredentialMetadata) validate() error {
	for i, d := range cm.Display {
		if err := d.validate(); err != nil {
			return fmt.Errorf("display[%d]: %w", i, err)
		}
	}
	for i, c := range cm.Claims {
		if err := c.validate(); err != nil {
			return fmt.Errorf("claims[%d]: %w", i, err)
		}
	}
	return nil
}

// CredentialConfiguration describes one Credential this issuer
// supports (§12.2.4's credential_configurations_supported entries).
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

	// CredentialMetadata is OPTIONAL (Appendix A): display/claims
	// metadata for this Credential — see CredentialMetadata's own doc
	// comment for the "format-specific mechanisms take precedence"
	// caveat.
	CredentialMetadata *CredentialMetadata
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
	if c.CredentialMetadata != nil {
		if err := c.CredentialMetadata.validate(); err != nil {
			return fmt.Errorf("credential_metadata: %w", err)
		}
	}
	return nil
}

// Metadata is this issuer's Credential Issuer Metadata (§12.2.4) —
// deliberately only the REQUIRED members plus what
// CredentialConfigurationsSupported needs so far; see
// ARCHITECTURE.md for what's still missing (authorization_servers).
type Metadata struct {
	CredentialIssuer                  fapi.URL                            `json:"credential_issuer"`
	CredentialEndpoint                fapi.URL                            `json:"credential_endpoint"`
	NonceEndpoint                     *fapi.URL                           `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint        *fapi.URL                           `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              *fapi.URL                           `json:"notification_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]metadataCredentialConfig `json:"credential_configurations_supported"`
	CredentialRequestEncryption       *metadataRequestEncryption          `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption      *metadataResponseEncryption         `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           *metadataBatchCredentialIssuance    `json:"batch_credential_issuance,omitempty"`
	Display                           []metadataDisplay                   `json:"display,omitempty"`
}

// metadataLogo is Logo's own wire shape, shared by metadataDisplay and
// metadataCredentialDisplay.
type metadataLogo struct {
	URI     string `json:"uri"`
	AltText string `json:"alt_text,omitempty"`
}

// metadataDisplay is Display's own wire shape (§12.2.4's top-level
// "display").
type metadataDisplay struct {
	Name   string        `json:"name,omitempty"`
	Locale string        `json:"locale,omitempty"`
	Logo   *metadataLogo `json:"logo,omitempty"`
}

// metadataBatchCredentialIssuance is BatchCredentialIssuance's own wire
// shape (§12.2.4's "batch_credential_issuance").
type metadataBatchCredentialIssuance struct {
	BatchSize int `json:"batch_size"`
}

// metadataBackgroundImage is BackgroundImage's own wire shape (Appendix
// A's "background_image").
type metadataBackgroundImage struct {
	URI string `json:"uri"`
}

// metadataCredentialDisplay is CredentialDisplay's own wire shape
// (Appendix A's "display" entries within credential_metadata).
type metadataCredentialDisplay struct {
	Name            string                   `json:"name"`
	Locale          string                   `json:"locale,omitempty"`
	Logo            *metadataLogo            `json:"logo,omitempty"`
	Description     string                   `json:"description,omitempty"`
	BackgroundColor string                   `json:"background_color,omitempty"`
	BackgroundImage *metadataBackgroundImage `json:"background_image,omitempty"`
	TextColor       string                   `json:"text_color,omitempty"`
}

// metadataClaimDisplay is ClaimDisplay's own wire shape (Appendix B.2's
// "display" entries within a claims description object).
type metadataClaimDisplay struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// metadataClaimsDescription is ClaimsDescription's own wire shape
// (Appendix B.2's claims description object).
type metadataClaimsDescription struct {
	Path      []any                  `json:"path"`
	Mandatory *bool                  `json:"mandatory,omitempty"`
	Display   []metadataClaimDisplay `json:"display,omitempty"`
}

// metadataCredentialMetadata is CredentialMetadata's own wire shape
// (Appendix A's "credential_metadata").
type metadataCredentialMetadata struct {
	Display []metadataCredentialDisplay `json:"display,omitempty"`
	Claims  []metadataClaimsDescription `json:"claims,omitempty"`
}

// metadataRequestEncryption is Config.RequestEncryption's own wire
// shape (§12.2.4's credential_request_encryption).
type metadataRequestEncryption struct {
	JWKS               []metadataJWK `json:"jwks"`
	EncValuesSupported []jwe.Enc     `json:"enc_values_supported"`
	ZipValuesSupported []jwe.Zip     `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool          `json:"encryption_required"`
}

// metadataResponseEncryption is Config.ResponseEncryption's own wire
// shape (§12.2.4's credential_response_encryption). AlgValuesSupported
// is always exactly ["ECDH-ES"] — see ResponseEncryptionSupport's own
// doc comment for why there's no corresponding Go field to set it
// from.
type metadataResponseEncryption struct {
	AlgValuesSupported []jwe.Alg `json:"alg_values_supported"`
	EncValuesSupported []jwe.Enc `json:"enc_values_supported"`
	ZipValuesSupported []jwe.Zip `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool      `json:"encryption_required"`
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
	CredentialMetadata                   *metadataCredentialMetadata        `json:"credential_metadata,omitempty"`
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
	if rs := iss.cfg.RequestEncryption; rs != nil {
		jwks := make([]metadataJWK, len(rs.Keys))
		for i, k := range rs.Keys {
			// New already validated every key is P-256, so this can't
			// fail.
			wireJWK, _ := jwk.Marshal(&k.PrivateKey.PublicKey)
			jwks[i] = metadataJWK{JWK: wireJWK, Kid: k.KeyID}
		}
		md.CredentialRequestEncryption = &metadataRequestEncryption{
			JWKS: jwks, EncValuesSupported: rs.EncValuesSupported,
			ZipValuesSupported: rs.ZipValuesSupported, EncryptionRequired: rs.Required,
		}
	}
	if rs := iss.cfg.ResponseEncryption; rs != nil {
		md.CredentialResponseEncryption = &metadataResponseEncryption{
			AlgValuesSupported: []jwe.Alg{jwe.ECDHES},
			EncValuesSupported: rs.EncValuesSupported, ZipValuesSupported: rs.ZipValuesSupported, EncryptionRequired: rs.Required,
		}
	}
	if b := iss.cfg.BatchCredentialIssuance; b != nil {
		md.BatchCredentialIssuance = &metadataBatchCredentialIssuance{BatchSize: b.BatchSize}
	}
	if len(iss.cfg.Display) > 0 {
		md.Display = make([]metadataDisplay, len(iss.cfg.Display))
		for i, d := range iss.cfg.Display {
			md.Display[i] = metadataDisplay{Name: d.Name, Locale: d.Locale, Logo: wireLogo(d.Logo)}
		}
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
		if c.CredentialMetadata != nil {
			wire.CredentialMetadata = wireCredentialMetadata(c.CredentialMetadata)
		}
		md.CredentialConfigurationsSupported[id] = wire
	}
	return md
}

// wireLogo converts a Logo to its wire shape, returning nil for a nil
// Logo.
func wireLogo(l *Logo) *metadataLogo {
	if l == nil {
		return nil
	}
	return &metadataLogo{URI: l.URI, AltText: l.AltText}
}

// wireCredentialMetadata converts a CredentialMetadata to its wire
// shape.
func wireCredentialMetadata(cm *CredentialMetadata) *metadataCredentialMetadata {
	wire := &metadataCredentialMetadata{}
	if len(cm.Display) > 0 {
		wire.Display = make([]metadataCredentialDisplay, len(cm.Display))
		for i, d := range cm.Display {
			cd := metadataCredentialDisplay{
				Name: d.Name, Locale: d.Locale, Description: d.Description,
				BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
				Logo: wireLogo(d.Logo),
			}
			if d.BackgroundImage != nil {
				cd.BackgroundImage = &metadataBackgroundImage{URI: d.BackgroundImage.URI}
			}
			wire.Display[i] = cd
		}
	}
	if len(cm.Claims) > 0 {
		wire.Claims = make([]metadataClaimsDescription, len(cm.Claims))
		for i, c := range cm.Claims {
			wc := metadataClaimsDescription{Path: c.Path, Mandatory: c.Mandatory}
			if len(c.Display) > 0 {
				wc.Display = make([]metadataClaimDisplay, len(c.Display))
				for j, cd := range c.Display {
					wc.Display[j] = metadataClaimDisplay(cd)
				}
			}
			wire.Claims[i] = wc
		}
	}
	return wire
}

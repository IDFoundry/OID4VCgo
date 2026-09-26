package oid4vci

import (
	"encoding/json"
	"fmt"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// KeyAttestationRequirement is a proof type's key_attestations_required
// object (§12.2.4): "the Credential Issuer expects the Wallet to send"
// a Key Attestation meeting these constraints. A present-but-empty
// value (both fields nil) means a key attestation is required with no
// further constraint — a Credential Issuer sets ProofTypeConfiguration's
// own KeyAttestationsRequired to a non-nil *KeyAttestationRequirement
// to require one at all, nil to not require one.
type KeyAttestationRequirement struct {
	// KeyStorage/UserAuthentication constrain which
	// attestation.AttackPotentialResistance values (Appendix D.2) an
	// issuer accepts, mirroring the Key Attestation claims of the same
	// name. Both OPTIONAL; non-empty if present.
	KeyStorage         []string `json:"key_storage,omitempty"`
	UserAuthentication []string `json:"user_authentication,omitempty"`
}

// ProofTypeConfiguration is one entry in a
// CredentialConfigurationMetadata's own ProofTypesSupported (§12.2.4).
type ProofTypeConfiguration struct {
	// ProofSigningAlgValuesSupported is REQUIRED: the algorithms an
	// issuer accepts a proof of this type to be signed with.
	ProofSigningAlgValuesSupported []string `json:"proof_signing_alg_values_supported"`

	// KeyAttestationsRequired, if non-nil, requires every proof of this
	// type to carry a Key Attestation — see the type's own doc comment.
	KeyAttestationsRequired *KeyAttestationRequirement `json:"key_attestations_required,omitempty"`
}

// Validate checks p's own structural requirements (§12.2.4) — not
// whether an issuer actually accepts a proof meeting them, that's the
// caller's own role-specific decision.
func (p ProofTypeConfiguration) Validate() error {
	if len(p.ProofSigningAlgValuesSupported) == 0 {
		return fmt.Errorf("proof_signing_alg_values_supported must not be empty")
	}
	return nil
}

// Logo is a "logo" object (§12.2.4/Appendix A) — the shared shape both
// Display's own Logo and CredentialDisplay's own Logo use.
type Logo struct {
	// URI is REQUIRED: where the Wallet can obtain the logo — any
	// scheme ("https:", "data:", ...); this package never fetches it.
	URI string `json:"uri"`

	// AltText is OPTIONAL: alternative text for the logo image.
	AltText string `json:"alt_text,omitempty"`
}

// Validate checks l's own structural requirements (§12.2.4/Appendix A).
func (l Logo) Validate() error {
	if l.URI == "" {
		return fmt.Errorf("uri is required")
	}
	return nil
}

// Display is one entry in Metadata's own top-level "display" (§12.2.4)
// — a Credential Issuer's own display properties for one language. At
// most one Display per distinct Locale (including "") is meaningful;
// this type doesn't reject a duplicate itself (§12.2.4 doesn't make it
// a MUST either) — describing, not policing, every SHOULD.
type Display struct {
	// Name is OPTIONAL: a display name for the Credential Issuer.
	Name string `json:"name,omitempty"`

	// Locale is OPTIONAL: a BCP47 language tag.
	Locale string `json:"locale,omitempty"`

	// Logo is OPTIONAL.
	Logo *Logo `json:"logo,omitempty"`
}

// Validate checks d's own structural requirements (§12.2.4).
func (d Display) Validate() error {
	if d.Logo != nil {
		if err := d.Logo.Validate(); err != nil {
			return fmt.Errorf("logo: %w", err)
		}
	}
	return nil
}

// BatchCredentialIssuance is Metadata's own optional
// "batch_credential_issuance" (§12.2.4): an issuer's own advertised
// support for more than one key proof per Credential Request.
type BatchCredentialIssuance struct {
	// BatchSize is REQUIRED: the maximum array size for a Credential
	// Request's own "proofs" parameter an issuer advertising this
	// supports. Must be 2 or greater.
	BatchSize int `json:"batch_size"`
}

// Validate checks b's own structural requirements (§12.2.4).
func (b BatchCredentialIssuance) Validate() error {
	if b.BatchSize < 2 {
		return fmt.Errorf("batch_size must be 2 or greater")
	}
	return nil
}

// BackgroundImage is CredentialDisplay's own "background_image" object
// (Appendix A).
type BackgroundImage struct {
	// URI is REQUIRED: where the Wallet can obtain the background
	// image.
	URI string `json:"uri"`
}

// CredentialDisplay is one entry in CredentialMetadata's own "display"
// array (Appendix A) — a Credential Configuration's own display
// properties for one language. Distinct from Display (the Credential
// *Issuer*-level display type): Name is REQUIRED here, unlike there.
type CredentialDisplay struct {
	// Name is REQUIRED: a display name for the Credential.
	Name string `json:"name"`

	Locale          string           `json:"locale,omitempty"`
	Logo            *Logo            `json:"logo,omitempty"`
	Description     string           `json:"description,omitempty"`
	BackgroundColor string           `json:"background_color,omitempty"`
	BackgroundImage *BackgroundImage `json:"background_image,omitempty"`
	TextColor       string           `json:"text_color,omitempty"`
}

// Validate checks cd's own structural requirements (Appendix A).
func (cd CredentialDisplay) Validate() error {
	if cd.Name == "" {
		return fmt.Errorf("name is required")
	}
	if cd.Logo != nil {
		if err := cd.Logo.Validate(); err != nil {
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
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// ClaimsDescription is one entry in CredentialMetadata's own "claims"
// array (Appendix B.2): how one claim in the issued Credential is
// displayed to the End-User. Path is a Claims Path Pointer (Appendix
// C) — the exact same wire shape OID4VP's own dcql.Path implements
// (§7.1 there: a non-empty array of strings, nulls, and non-negative
// integers), kept here as a plain []any rather than importing that
// OID4VP-specific package: describing display metadata never needs
// dcql.Path's own Select/evaluation behavior, only its wire shape, and
// this OID4VCI-side type has no reason to depend on an OID4VP one for
// that.
type ClaimsDescription struct {
	// Path is REQUIRED: each element a string, nil (wire null, "select
	// every array element"), or non-negative int.
	Path []any `json:"path"`

	// Mandatory is OPTIONAL, default false — use IsMandatory to read
	// the effective value.
	Mandatory *bool `json:"mandatory,omitempty"`

	// Display is OPTIONAL.
	Display []ClaimDisplay `json:"display,omitempty"`
}

// IsMandatory reports c's own effective value — false unless Mandatory
// was explicitly set to true (Appendix B.2's own default).
func (c ClaimsDescription) IsMandatory() bool {
	return c.Mandatory != nil && *c.Mandatory
}

// Validate checks c's own structural requirements (Appendix B.2).
func (c ClaimsDescription) Validate() error {
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

// CredentialMetadata is a CredentialConfigurationMetadata's own
// optional "credential_metadata" object (Appendix A): display/claims
// metadata for the issued Credential. Format-specific mechanisms (e.g.
// SD-JWT VC's own type metadata) are always preferred by the Wallet
// over this, which serves only as a fallback default (Appendix A's own
// text) — this type makes no attempt to keep the two in sync.
type CredentialMetadata struct {
	// Display and Claims are both OPTIONAL; non-empty if present.
	Display []CredentialDisplay `json:"display,omitempty"`
	Claims  []ClaimsDescription `json:"claims,omitempty"`
}

// Validate checks cm's own structural requirements (Appendix A/B.2).
func (cm CredentialMetadata) Validate() error {
	for i, d := range cm.Display {
		if err := d.Validate(); err != nil {
			return fmt.Errorf("display[%d]: %w", i, err)
		}
	}
	for i, c := range cm.Claims {
		if err := c.Validate(); err != nil {
			return fmt.Errorf("claims[%d]: %w", i, err)
		}
	}
	return nil
}

// CredentialConfigurationMetadata is one entry in Metadata's own
// "credential_configurations_supported" (§12.2.4) — the wire shape of
// one Credential an issuer publishes support for. Distinct from
// issuer.CredentialConfiguration (that package's own Go-ergonomic
// *input* shape, which a Credential Issuer builds one of these from):
// CredentialSigningAlgValuesSupported is untyped here because the wire
// carries either JOSE alg strings or COSE alg numbers depending on
// Format, where issuer.CredentialConfiguration instead exposes two
// separate typed fields for the same reason RequestCredential wants
// (build-time type safety) that a wire decoder doesn't.
type CredentialConfigurationMetadata struct {
	// Format is REQUIRED — a Credential Format Identifier such as
	// credential/sdjwtvc.CredentialFormat ("dc+sd-jwt").
	Format string `json:"format"`

	// Scope is OPTIONAL: the Authorization Request scope value that
	// selects this Credential.
	Scope string `json:"scope,omitempty"`

	// CryptographicBindingMethodsSupported is REQUIRED when
	// Cryptographic Key Binding applies to this Credential; omitted
	// otherwise.
	CryptographicBindingMethodsSupported []string `json:"cryptographic_binding_methods_supported,omitempty"`

	// CredentialSigningAlgValuesSupported is OPTIONAL: either a
	// []string of JOSE alg values or a []int/[]float64 of COSE alg
	// numbers (Appendix A.2.2), depending on Format — decode into the
	// shape Format implies, or inspect it with a type switch.
	CredentialSigningAlgValuesSupported any `json:"credential_signing_alg_values_supported,omitempty"`

	// ProofTypesSupported is REQUIRED exactly when
	// CryptographicBindingMethodsSupported is present, keyed by proof
	// type identifier (ProofTypeJWT, ProofTypeAttestation).
	ProofTypesSupported map[string]ProofTypeConfiguration `json:"proof_types_supported,omitempty"`

	// VCT is credential/sdjwtvc's own format-specific metadata
	// parameter (Appendix A.3.2): present when Format is
	// credential/sdjwtvc.CredentialFormat, meaningless otherwise.
	VCT string `json:"vct,omitempty"`

	// DocType is credential/mdoc's own format-specific metadata
	// parameter (Appendix A.2.2): present when Format is
	// credential/mdoc.CredentialFormat, meaningless otherwise.
	DocType string `json:"doctype,omitempty"`

	// CredentialMetadata is OPTIONAL (Appendix A).
	CredentialMetadata *CredentialMetadata `json:"credential_metadata,omitempty"`
}

// JWK is a JSON Web Key (RFC 7517) plus the "kid"/"alg" every entry in
// an encryption jwks needs — internal/jwk.JWK itself has neither field,
// since both are contextual to where a key is published, not part of
// the key material Marshal encodes. §10's own "The alg parameter MUST
// be present. The JWE alg algorithm used MUST be equal to the alg
// value of the chosen JWK" makes Alg REQUIRED here, not optional
// metadata — confirmed live: the OIDF suite's own
// VCICheckCredentialRequestEncryptionSupported check rejects a
// published key with no "alg" member outright ("expected at least one
// key with... an asymmetric JWE alg").
//
// The embedded internal/jwk.JWK's own PublicKey() method promotes
// onto this type (json.Unmarshal into a JWK, then call .PublicKey())
// — a caller outside this module that only needs to decode a fetched
// JWK back into a crypto.PublicKey (e.g. to build its own
// verifier.SDJWTVCIssuerKeyResolver against a pinned Issuer key) can
// use this exported type for that, without needing internal/jwk
// itself. Alg here is specifically the JWE encryption algorithm
// (§10's own contract above); a signing-algorithm use case needs its
// own alg field alongside this type, the same way this repo's own
// cmd/conformance-verifier does.
type JWK struct {
	jwk.JWK
	Kid string  `json:"kid"`
	Alg jwe.Alg `json:"alg"`
}

// JWKSet is a JSON Web Key Set (RFC 7517 §5) — §12.2.4's own "jwks"
// member is REQUIRED to be one (a {"keys": [...]} object, not a bare
// JSON array of keys).
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// RequestEncryptionMetadata is Metadata's own "credential_request_encryption"
// (§12.2.4) — the wire shape of an issuer's own advertised support for
// §10 Credential Request encryption. Distinct from
// issuer.RequestEncryptionSupport (that package's own input shape,
// which holds private decryption keys, not the public JWKS this
// publishes).
type RequestEncryptionMetadata struct {
	JWKS               JWKSet    `json:"jwks"`
	EncValuesSupported []jwe.Enc `json:"enc_values_supported"`
	ZipValuesSupported []jwe.Zip `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool      `json:"encryption_required"`
}

// ResponseEncryptionMetadata is Metadata's own "credential_response_encryption"
// (§12.2.4) — the wire shape of an issuer's own advertised support for
// §10 Credential Response encryption. AlgValuesSupported is always
// exactly ["ECDH-ES"] for every issuer this repo builds (see
// issuer.ResponseEncryptionSupport's own doc comment for why).
type ResponseEncryptionMetadata struct {
	AlgValuesSupported []jwe.Alg `json:"alg_values_supported"`
	EncValuesSupported []jwe.Enc `json:"enc_values_supported"`
	ZipValuesSupported []jwe.Zip `json:"zip_values_supported,omitempty"`
	EncryptionRequired bool      `json:"encryption_required"`
}

// Metadata is a Credential Issuer's own Credential Issuer Metadata
// document (§12.2.4) — issuer.Issuer.Metadata() builds one to serve at
// GET /.well-known/openid-credential-issuer, and
// wallet.FetchCredentialIssuerMetadata decodes one fetched from there.
type Metadata struct {
	CredentialIssuer fapi.URL `json:"credential_issuer"`
	// AuthorizationServers are the OAuth 2.0 Authorization Servers
	// (their issuer identifiers) this Credential Issuer relies on
	// (§12.2.4). OPTIONAL: when absent, the Credential Issuer is its
	// own Authorization Server. With more than one, a Credential Offer
	// grant's authorization_server says which one to use.
	AuthorizationServers              []fapi.URL                                 `json:"authorization_servers,omitempty"`
	CredentialEndpoint                fapi.URL                                   `json:"credential_endpoint"`
	NonceEndpoint                     *fapi.URL                                  `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint        *fapi.URL                                  `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              *fapi.URL                                  `json:"notification_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfigurationMetadata `json:"credential_configurations_supported"`
	CredentialRequestEncryption       *RequestEncryptionMetadata                 `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption      *ResponseEncryptionMetadata                `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           *BatchCredentialIssuance                   `json:"batch_credential_issuance,omitempty"`
	Display                           []Display                                  `json:"display,omitempty"`
}

// wireMetadata is Metadata's own decode-only wire shape: fapi.URL's
// own MarshalJSON has no UnmarshalJSON counterpart — its own doc
// comment explains why ("parsing a URL back out needs one of
// ParseIssuerURL/ParseEndpointURL's validation modes, a choice a
// generic decoder can't make on the caller's behalf") — so
// UnmarshalJSON below decodes into this plain-string shape first, then
// makes that choice itself: ParseIssuerURL for CredentialIssuer (an
// Issuer identifier) and each AuthorizationServers entry (an
// Authorization Server's issuer identifier), ParseEndpointURL for
// every other URL field (a
// plain reachable endpoint), matching issuer.Config's own identical
// split between its Issuer and Endpoints fields.
type wireMetadata struct {
	CredentialIssuer                  string                                     `json:"credential_issuer"`
	AuthorizationServers              []string                                   `json:"authorization_servers,omitempty"`
	CredentialEndpoint                string                                     `json:"credential_endpoint"`
	NonceEndpoint                     *string                                    `json:"nonce_endpoint,omitempty"`
	DeferredCredentialEndpoint        *string                                    `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint              *string                                    `json:"notification_endpoint,omitempty"`
	CredentialConfigurationsSupported map[string]CredentialConfigurationMetadata `json:"credential_configurations_supported"`
	CredentialRequestEncryption       *RequestEncryptionMetadata                 `json:"credential_request_encryption,omitempty"`
	CredentialResponseEncryption      *ResponseEncryptionMetadata                `json:"credential_response_encryption,omitempty"`
	BatchCredentialIssuance           *BatchCredentialIssuance                   `json:"batch_credential_issuance,omitempty"`
	Display                           []Display                                  `json:"display,omitempty"`
}

// UnmarshalJSON decodes m per §12.2.4 — see wireMetadata's own doc
// comment for why this is a custom implementation, not the default
// struct decode.
func (m *Metadata) UnmarshalJSON(data []byte) error {
	var wire wireMetadata
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	issuerURL, err := fapi.ParseIssuerURL(wire.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("credential_issuer: %w", err)
	}
	var authorizationServers []fapi.URL
	for i, raw := range wire.AuthorizationServers {
		u, err := fapi.ParseIssuerURL(raw)
		if err != nil {
			return fmt.Errorf("authorization_servers[%d]: %w", i, err)
		}
		authorizationServers = append(authorizationServers, u)
	}
	credentialURL, err := fapi.ParseEndpointURL(wire.CredentialEndpoint)
	if err != nil {
		return fmt.Errorf("credential_endpoint: %w", err)
	}
	nonceURL, err := parseOptionalEndpointURL("nonce_endpoint", wire.NonceEndpoint)
	if err != nil {
		return err
	}
	deferredURL, err := parseOptionalEndpointURL("deferred_credential_endpoint", wire.DeferredCredentialEndpoint)
	if err != nil {
		return err
	}
	notificationURL, err := parseOptionalEndpointURL("notification_endpoint", wire.NotificationEndpoint)
	if err != nil {
		return err
	}

	*m = Metadata{
		CredentialIssuer: issuerURL, AuthorizationServers: authorizationServers, CredentialEndpoint: credentialURL,
		NonceEndpoint: nonceURL, DeferredCredentialEndpoint: deferredURL, NotificationEndpoint: notificationURL,
		CredentialConfigurationsSupported: wire.CredentialConfigurationsSupported,
		CredentialRequestEncryption:       wire.CredentialRequestEncryption,
		CredentialResponseEncryption:      wire.CredentialResponseEncryption,
		BatchCredentialIssuance:           wire.BatchCredentialIssuance,
		Display:                           wire.Display,
	}
	return nil
}

// parseOptionalEndpointURL parses raw (nil means the field was absent)
// as an endpoint URL, returning nil unchanged — shared by
// UnmarshalJSON's three optional *fapi.URL fields.
func parseOptionalEndpointURL(field string, raw *string) (*fapi.URL, error) {
	if raw == nil {
		return nil, nil
	}
	u, err := fapi.ParseEndpointURL(*raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return &u, nil
}

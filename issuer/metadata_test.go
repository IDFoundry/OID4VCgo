package issuer_test

import (
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/issuer"
)

// marshalWire JSON-round-trips v (typically a Metadata) into a generic
// map, for asserting on the actual wire member names/types rather than
// Go field names.
func marshalWire(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return wire
}

func TestMetadata(t *testing.T) {
	cfg := validConfig(t)
	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	md := iss.Metadata()
	if md.CredentialIssuer.String() != testIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", md.CredentialIssuer.String(), testIssuer)
	}
	if md.CredentialEndpoint.String() != testCredentialEndpoint {
		t.Errorf("CredentialEndpoint = %q, want %q", md.CredentialEndpoint.String(), testCredentialEndpoint)
	}
	if md.NonceEndpoint == nil || md.NonceEndpoint.String() != testNonceEndpoint {
		t.Errorf("NonceEndpoint = %v, want %q", md.NonceEndpoint, testNonceEndpoint)
	}
	if md.DeferredCredentialEndpoint == nil || md.DeferredCredentialEndpoint.String() != testDeferredCredentialEndpoint {
		t.Errorf("DeferredCredentialEndpoint = %v, want %q", md.DeferredCredentialEndpoint, testDeferredCredentialEndpoint)
	}
	if md.NotificationEndpoint == nil || md.NotificationEndpoint.String() != testNotificationEndpoint {
		t.Errorf("NotificationEndpoint = %v, want %q", md.NotificationEndpoint, testNotificationEndpoint)
	}
	if len(md.CredentialConfigurationsSupported) != 1 {
		t.Fatalf("got %d credential configurations, want 1", len(md.CredentialConfigurationsSupported))
	}

	wire := marshalWire(t, md)
	if wire["credential_issuer"] != testIssuer {
		t.Errorf("wire credential_issuer = %v", wire["credential_issuer"])
	}
	if wire["credential_endpoint"] != testCredentialEndpoint {
		t.Errorf("wire credential_endpoint = %v", wire["credential_endpoint"])
	}
	if wire["nonce_endpoint"] != testNonceEndpoint {
		t.Errorf("wire nonce_endpoint = %v", wire["nonce_endpoint"])
	}
	if wire["deferred_credential_endpoint"] != testDeferredCredentialEndpoint {
		t.Errorf("wire deferred_credential_endpoint = %v", wire["deferred_credential_endpoint"])
	}
	if wire["notification_endpoint"] != testNotificationEndpoint {
		t.Errorf("wire notification_endpoint = %v", wire["notification_endpoint"])
	}

	configs, ok := wire["credential_configurations_supported"].(map[string]any)
	if !ok {
		t.Fatalf("credential_configurations_supported is not an object: %v", wire["credential_configurations_supported"])
	}
	idc, ok := configs["IdentityCredential"].(map[string]any)
	if !ok {
		t.Fatalf("IdentityCredential entry is not an object: %v", configs["IdentityCredential"])
	}
	if idc["format"] != "dc+sd-jwt" {
		t.Errorf("format = %v", idc["format"])
	}
	if idc["vct"] != "https://credentials.example.com/identity_credential" {
		t.Errorf("vct = %v", idc["vct"])
	}
	algs, ok := idc["credential_signing_alg_values_supported"].([]any)
	if !ok || len(algs) != 1 || algs[0] != "ES256" {
		t.Errorf("credential_signing_alg_values_supported = %v, want [ES256] as strings", idc["credential_signing_alg_values_supported"])
	}
	proofTypes, ok := idc["proof_types_supported"].(map[string]any)
	if !ok {
		t.Fatalf("proof_types_supported is not an object: %v", idc["proof_types_supported"])
	}
	if _, ok := proofTypes[oid4vci.ProofTypeJWT]; !ok {
		t.Errorf("proof_types_supported is missing %q: %v", oid4vci.ProofTypeJWT, proofTypes)
	}
}

func TestMetadata_OmitsNonceEndpointWhenDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies(t)
	deps.Nonces = nil

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()
	if md.NonceEndpoint != nil {
		t.Errorf("NonceEndpoint = %v, want nil", md.NonceEndpoint)
	}

	wire := marshalWire(t, md)
	if _, ok := wire["nonce_endpoint"]; ok {
		t.Errorf("wire form still has nonce_endpoint: %v", wire["nonce_endpoint"])
	}
}

func TestMetadata_OmitsDeferredCredentialEndpointWhenDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.DeferredCredential = fapi.URL{}
	cfg.Limits.DeferredIssuancePollInterval = 0
	deps := validDependencies(t)
	deps.DeferredTransactions = nil

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()
	if md.DeferredCredentialEndpoint != nil {
		t.Errorf("DeferredCredentialEndpoint = %v, want nil", md.DeferredCredentialEndpoint)
	}

	wire := marshalWire(t, md)
	if _, ok := wire["deferred_credential_endpoint"]; ok {
		t.Errorf("wire form still has deferred_credential_endpoint: %v", wire["deferred_credential_endpoint"])
	}
}

func TestMetadata_OmitsNotificationEndpointWhenDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Notification = fapi.URL{}
	deps := validDependencies(t)
	deps.Notifications = nil

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()
	if md.NotificationEndpoint != nil {
		t.Errorf("NotificationEndpoint = %v, want nil", md.NotificationEndpoint)
	}

	wire := marshalWire(t, md)
	if _, ok := wire["notification_endpoint"]; ok {
		t.Errorf("wire form still has notification_endpoint: %v", wire["notification_endpoint"])
	}
}

// mdlCredentialConfiguration is the shared base for every test needing
// a mso_mdoc CredentialConfiguration — Appendix A.2.2's own
// non-normative "org.iso.18013.5.1.mDL" example, minus credential_metadata.
func mdlCredentialConfiguration() issuer.CredentialConfiguration {
	return issuer.CredentialConfiguration{
		Format:                                  mdoc.CredentialFormat,
		DocType:                                 "org.iso.18013.5.1.mDL",
		CryptographicBindingMethodsSupported:    []string{"cose_key"},
		CredentialSigningAlgValuesSupportedCOSE: []cose.Alg{cose.ES256, -9},
		ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
	}
}

// TestMetadata_MdocFormat checks the wire shape against OID4VCI 1.0
// Appendix A.2.2's own non-normative example: numeric COSE algorithm
// identifiers as bare JSON numbers (not JOSE alg strings), and doctype
// present.
func TestMetadata_MdocFormat(t *testing.T) {
	cfg := validConfig(t)
	cfg.CredentialConfigurationsSupported["MobileDrivingLicence"] = mdlCredentialConfiguration()

	deps := validDependencies(t)
	deps.MdocSigner = testMdocSigner(t)
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wire := marshalWire(t, iss.Metadata())
	configs := wire["credential_configurations_supported"].(map[string]any)
	mdl, ok := configs["MobileDrivingLicence"].(map[string]any)
	if !ok {
		t.Fatalf("MobileDrivingLicence entry is not an object: %v", configs["MobileDrivingLicence"])
	}
	if mdl["format"] != mdoc.CredentialFormat {
		t.Errorf("format = %v, want %q", mdl["format"], mdoc.CredentialFormat)
	}
	if mdl["doctype"] != "org.iso.18013.5.1.mDL" {
		t.Errorf("doctype = %v", mdl["doctype"])
	}
	algs, ok := mdl["credential_signing_alg_values_supported"].([]any)
	if !ok || len(algs) != 2 || algs[0] != float64(-7) || algs[1] != float64(-9) {
		t.Errorf("credential_signing_alg_values_supported = %v, want [-7 -9] as numbers", mdl["credential_signing_alg_values_supported"])
	}
	if _, hasVCT := mdl["vct"]; hasVCT {
		t.Errorf("wire form has vct for an mdoc config: %v", mdl["vct"])
	}
}

// TestMetadata_SpecWorkedExample mirrors OID4VCI 1.0 Appendix I.1's own
// non-normative Credential Issuer Metadata example (batch_credential_issuance,
// top-level display, and one credential_configurations_supported
// entry's credential_metadata, including its claims array's own Claims
// Path Pointers) — verifying the actual wire JSON against the spec's
// own worked values, not just a round-trip.
func TestMetadata_SpecWorkedExample(t *testing.T) {
	cfg := validConfig(t)
	cfg.Display = []oid4vci.Display{
		{
			Name: "Example University", Locale: "en-US",
			Logo: &oid4vci.Logo{URI: "https://university.example.edu/public/logo.png", AltText: "a square logo of a university"},
		},
		{
			Name: "Example Université", Locale: "fr-FR",
			Logo: &oid4vci.Logo{URI: "https://university.example.edu/public/logo.png", AltText: "Un logo universitaire carré"},
		},
	}
	cfg.BatchCredentialIssuance = &oid4vci.BatchCredentialIssuance{BatchSize: 10}
	cfg.CredentialConfigurationsSupported["SD_JWT_VC_example_in_OpenID4VCI"] = issuer.CredentialConfiguration{
		Format:                               "dc+sd-jwt",
		Scope:                                "SD_JWT_VC_example_in_OpenID4VCI",
		VCT:                                  "SD_JWT_VC_example_in_OpenID4VCI",
		CryptographicBindingMethodsSupported: []string{"jwk"},
		CredentialSigningAlgValuesSupported:  []string{"ES256"},
		ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {
				ProofSigningAlgValuesSupported: []string{"ES256"},
				KeyAttestationsRequired: &oid4vci.KeyAttestationRequirement{
					KeyStorage:         []string{"iso_18045_moderate"},
					UserAuthentication: []string{"iso_18045_moderate"},
				},
			},
		},
		CredentialMetadata: &oid4vci.CredentialMetadata{
			Display: []oid4vci.CredentialDisplay{
				{
					Name: "IdentityCredential", Locale: "en-US",
					Logo: &oid4vci.Logo{
						URI:     "https://university.example.edu/public/logo_credential.png",
						AltText: "a square logo of a university credential",
					},
					Description:     "A credential that signals the membership of a university",
					BackgroundColor: "#12107c",
					TextColor:       "#FFFFFF",
				},
			},
			Claims: []oid4vci.ClaimsDescription{
				{Path: []any{"given_name"}, Display: []oid4vci.ClaimDisplay{
					{Name: "Given Name", Locale: "en-US"}, {Name: "Vorname", Locale: "de-DE"},
				}},
				{Path: []any{"family_name"}, Display: []oid4vci.ClaimDisplay{
					{Name: "Surname", Locale: "en-US"}, {Name: "Nachname", Locale: "de-DE"},
				}},
				{Path: []any{"email"}},
				{Path: []any{"phone_number"}},
				{Path: []any{"address"}, Display: []oid4vci.ClaimDisplay{
					{Name: "Place of residence", Locale: "en-US"}, {Name: "Wohnsitz", Locale: "de-DE"},
				}},
				{Path: []any{"address", "street_address"}},
				{Path: []any{"address", "locality"}},
				{Path: []any{"address", "region"}},
				{Path: []any{"address", "country"}},
				{Path: []any{"birthdate"}},
				{Path: []any{"is_over_18"}},
				{Path: []any{"is_over_21"}},
				{Path: []any{"is_over_65"}},
			},
		},
	}

	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wire := marshalWire(t, iss.Metadata())

	batch, ok := wire["batch_credential_issuance"].(map[string]any)
	if !ok || batch["batch_size"] != float64(10) {
		t.Errorf("batch_credential_issuance = %v, want batch_size 10", wire["batch_credential_issuance"])
	}

	display, ok := wire["display"].([]any)
	if !ok || len(display) != 2 {
		t.Fatalf("display = %v, want a 2-element array", wire["display"])
	}
	first := display[0].(map[string]any)
	if first["name"] != "Example University" || first["locale"] != "en-US" {
		t.Errorf("display[0] = %v", first)
	}
	firstLogo := first["logo"].(map[string]any)
	if firstLogo["uri"] != "https://university.example.edu/public/logo.png" || firstLogo["alt_text"] != "a square logo of a university" {
		t.Errorf("display[0].logo = %v", firstLogo)
	}
	second := display[1].(map[string]any)
	if second["name"] != "Example Université" || second["locale"] != "fr-FR" {
		t.Errorf("display[1] = %v", second)
	}

	configs := wire["credential_configurations_supported"].(map[string]any)
	sdjwt := configs["SD_JWT_VC_example_in_OpenID4VCI"].(map[string]any)
	cm, ok := sdjwt["credential_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("credential_metadata missing: %v", sdjwt)
	}

	cmDisplay, ok := cm["display"].([]any)
	if !ok || len(cmDisplay) != 1 {
		t.Fatalf("credential_metadata.display = %v, want a 1-element array", cm["display"])
	}
	cd := cmDisplay[0].(map[string]any)
	if cd["name"] != "IdentityCredential" || cd["background_color"] != "#12107c" || cd["text_color"] != "#FFFFFF" {
		t.Errorf("credential_metadata.display[0] = %v", cd)
	}
	if cd["description"] != "A credential that signals the membership of a university" {
		t.Errorf("credential_metadata.display[0].description = %v", cd["description"])
	}

	claims, ok := cm["claims"].([]any)
	if !ok || len(claims) != 13 {
		t.Fatalf("credential_metadata.claims = %v, want 13 entries", cm["claims"])
	}
	givenName := claims[0].(map[string]any)
	gnPath, ok := givenName["path"].([]any)
	if !ok || len(gnPath) != 1 || gnPath[0] != "given_name" {
		t.Errorf("claims[0].path = %v, want [given_name]", givenName["path"])
	}
	gnDisplay, ok := givenName["display"].([]any)
	if !ok || len(gnDisplay) != 2 {
		t.Fatalf("claims[0].display = %v, want a 2-element array", givenName["display"])
	}
	if gnDisplay[0].(map[string]any)["name"] != "Given Name" || gnDisplay[1].(map[string]any)["name"] != "Vorname" {
		t.Errorf("claims[0].display = %v", gnDisplay)
	}

	email := claims[2].(map[string]any)
	if _, hasDisplay := email["display"]; hasDisplay {
		t.Errorf("claims[2] (email) has display, want none: %v", email)
	}
	if _, hasMandatory := email["mandatory"]; hasMandatory {
		t.Errorf("claims[2] (email) has mandatory, want omitted (default false): %v", email)
	}

	streetAddress := claims[5].(map[string]any)
	saPath, ok := streetAddress["path"].([]any)
	if !ok || len(saPath) != 2 || saPath[0] != "address" || saPath[1] != "street_address" {
		t.Errorf("claims[5].path = %v, want [address street_address]", streetAddress["path"])
	}
}

func TestMetadata_OmitsBatchCredentialIssuanceAndDisplayByDefault(t *testing.T) {
	iss, err := issuer.New(validConfig(t), validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wire := marshalWire(t, iss.Metadata())
	if _, ok := wire["batch_credential_issuance"]; ok {
		t.Errorf("wire form has batch_credential_issuance: %v", wire["batch_credential_issuance"])
	}
	if _, ok := wire["display"]; ok {
		t.Errorf("wire form has display: %v", wire["display"])
	}
	configs := wire["credential_configurations_supported"].(map[string]any)
	idc := configs["IdentityCredential"].(map[string]any)
	if _, ok := idc["credential_metadata"]; ok {
		t.Errorf("wire form has credential_metadata: %v", idc["credential_metadata"])
	}
}

// TestClaimsDescriptionIsMandatory checks IsMandatory's own "default
// false" reader semantics (Appendix B.2).
func TestClaimsDescriptionIsMandatory(t *testing.T) {
	unset := oid4vci.ClaimsDescription{Path: []any{"x"}}
	if unset.IsMandatory() {
		t.Errorf("IsMandatory() = true for an unset Mandatory, want false")
	}
	falseVal := false
	explicitFalse := oid4vci.ClaimsDescription{Path: []any{"x"}, Mandatory: &falseVal}
	if explicitFalse.IsMandatory() {
		t.Errorf("IsMandatory() = true for an explicit false, want false")
	}
	trueVal := true
	explicitTrue := oid4vci.ClaimsDescription{Path: []any{"x"}, Mandatory: &trueVal}
	if !explicitTrue.IsMandatory() {
		t.Errorf("IsMandatory() = false for an explicit true, want true")
	}
}

// TestMetadata_MdocCredentialMetadata mirrors Appendix A.2.2's own
// non-normative example: mdoc claims use the exact same
// credential_metadata mechanism as dc+sd-jwt, just with a two-element
// path of [namespace, element] rather than a separate mdoc-specific
// wire member.
func TestMetadata_MdocCredentialMetadata(t *testing.T) {
	trueVal := true
	cfg := validConfig(t)
	mdlConfig := mdlCredentialConfiguration()
	mdlConfig.CredentialMetadata = &oid4vci.CredentialMetadata{
		Claims: []oid4vci.ClaimsDescription{
			{Path: []any{"org.iso.18013.5.1", "given_name"}, Display: []oid4vci.ClaimDisplay{
				{Name: "Given Name", Locale: "en-US"},
			}},
			{Path: []any{"org.iso.18013.5.1", "birth_date"}, Mandatory: &trueVal},
			{Path: []any{"org.iso.18013.5.1.aamva", "organ_donor"}},
		},
	}
	cfg.CredentialConfigurationsSupported["MobileDrivingLicence"] = mdlConfig

	deps := validDependencies(t)
	deps.MdocSigner = testMdocSigner(t)
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wire := marshalWire(t, iss.Metadata())
	configs := wire["credential_configurations_supported"].(map[string]any)
	mdl := configs["MobileDrivingLicence"].(map[string]any)
	cm := mdl["credential_metadata"].(map[string]any)
	claims := cm["claims"].([]any)
	if len(claims) != 3 {
		t.Fatalf("claims = %v, want 3 entries", claims)
	}

	givenName := claims[0].(map[string]any)
	path := givenName["path"].([]any)
	if len(path) != 2 || path[0] != "org.iso.18013.5.1" || path[1] != "given_name" {
		t.Errorf("claims[0].path = %v, want [org.iso.18013.5.1 given_name]", path)
	}

	birthDate := claims[1].(map[string]any)
	if birthDate["mandatory"] != true {
		t.Errorf("claims[1].mandatory = %v, want true", birthDate["mandatory"])
	}
}

func TestMetadata_KeyAttestationRequirement(t *testing.T) {
	cfg := validConfig(t)
	cc := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"ES256"},
			KeyAttestationsRequired: &oid4vci.KeyAttestationRequirement{
				KeyStorage: []string{"iso_18045_moderate"},
			},
		},
	}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = cc

	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	wire := marshalWire(t, iss.Metadata())
	configs := wire["credential_configurations_supported"].(map[string]any)
	idc := configs["IdentityCredential"].(map[string]any)
	proofTypes := idc["proof_types_supported"].(map[string]any)
	jwtProof := proofTypes[oid4vci.ProofTypeJWT].(map[string]any)
	kar, ok := jwtProof["key_attestations_required"].(map[string]any)
	if !ok {
		t.Fatalf("key_attestations_required missing: %v", jwtProof)
	}
	storage, ok := kar["key_storage"].([]any)
	if !ok || len(storage) != 1 || storage[0] != "iso_18045_moderate" {
		t.Errorf("key_storage = %v", kar["key_storage"])
	}
}

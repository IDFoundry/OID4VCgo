package issuer_test

import (
	"encoding/json"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/issuer"
)

func TestMetadata(t *testing.T) {
	cfg := validConfig(t)
	iss, err := issuer.New(cfg, validDependencies())
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
	if len(md.CredentialConfigurationsSupported) != 1 {
		t.Fatalf("got %d credential configurations, want 1", len(md.CredentialConfigurationsSupported))
	}

	raw, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if wire["credential_issuer"] != testIssuer {
		t.Errorf("wire credential_issuer = %v", wire["credential_issuer"])
	}
	if wire["credential_endpoint"] != testCredentialEndpoint {
		t.Errorf("wire credential_endpoint = %v", wire["credential_endpoint"])
	}
	if wire["nonce_endpoint"] != testNonceEndpoint {
		t.Errorf("wire nonce_endpoint = %v", wire["nonce_endpoint"])
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
	if _, ok := proofTypes[issuer.ProofTypeJWT]; !ok {
		t.Errorf("proof_types_supported is missing %q: %v", issuer.ProofTypeJWT, proofTypes)
	}
}

func TestMetadata_OmitsNonceEndpointWhenDisabled(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies()
	deps.Nonces = nil

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	md := iss.Metadata()
	if md.NonceEndpoint != nil {
		t.Errorf("NonceEndpoint = %v, want nil", md.NonceEndpoint)
	}

	raw, err := json.Marshal(md)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if _, ok := wire["nonce_endpoint"]; ok {
		t.Errorf("wire form still has nonce_endpoint: %v", wire["nonce_endpoint"])
	}
}

// TestMetadata_MdocFormat checks the wire shape against OID4VCI 1.0
// Appendix A.2.2's own non-normative example: numeric COSE algorithm
// identifiers as bare JSON numbers (not JOSE alg strings), and doctype
// present.
func TestMetadata_MdocFormat(t *testing.T) {
	cfg := validConfig(t)
	cfg.CredentialConfigurationsSupported["MobileDrivingLicence"] = issuer.CredentialConfiguration{
		Format:                                  mdoc.CredentialFormat,
		DocType:                                 "org.iso.18013.5.1.mDL",
		CryptographicBindingMethodsSupported:    []string{"cose_key"},
		CredentialSigningAlgValuesSupportedCOSE: []cose.Alg{cose.ES256, -9},
		ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
			issuer.ProofTypeJWT: {ProofSigningAlgValuesSupported: []string{"ES256"}},
		},
	}

	iss, err := issuer.New(cfg, validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := json.Marshal(iss.Metadata())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
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

func TestMetadata_KeyAttestationRequirement(t *testing.T) {
	cfg := validConfig(t)
	cc := cfg.CredentialConfigurationsSupported["IdentityCredential"]
	cc.ProofTypesSupported = map[string]issuer.ProofTypeConfiguration{
		issuer.ProofTypeJWT: {
			ProofSigningAlgValuesSupported: []string{"ES256"},
			KeyAttestationsRequired: &issuer.KeyAttestationRequirement{
				KeyStorage: []string{"iso_18045_moderate"},
			},
		},
	}
	cfg.CredentialConfigurationsSupported["IdentityCredential"] = cc

	iss, err := issuer.New(cfg, validDependencies())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := json.Marshal(iss.Metadata())
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	configs := wire["credential_configurations_supported"].(map[string]any)
	idc := configs["IdentityCredential"].(map[string]any)
	proofTypes := idc["proof_types_supported"].(map[string]any)
	jwtProof := proofTypes[issuer.ProofTypeJWT].(map[string]any)
	kar, ok := jwtProof["key_attestations_required"].(map[string]any)
	if !ok {
		t.Fatalf("key_attestations_required missing: %v", jwtProof)
	}
	storage, ok := kar["key_storage"].([]any)
	if !ok || len(storage) != 1 || storage[0] != "iso_18045_moderate" {
		t.Errorf("key_storage = %v", kar["key_storage"])
	}
}

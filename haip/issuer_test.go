package haip_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func TestRecommendedJWTProofType(t *testing.T) {
	ptc := haip.RecommendedJWTProofType()
	if len(ptc.ProofSigningAlgValuesSupported) != 1 || ptc.ProofSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("ProofSigningAlgValuesSupported = %v, want [ES256]", ptc.ProofSigningAlgValuesSupported)
	}
	if ptc.KeyAttestationsRequired != nil {
		t.Errorf("KeyAttestationsRequired = %v, want nil", ptc.KeyAttestationsRequired)
	}
}

func TestRecommendedAttestationProofType(t *testing.T) {
	ptc := haip.RecommendedAttestationProofType()
	if len(ptc.ProofSigningAlgValuesSupported) != 1 || ptc.ProofSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("ProofSigningAlgValuesSupported = %v, want [ES256]", ptc.ProofSigningAlgValuesSupported)
	}
	if ptc.KeyAttestationsRequired == nil {
		t.Fatalf("KeyAttestationsRequired = nil, want non-nil")
	}
	if len(ptc.KeyAttestationsRequired.KeyStorage) != 0 || len(ptc.KeyAttestationsRequired.UserAuthentication) != 0 {
		t.Errorf("KeyAttestationsRequired = %+v, want no further constraint", ptc.KeyAttestationsRequired)
	}
}

func TestRecommendedIssuerConfig(t *testing.T) {
	rec := haip.RecommendedIssuerConfig()
	if len(rec.ProofTypesSupported) != 1 {
		t.Fatalf("ProofTypesSupported has %d entries, want 1 (jwt)", len(rec.ProofTypesSupported))
	}
	jwtPTC, ok := rec.ProofTypesSupported[oid4vci.ProofTypeJWT]
	if !ok {
		t.Fatalf("ProofTypesSupported is missing %q", oid4vci.ProofTypeJWT)
	}
	if jwtPTC.KeyAttestationsRequired == nil {
		t.Errorf("jwt proof type KeyAttestationsRequired = nil, want a key attestation required")
	}
}

func mustHAIPEndpointURL(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(raw)
	if err != nil {
		t.Fatalf("ParseEndpointURL(%q): %v", raw, err)
	}
	return u
}

func TestValidateIssuerConfig_Accepts(t *testing.T) {
	cfg := issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Endpoints: issuer.Endpoints{Nonce: mustHAIPEndpointURL(t, "https://issuer.example.com/nonce")},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Scope:                                "identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
			},
			"UnboundCredential": {
				Scope: "unbound_credential",
			},
		},
	}
	if err := haip.ValidateIssuerConfig(cfg, issuer.Dependencies{}); err != nil {
		t.Fatalf("ValidateIssuerConfig: %v", err)
	}
}

func TestValidateIssuerConfig_RejectsMissingScope(t *testing.T) {
	cfg := issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {},
		},
	}
	if err := haip.ValidateIssuerConfig(cfg, issuer.Dependencies{}); err == nil {
		t.Fatalf("ValidateIssuerConfig = nil error, want error")
	}
}

func TestValidateIssuerConfig_RejectsKeyBindingWithoutNonceEndpoint(t *testing.T) {
	cfg := issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Scope:                                "identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
			},
		},
	}
	if err := haip.ValidateIssuerConfig(cfg, issuer.Dependencies{}); err == nil {
		t.Fatalf("ValidateIssuerConfig = nil error, want error (key binding requires endpoints.nonce)")
	}
}

func TestValidateIssuerConfig_RejectsAnonymousPreAuthorizedCode(t *testing.T) {
	for name, choice := range map[string]issuer.PreAuthorizedCodeClientAuthentication{
		"value":   issuer.AnonymousPreAuthorizedCode{},
		"pointer": &issuer.AnonymousPreAuthorizedCode{},
	} {
		cfg := issuer.Config{Assurance: issuer.AssuranceDevelopment, PreAuthorizedCodeClientAuthentication: choice}
		if err := haip.ValidateIssuerConfig(cfg, issuer.Dependencies{}); err == nil {
			t.Errorf("%s: ValidateIssuerConfig = nil error, want anonymous pre-authorized code redemption refused", name)
		}
	}
}

// HAIP 1.0 §4.3: "The scope value MUST map to a specific Credential
// Type." Two configurations of one type may share a scope; of two
// types may not.
func TestValidateIssuerConfig_ScopeMapsToOneType(t *testing.T) {
	validate := func(second issuer.CredentialConfiguration) error {
		return haip.ValidateIssuerConfig(issuer.Config{
			Assurance: issuer.AssuranceDevelopment,
			CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
				"pid":   {Format: "dc+sd-jwt", Scope: "pid", VCT: "urn:eudi:pid:1"},
				"other": second,
			},
		}, issuer.Dependencies{})
	}
	if err := validate(issuer.CredentialConfiguration{Format: "dc+sd-jwt", Scope: "pid", VCT: "urn:eudi:pid:1"}); err != nil {
		t.Errorf("one type under one scope: %v", err)
	}
	if err := validate(issuer.CredentialConfiguration{Format: "dc+sd-jwt", Scope: "pid", VCT: "urn:example:diploma"}); err == nil {
		t.Error("two vcts under one scope were accepted")
	}
	if err := validate(issuer.CredentialConfiguration{Format: "mso_mdoc", Scope: "pid", DocType: "eu.europa.ec.eudi.pid.1"}); err == nil {
		t.Error("an SD-JWT VC and an mdoc under one scope were accepted")
	}
}

// Configurations sharing a scope must require the same key
// attestations, whichever proof types carry them: a token for the
// stricter would be good for the other.
func TestValidateIssuerConfig_ScopeSharesKeyAttestations(t *testing.T) {
	hardware := &oid4vci.KeyAttestationRequirement{KeyStorage: []string{"iso_18045_high"}}
	validate := func(first, second map[string]oid4vci.ProofTypeConfiguration) error {
		// Every proof type takes ES256 (HAIP 1.0 §7), so only the key
		// attestations differ.
		for _, ptcs := range []map[string]oid4vci.ProofTypeConfiguration{first, second} {
			for name, ptc := range ptcs {
				ptc.ProofSigningAlgValuesSupported = []string{"ES256"}
				ptcs[name] = ptc
			}
		}
		return haip.ValidateIssuerConfig(issuer.Config{
			Assurance: issuer.AssuranceDevelopment,
			CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
				"pid_hw": {Format: "dc+sd-jwt", Scope: "pid", VCT: "urn:eudi:pid:1", ProofTypesSupported: first},
				"pid_sw": {Format: "dc+sd-jwt", Scope: "pid", VCT: "urn:eudi:pid:1", ProofTypesSupported: second},
			},
		}, issuer.Dependencies{})
	}
	jwtHW := map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: {KeyAttestationsRequired: hardware}}
	if err := validate(jwtHW, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: {KeyAttestationsRequired: hardware}}); err != nil {
		t.Errorf("the same key attestations by other proof types: %v", err)
	}
	if err := validate(jwtHW, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: {}}); err == nil {
		t.Error("a scope shared with a configuration requiring no key attestation was accepted")
	}
	if err := validate(jwtHW, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: {KeyAttestationsRequired: &oid4vci.KeyAttestationRequirement{}}}); err == nil {
		t.Error("a scope shared with a configuration requiring a weaker key attestation was accepted")
	}
	repeated := &oid4vci.KeyAttestationRequirement{KeyStorage: []string{"iso_18045_high", "iso_18045_high"}}
	if err := validate(jwtHW, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: {KeyAttestationsRequired: repeated}}); err != nil {
		t.Errorf("the same key attestations with a level repeated: %v", err)
	}
	if err := validate(nil, map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: {}}); err != nil {
		t.Errorf("no proof types beside a proof type requiring no key attestation: %v", err)
	}
	if err := validate(nil, jwtHW); err == nil {
		t.Error("a scope shared by a configuration taking no proofs and one requiring a key attestation was accepted")
	}
}

// HAIP 1.0 §4.5.1's "jwt proof type using key_attestation": the
// configuration requires a key attestation and is one issuer.New
// accepts with an AttestationVerifier.
func TestRecommendedJWTKeyAttestationProofType(t *testing.T) {
	ptc := haip.RecommendedJWTKeyAttestationProofType()
	if ptc.KeyAttestationsRequired == nil || len(ptc.ProofSigningAlgValuesSupported) != 1 || ptc.ProofSigningAlgValuesSupported[0] != string(haip.RecommendedJOSEAlgorithm) {
		t.Errorf("RecommendedJWTKeyAttestationProofType() = %+v", ptc)
	}
}

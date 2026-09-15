package haip_test

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/haip"
	"github.com/idfoundry/oid4vcigo/issuer"
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
	if len(rec.ProofTypesSupported) != 2 {
		t.Fatalf("ProofTypesSupported has %d entries, want 2", len(rec.ProofTypesSupported))
	}
	jwtPTC, ok := rec.ProofTypesSupported[oid4vci.ProofTypeJWT]
	if !ok {
		t.Fatalf("ProofTypesSupported is missing %q", oid4vci.ProofTypeJWT)
	}
	if jwtPTC.KeyAttestationsRequired != nil {
		t.Errorf("jwt proof type KeyAttestationsRequired = %v, want nil", jwtPTC.KeyAttestationsRequired)
	}
	attestationPTC, ok := rec.ProofTypesSupported[oid4vci.ProofTypeAttestation]
	if !ok {
		t.Fatalf("ProofTypesSupported is missing %q", oid4vci.ProofTypeAttestation)
	}
	if attestationPTC.KeyAttestationsRequired == nil {
		t.Errorf("attestation proof type KeyAttestationsRequired = nil, want non-nil")
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
	if err := haip.ValidateIssuerConfig(cfg); err != nil {
		t.Fatalf("ValidateIssuerConfig: %v", err)
	}
}

func TestValidateIssuerConfig_RejectsMissingScope(t *testing.T) {
	cfg := issuer.Config{
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {},
		},
	}
	if err := haip.ValidateIssuerConfig(cfg); err == nil {
		t.Fatalf("ValidateIssuerConfig = nil error, want error")
	}
}

func TestValidateIssuerConfig_RejectsKeyBindingWithoutNonceEndpoint(t *testing.T) {
	cfg := issuer.Config{
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			"IdentityCredential": {
				Scope:                                "identity_credential",
				CryptographicBindingMethodsSupported: []string{"jwk"},
			},
		},
	}
	if err := haip.ValidateIssuerConfig(cfg); err == nil {
		t.Fatalf("ValidateIssuerConfig = nil error, want error (key binding requires endpoints.nonce)")
	}
}

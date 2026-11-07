package issuer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestIssuerKeepsItsOwnConfig checks the proof policy New validated
// holds whatever the caller later does to its Config, or to what
// Metadata returns: a configuration requiring key attestations keeps
// refusing a jwt proof without one.
func TestIssuerKeepsItsOwnConfig(t *testing.T) {
	requireKeyAttestation := func(cfg *issuer.Config, _ *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		c.ProofTypesSupported[oid4vci.ProofTypeJWT] = oid4vci.ProofTypeConfiguration{
			ProofSigningAlgValuesSupported: []string{"ES256"},
			KeyAttestationsRequired:        &oid4vci.KeyAttestationRequirement{},
		}
	}
	plainJWT := oid4vci.ProofTypeConfiguration{ProofSigningAlgValuesSupported: []string{"ES256"}}
	tests := []struct {
		name   string
		change func(f credentialEndpointFixture, configs map[string]issuer.CredentialConfiguration)
	}{
		{"Metadata's result", func(f credentialEndpointFixture, _ map[string]issuer.CredentialConfiguration) {
			md := f.iss.Metadata()
			md.CredentialConfigurationsSupported[testSDJWTConfigID].ProofTypesSupported[oid4vci.ProofTypeJWT] = plainJWT
		}},
		{"the Config passed to New", func(_ credentialEndpointFixture, configs map[string]issuer.CredentialConfiguration) {
			configs[testSDJWTConfigID].ProofTypesSupported[oid4vci.ProofTypeJWT] = plainJWT
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var configs map[string]issuer.CredentialConfiguration
			f := newCredentialEndpointFixture(t, requireKeyAttestation, func(cfg *issuer.Config, _ *issuer.Dependencies) {
				configs = cfg.CredentialConfigurationsSupported
			})
			tt.change(f, configs)
			key := testP256Key(t)
			_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, key, testIssuer, f.issueNonce(t))}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if err == nil || !strings.Contains(err.Error(), "key_attestation") {
				t.Fatalf("RequestCredential = %v, want a jwt proof without a key attestation refused", err)
			}
			if f.iss.Metadata().CredentialConfigurationsSupported[testSDJWTConfigID].ProofTypesSupported[oid4vci.ProofTypeJWT].KeyAttestationsRequired == nil {
				t.Fatal("Metadata no longer advertises key_attestations_required")
			}
		})
	}
}

package issuer_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// Without a Nonce Endpoint, an attestation proof is dated by its iat,
// as a jwt proof is (TestRequestCredential_ProofAgeWithoutNonceEndpoint):
// one outside Limits.MaxProofAge of now, in either direction, is
// refused, though its own exp hasn't passed (OID4VCI 1.0 Appendix F.4).
func TestRequestCredential_AttestationProofAgeWithoutNonceEndpoint(t *testing.T) {
	for name, tc := range map[string]struct {
		offset  time.Duration
		wantErr bool
	}{
		"fresh":             {0, false},
		"within the age":    {-30 * time.Second, false},
		"too old":           {-2 * time.Minute, true},
		"too far in future": {2 * time.Minute, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
				cfg.Endpoints.Nonce = fapi.URL{}
				cfg.Limits.NonceLifetime = 0
				cfg.Limits.MaxProofAge = time.Minute
				deps.Nonces = nil
			})
			key := testP256Key(t)
			exp := f.now.Add(time.Hour).Unix()
			att, err := attestation.Issue(f.attestationSigner, jose.ES256, attestation.Header{}, attestation.Claims{
				IssuedAt: f.now.Add(tc.offset).Unix(), ExpiresAt: &exp, AttestedKeys: []json.RawMessage{jwkJSON(t, &key.PublicKey)},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
				CredentialConfigurationID: testSDJWTConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeAttestation: {att}},
				SDJWTClaims:               testSDJWTClaims(),
			})
			if tc.wantErr {
				assertIssuerError(t, err, issuer.ErrorInvalidProof)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
		})
	}
}

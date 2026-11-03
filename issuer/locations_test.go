package issuer_test

import (
	"context"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// With authorization_servers in the metadata, an authorization detail
// grants a configuration only where its locations name this issuer
// (§5.1.1, §6.2): one without them, from an Authorization Server other
// issuers share, grants nothing here.
func TestRequestCredential_LocationsRequiredWithAuthorizationServers(t *testing.T) {
	for name, tc := range map[string]struct {
		locations []string
		wantErr   issuer.ErrorCode
	}{
		"located here":  {locations: []string{testIssuer}},
		"no locations":  {wantErr: issuer.ErrorInsufficientScope},
		"located there": {locations: []string{"https://elsewhere.example.com"}, wantErr: issuer.ErrorInsufficientScope},
	} {
		t.Run(name, func(t *testing.T) {
			f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
				cfg.AuthorizationServers = []fapi.URL{mustEndpointURL(t, "https://as.example.com")}
			})
			_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{
				ClientIdentity: issuer.KnownClientID("test-client"),
				AuthorizationDetails: []oid4vci.AuthorizationDetail{{
					Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: testMdocConfigID, Locations: tc.locations,
				}},
			}, issuer.CredentialRequest{
				CredentialConfigurationID: testMdocConfigID,
				Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
				MdocClaims:                testMdocClaims(t),
			})
			if tc.wantErr != "" {
				assertIssuerError(t, err, tc.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("RequestCredential: %v", err)
			}
		})
	}
}

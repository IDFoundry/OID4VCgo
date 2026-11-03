package issuer_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A PerCredential that drops a Credential's claims fails the request,
// rather than panicking after the c_nonce is spent.
func TestRequestCredential_PerCredentialRemovingClaims(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		SDJWTClaims:               testSDJWTClaims(),
		PerCredential: func(_ context.Context, c *issuer.CredentialInstance) error {
			c.SDJWTClaims = nil
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "removed") {
		t.Fatalf("RequestCredential = %v, want the removed claims refused", err)
	}
}

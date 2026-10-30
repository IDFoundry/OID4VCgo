package walletflow_test

import (
	"context"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// A configuration with no scope is requested by authorization_details
// in the authorization code flow (OpenID4VCI 1.0 §5.1.1). The
// Authorization Server's consent mints its credential_identifier
// (§6.2), which reaches the Token Response, and the Credential Request
// names it at the Credential Endpoint, whose Prepare finds it among
// those minted for the holder.
func TestIssuance_CredentialAuthorizationDetails(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{MdocUnscoped: true, CredentialAuthorizationDetails: true})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.MdocConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("result = %+v", result)
	}
	minted, presented := f.env.CredentialIdentifiers()
	if len(minted) != 1 || len(presented) == 0 {
		t.Fatalf("minted %v, presented %v; want one minted and presented", minted, presented)
	}
	for _, id := range presented {
		if !slices.Contains(minted, id) {
			t.Errorf("presented %q, which the Authorization Server didn't mint", id)
		}
	}
}

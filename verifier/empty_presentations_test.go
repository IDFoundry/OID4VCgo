package verifier_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// A vp_token naming the credential query with an empty array answers
// nothing: it's refused, not taken as a query answered by no
// credential. Only verifyCredentialQuery's own count check sees this,
// since the query's ID is present.
func TestVerifyResponse_RefusesEmptyPresentationArray(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testIdentityQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	for name, presentations := range map[string][]string{"empty": {}, "nil": nil} {
		_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: testIdentityQuery(t), ExpectedNonce: built.Nonce,
			Response:         verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": presentations}},
			MaxKeyBindingAge: time.Hour,
		})
		var verr *verifier.Error
		if !errors.As(err, &verr) || !strings.Contains(err.Error(), "no presentation returned") {
			t.Errorf("%s: VerifyResponse = %v, want a *verifier.Error: no presentation returned", name, err)
		}
	}
}

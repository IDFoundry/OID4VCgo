package verifier_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An SD-JWT presentation's Disclosures aren't decoded before its
// issuer's key is resolved and its Issuer-signed JWT verifies: one
// whose JWT fails is refused for that, not for the undecodable
// Disclosures it carries.
func TestVerifyResponse_SDJWTDisclosuresAfterIssuerSignature(t *testing.T) {
	pres := unsignedPresentation(t, map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}) + "!undecodable!~"
	query := multipleQuery(t)
	unbound := false
	query.Credentials[0].RequireCryptographicHolderBinding = &unbound
	_, err := newTestVerifier(t).VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": {pres}}},
		ExpectedNonce: "n", MaxKeyBindingAge: time.Hour,
		IssuerKeys: fixedSDJWTVCIssuerKeyResolver{pub: &testP256Key(t).PublicKey, alg: jose.ES256},
	})
	if err == nil || !strings.Contains(err.Error(), "verify issuer JWT") {
		t.Fatalf("err = %v, want the Issuer-signed JWT refused", err)
	}
	var failed *verifier.Error
	if !errors.As(err, &failed) || failed.Reason() != verifier.ReasonInvalidCredential {
		t.Errorf("err = %v, want invalid_credential", err)
	}
}

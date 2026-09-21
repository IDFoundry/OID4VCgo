package verifier_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestVerifyResponse_AttributesFailureToWallet proves a failure caused
// by what the Wallet actually presented — a missing Presentation, in
// this case — is a *verifier.Error, letting a caller distinguish "the
// Wallet's response was bad" from a caller/deployment mistake without
// string-matching the error text. See verifier.Error's own doc
// comment.
func TestVerifyResponse_AttributesFailureToWallet(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testIdentityQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: testIdentityQuery(t), ExpectedNonce: built.Nonce,
		Response:         verifier.ParsedResponse{VPToken: map[string][]string{}},
		MaxKeyBindingAge: time.Hour,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
	var verr *verifier.Error
	if !errors.As(err, &verr) {
		t.Errorf("error = %v, want a *verifier.Error — a missing Presentation is attributable to the Wallet's own response", err)
	}
}

// TestVerifyResponse_DoesNotAttributeDeploymentMistakeToWallet proves
// the opposite: a caller/deployment mistake in VerifyResponseRequest
// itself (here, an unset ExpectedNonce) — checked before req.Response
// is even inspected — is a plain error, not a *verifier.Error, the
// same distinction issuer.Error/its own client_id_test.go establish on
// the issuance side.
func TestVerifyResponse_DoesNotAttributeDeploymentMistakeToWallet(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: dcql.Query{Credentials: []dcql.CredentialQuery{}},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
	var verr *verifier.Error
	if errors.As(err, &verr) {
		t.Errorf("error = %v (a *verifier.Error), want a plain error — an unset expected_nonce is a caller/deployment mistake, not something attributable to the Wallet's response", err)
	}
}

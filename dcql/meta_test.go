package dcql_test

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/dcql"
)

func TestSatisfiedBySDJWTVCClaims(t *testing.T) {
	cq := dcql.CredentialQuery{
		ID: "identity_credential", Format: "dc+sd-jwt",
		Meta:   mustSDJWTVCMeta(t, "https://credentials.example.com/identity_credential"),
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
	}

	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/identity_credential", "given_name": "Alice",
	}); err != nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (matching) = %v, want nil", err)
	}

	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/some_other_credential", "given_name": "Alice",
	}); err == nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (wrong vct) = nil, want error")
	}

	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/identity_credential",
	}); err == nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (missing claim) = nil, want error")
	}
}

func TestSatisfiedBySDJWTVCClaimsAcceptsAnyVCTWhenUnconstrained(t *testing.T) {
	cq := dcql.CredentialQuery{ID: "any", Format: "dc+sd-jwt", Meta: mustSDJWTVCMeta(t)}
	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{"vct": "https://anything.example.com"}); err != nil {
		t.Errorf("SatisfiedBySDJWTVCClaims = %v, want nil", err)
	}
}

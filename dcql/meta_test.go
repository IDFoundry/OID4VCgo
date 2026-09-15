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

func TestSatisfiedByMdocClaims(t *testing.T) {
	cq := dcql.CredentialQuery{
		ID: "mdl", Format: "mso_mdoc",
		Meta: mustMdocMeta(t, "org.iso.18013.5.1.mDL"),
		Claims: []dcql.ClaimsQuery{
			{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")}},
		},
	}
	nameSpaces := map[string]map[string]any{
		"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
	}

	if err := cq.SatisfiedByMdocClaims("org.iso.18013.5.1.mDL", nameSpaces); err != nil {
		t.Errorf("SatisfiedByMdocClaims (matching) = %v, want nil", err)
	}
	if err := cq.SatisfiedByMdocClaims("org.iso.18013.5.1.mVRC", nameSpaces); err == nil {
		t.Errorf("SatisfiedByMdocClaims (wrong doctype) = nil, want error")
	}
	if err := cq.SatisfiedByMdocClaims("org.iso.18013.5.1.mDL", map[string]map[string]any{
		"org.iso.18013.5.1": {"family_name": "Doe"},
	}); err == nil {
		t.Errorf("SatisfiedByMdocClaims (missing element) = nil, want error")
	}
	if err := cq.SatisfiedByMdocClaims("org.iso.18013.5.1.mDL", map[string]map[string]any{}); err == nil {
		t.Errorf("SatisfiedByMdocClaims (missing namespace) = nil, want error")
	}
}

func TestSatisfiedByMdocClaimsRejectsNonMdocPath(t *testing.T) {
	cq := dcql.CredentialQuery{
		ID: "mdl", Format: "mso_mdoc",
		Meta:   mustMdocMeta(t, "org.iso.18013.5.1.mDL"),
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("only-one-component")}}},
	}
	if err := cq.SatisfiedByMdocClaims("org.iso.18013.5.1.mDL", map[string]map[string]any{}); err == nil {
		t.Errorf("SatisfiedByMdocClaims = nil, want error")
	}
}

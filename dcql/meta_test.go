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

// TestSatisfiedBySDJWTVCClaimsWithClaimSets mirrors §6.4.1's own
// worked example: a required claim plus an either/or pair, expressed
// as two claim_sets options — the second (least-preferred) option
// still satisfies the query when it's the only one a credential can
// fulfill.
func TestSatisfiedBySDJWTVCClaimsWithClaimSets(t *testing.T) {
	cq := dcql.CredentialQuery{
		ID: "identity_credential", Format: "dc+sd-jwt",
		Meta: mustSDJWTVCMeta(t, "https://credentials.example.com/identity_credential"),
		Claims: []dcql.ClaimsQuery{
			{ID: "last_name", Path: dcql.Path{dcql.PathKey("last_name")}},
			{ID: "postal_code", Path: dcql.Path{dcql.PathKey("postal_code")}},
			{ID: "locality", Path: dcql.Path{dcql.PathKey("locality")}},
			{ID: "region", Path: dcql.Path{dcql.PathKey("region")}},
		},
		ClaimSets: [][]string{
			{"last_name", "postal_code"},
			{"last_name", "locality", "region"},
		},
	}

	// Satisfies only the first (most-preferred) option.
	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/identity_credential", "last_name": "Doe", "postal_code": "12345",
	}); err != nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (first option) = %v, want nil", err)
	}

	// Satisfies only the second (least-preferred) option.
	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/identity_credential", "last_name": "Doe", "locality": "Anytown", "region": "CA",
	}); err != nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (second option) = %v, want nil", err)
	}

	// Satisfies neither option (missing postal_code and locality/region).
	if err := cq.SatisfiedBySDJWTVCClaims(map[string]any{
		"vct": "https://credentials.example.com/identity_credential", "last_name": "Doe",
	}); err == nil {
		t.Errorf("SatisfiedBySDJWTVCClaims (neither option) = nil, want error")
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

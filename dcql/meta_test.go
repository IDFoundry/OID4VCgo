package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
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
// worked example: the second (least-preferred) claim_sets option
// still satisfies the query when it's the only one a credential can
// fulfill.
func TestSatisfiedBySDJWTVCClaimsWithClaimSets(t *testing.T) {
	cq := claimSetsCredentialQuery(t)
	const vct = "https://credentials.example.com/identity_credential"

	cases := map[string]struct {
		claims  map[string]any
		wantErr bool
	}{
		"first option":   {map[string]any{"vct": vct, "last_name": "Doe", "postal_code": "12345"}, false},
		"second option":  {map[string]any{"vct": vct, "last_name": "Doe", "locality": "Anytown", "region": "CA"}, false},
		"neither option": {map[string]any{"vct": vct, "last_name": "Doe"}, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := cq.SatisfiedBySDJWTVCClaims(tc.claims)
			if tc.wantErr != (err != nil) {
				t.Errorf("SatisfiedBySDJWTVCClaims = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestSelectedSDJWTVCClaimPathsReturnsWinningOption mirrors §6.4.1's
// own worked example again, this time checking
// SelectedSDJWTVCClaimPaths's own richer return value: which specific
// Paths the winning claim_sets option resolved, not just that some
// option did.
func TestSelectedSDJWTVCClaimPathsReturnsWinningOption(t *testing.T) {
	cq := claimSetsCredentialQuery(t)
	const vct = "https://credentials.example.com/identity_credential"

	paths, err := cq.SelectedSDJWTVCClaimPaths(map[string]any{
		"vct": vct, "last_name": "Doe", "locality": "Anytown", "region": "CA",
	})
	if err != nil {
		t.Fatalf("SelectedSDJWTVCClaimPaths: %v", err)
	}
	want := []dcql.Path{
		{dcql.PathKey("last_name")}, {dcql.PathKey("locality")}, {dcql.PathKey("region")},
	}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i, p := range want {
		if !pathsEqual(t, paths[i], p) {
			t.Errorf("paths[%d] = %v, want %v", i, paths[i], p)
		}
	}
}

// TestSelectedSDJWTVCClaimPathsEmptyWhenNoClaimsRequested mirrors
// §6.4.1's own "claims is absent" case: nothing is selected, matching
// "the Wallet MUST return only the claims that are mandatory to
// present."
func TestSelectedSDJWTVCClaimPathsEmptyWhenNoClaimsRequested(t *testing.T) {
	cq := dcql.CredentialQuery{ID: "any", Format: "dc+sd-jwt", Meta: mustSDJWTVCMeta(t)}
	paths, err := cq.SelectedSDJWTVCClaimPaths(map[string]any{"vct": "https://anything.example.com"})
	if err != nil {
		t.Fatalf("SelectedSDJWTVCClaimPaths: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("paths = %v, want empty", paths)
	}
}

// pathsEqual compares two dcql.Path values by their own JSON wire
// form — dcql.Path has no exported equality method and its own
// PathElement fields are private, so this is the simplest correct way
// to compare two Paths in a test outside the dcql package itself.
func pathsEqual(t *testing.T, a, b dcql.Path) bool {
	t.Helper()
	aJSON, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	bJSON, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(aJSON) == string(bJSON)
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

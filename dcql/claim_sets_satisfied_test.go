package dcql_test

import (
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// SatisfiedMdocClaimPaths and SatisfiedSDJWTVCPresentationPaths return
// the paths of each claim_sets option a presentation satisfies, values
// filters included, each claim once: the claims a Verifier may receive.
func TestSatisfiedClaimPaths(t *testing.T) {
	const ns = "org.iso.18013.5.1"
	const docType = "org.iso.18013.5.1.mDL"
	mdocPath := func(element string) dcql.Path { return dcql.KeyPath(ns, element) }
	mdocMeta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: docType})
	if err != nil {
		t.Fatal(err)
	}
	query := dcql.CredentialQuery{
		ID: "mdl", Format: "mso_mdoc", Meta: mdocMeta,
		Claims: []dcql.ClaimsQuery{
			{ID: "country", Path: mdocPath("resident_country"), Values: []any{"DE"}},
			{ID: "city", Path: mdocPath("resident_city")},
			{ID: "name", Path: mdocPath("family_name")},
		},
		ClaimSets: [][]string{{"country", "city"}, {"name", "city"}, {"name"}},
	}
	for name, tc := range map[string]struct {
		elements map[string]any
		want     []dcql.Path
	}{
		"a French resident": {map[string]any{"resident_country": "FR", "resident_city": "Paris", "family_name": "Dupont"},
			[]dcql.Path{mdocPath("family_name"), mdocPath("resident_city")}},
		"a German resident": {map[string]any{"resident_country": "DE", "resident_city": "Berlin", "family_name": "Müller"},
			[]dcql.Path{mdocPath("resident_country"), mdocPath("resident_city"), mdocPath("family_name")}},
		"a name alone": {map[string]any{"family_name": "Dupont"}, []dcql.Path{mdocPath("family_name")}},
	} {
		got, err := query.SatisfiedMdocClaimPaths(docType, map[string]map[string]any{ns: tc.elements})
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
	if _, err := query.SatisfiedMdocClaimPaths(docType, map[string]map[string]any{ns: {"resident_country": "FR"}}); err == nil {
		t.Error("no option satisfied: nil error")
	}

	sdjwtMeta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:x"}})
	if err != nil {
		t.Fatal(err)
	}
	sdjwt := dcql.CredentialQuery{
		ID: "pid", Format: "dc+sd-jwt", Meta: sdjwtMeta,
		Claims: []dcql.ClaimsQuery{
			{ID: "country", Path: dcql.KeyPath("address", "country"), Values: []any{"DE"}},
			{ID: "name", Path: dcql.KeyPath("given_name")},
		},
		ClaimSets: [][]string{{"country"}, {"name"}},
	}
	got, err := sdjwt.SatisfiedSDJWTVCPresentationPaths(map[string]any{"vct": "urn:x", "given_name": "Jean", "address": map[string]any{"country": "FR"}})
	if want := []dcql.Path{dcql.KeyPath("given_name")}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("SD-JWT VC, a French address beside the name: %v, %v; want %v", got, err, want)
	}
}

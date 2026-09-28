package dcql_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

func sdjwtQuery(t *testing.T, claims []dcql.ClaimsQuery, claimSets [][]string) dcql.CredentialQuery {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:test"}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.CredentialQuery{ID: "q", Format: "dc+sd-jwt", Meta: meta, Claims: claims, ClaimSets: claimSets}
}

func key(k ...string) dcql.Path {
	p := make(dcql.Path, len(k))
	for i, s := range k {
		p[i] = dcql.PathKey(s)
	}
	return p
}

// fromJSON decodes values the way a query arriving as JSON holds them.
func fromJSON(t *testing.T, s string) []any {
	t.Helper()
	var v []any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatalf("unmarshal %s: %v", s, err)
	}
	return v
}

func TestSatisfiedBySDJWTVCClaims_EnforcesValues(t *testing.T) {
	claims := map[string]any{
		"vct": "urn:test", "age_over_18": false, "given_name": "Jane",
		"birth_year": float64(1985), "nationalities": []any{"DE", "FR"},
	}
	cases := []struct {
		name   string
		claim  dcql.ClaimsQuery
		wantOK bool
	}{
		{"bool differs", dcql.ClaimsQuery{Path: key("age_over_18"), Values: []any{true}}, false},
		{"bool matches", dcql.ClaimsQuery{Path: key("age_over_18"), Values: []any{false}}, true},
		{"string differs", dcql.ClaimsQuery{Path: key("given_name"), Values: []any{"John"}}, false},
		{"string matches one of", dcql.ClaimsQuery{Path: key("given_name"), Values: []any{"John", "Jane"}}, true},
		{"type differs", dcql.ClaimsQuery{Path: key("given_name"), Values: []any{true}}, false},
		{"number matches", dcql.ClaimsQuery{Path: key("birth_year"), Values: fromJSON(t, "[1985]")}, true},
		{"number differs", dcql.ClaimsQuery{Path: key("birth_year"), Values: []any{1986}}, false},
		{"number vs string", dcql.ClaimsQuery{Path: key("birth_year"), Values: []any{"1985"}}, false},
		{"wildcard matches an element", dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey("nationalities"), dcql.Wildcard}, Values: []any{"FR"}}, true},
		{"wildcard matches no element", dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey("nationalities"), dcql.Wildcard}, Values: []any{"US"}}, false},
		{"no values: presence only", dcql.ClaimsQuery{Path: key("age_over_18")}, true},
	}
	for _, c := range cases {
		err := sdjwtQuery(t, []dcql.ClaimsQuery{c.claim}, nil).SatisfiedBySDJWTVCClaims(claims)
		if (err == nil) != c.wantOK {
			t.Errorf("%s: err = %v, want ok = %v", c.name, err, c.wantOK)
		}
	}
}

// TestSelectedSDJWTVCClaimPaths_ValuesSelectClaimSetOption: an option
// whose value doesn't match is skipped for the next one.
func TestSelectedSDJWTVCClaimPaths_ValuesSelectClaimSetOption(t *testing.T) {
	claims := map[string]any{"vct": "urn:test", "age_over_18": false, "given_name": "Jane"}
	q := sdjwtQuery(t, []dcql.ClaimsQuery{
		{ID: "adult", Path: key("age_over_18"), Values: []any{true}},
		{ID: "name", Path: key("given_name")},
	}, [][]string{{"adult"}, {"name"}})
	paths, err := q.SelectedSDJWTVCClaimPaths(claims)
	if err != nil {
		t.Fatalf("SelectedSDJWTVCClaimPaths: %v", err)
	}
	if len(paths) != 1 || fmt.Sprint(paths[0]) != fmt.Sprint(key("given_name")) {
		t.Errorf("paths = %v, want the given_name option", paths)
	}
}

func TestSatisfiedByMdocClaims_EnforcesValues(t *testing.T) {
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.test"})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	nameSpaces := map[string]map[string]any{"ns": {"age_over_18": false, "age_birth_year": uint64(1985)}}
	for name, c := range map[string]struct {
		claim  dcql.ClaimsQuery
		wantOK bool
	}{
		"bool differs":              {dcql.ClaimsQuery{Path: key("ns", "age_over_18"), Values: []any{true}}, false},
		"CBOR uint vs JSON number":  {dcql.ClaimsQuery{Path: key("ns", "age_birth_year"), Values: fromJSON(t, "[1985]")}, true},
		"CBOR uint differs":         {dcql.ClaimsQuery{Path: key("ns", "age_birth_year"), Values: []any{int64(1984)}}, false},
		"presence only (no values)": {dcql.ClaimsQuery{Path: key("ns", "age_over_18")}, true},
	} {
		q := dcql.CredentialQuery{ID: "q", Format: "mso_mdoc", Meta: meta, Claims: []dcql.ClaimsQuery{c.claim}}
		if err := q.SatisfiedByMdocClaims("org.test", nameSpaces); (err == nil) != c.wantOK {
			t.Errorf("%s: err = %v, want ok = %v", name, err, c.wantOK)
		}
	}
}

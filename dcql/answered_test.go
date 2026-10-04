package dcql_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

func TestCheckAnswered(t *testing.T) {
	cq := func(id string) dcql.CredentialQuery {
		return dcql.CredentialQuery{ID: id, Format: "dc+sd-jwt", Meta: mustSDJWTVCMeta(t, "urn:example")}
	}
	optional := false
	queries := []dcql.CredentialQuery{cq("a"), cq("b"), cq("c")}
	plain := dcql.Query{Credentials: queries}
	alternatives := dcql.Query{Credentials: queries, CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"a"}, {"b"}}}}}
	nested := dcql.Query{Credentials: queries, CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"a"}, {"a", "b"}}}}}
	// Sets sharing a query: each takes one of its options, and a query
	// in two sets counts for both.
	shared := dcql.Query{Credentials: queries, CredentialSets: []dcql.CredentialSetQuery{
		{Options: [][]string{{"a"}, {"b"}}}, {Options: [][]string{{"b"}}},
	}}
	sharedPair := dcql.Query{Credentials: queries, CredentialSets: []dcql.CredentialSetQuery{
		{Options: [][]string{{"a", "b"}}}, {Options: [][]string{{"a"}, {"b"}}},
	}}
	withOptional := dcql.Query{Credentials: queries, CredentialSets: []dcql.CredentialSetQuery{
		{Options: [][]string{{"a"}}}, {Required: &optional, Options: [][]string{{"b", "c"}}},
	}}
	for _, tc := range []struct {
		name     string
		query    dcql.Query
		answered []string
		wantErr  string // "" for none
	}{
		{"every query", plain, []string{"a", "b", "c"}, ""},
		{"a query left out", plain, []string{"a", "b"}, `"c" is required`},
		{"an unknown query", plain, []string{"a", "b", "c", "x"}, `"x" isn't one of`},
		{"one alternative", alternatives, []string{"b"}, ""},
		{"both alternatives", alternatives, []string{"a", "b"}, "a credential set takes one"},
		{"no alternative", alternatives, nil, "is required"},
		{"a query outside the sets", alternatives, []string{"a", "c"}, `"c" is answered but`},
		{"the larger of nested options", nested, []string{"a", "b"}, ""},
		{"the smaller of nested options", nested, []string{"a"}, ""},
		{"an optional set left out", withOptional, []string{"a"}, ""},
		{"an optional set answered", withOptional, []string{"a", "b", "c"}, ""},
		{"an optional set's option in part", withOptional, []string{"a", "b"}, `"b" is answered but`},
		{"a shared query answering both sets", shared, []string{"b"}, ""},
		{"each set its own option", shared, []string{"a", "b"}, ""},
		{"a shared query, the other set its own", sharedPair, []string{"a", "b"}, ""},
		{"a shared set left unanswered", shared, []string{"a"}, "credential_sets[1] is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.query.Validate(); err != nil {
				t.Fatal(err)
			}
			answered := map[string]bool{}
			for _, id := range tc.answered {
				answered[id] = true
			}
			err := tc.query.CheckAnswered(answered)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("CheckAnswered = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("CheckAnswered = %v, want an error containing %q", err, tc.wantErr)
			}
		})
	}
}

// An option listing a credential query twice isn't valid.
func TestCredentialSetQuery_RejectsDuplicateIDs(t *testing.T) {
	q := dcql.Query{
		Credentials:    []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt", Meta: mustSDJWTVCMeta(t, "urn:example")}},
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"a", "a"}}}},
	}
	if err := q.Validate(); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("Validate = %v, want the duplicate refused", err)
	}
}

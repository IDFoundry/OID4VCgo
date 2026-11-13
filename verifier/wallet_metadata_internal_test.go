package verifier

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

func TestAnswerable(t *testing.T) {
	query := func(sets ...dcql.CredentialSetQuery) dcql.Query {
		return dcql.Query{
			Credentials: []dcql.CredentialQuery{
				{ID: "sd", Format: "dc+sd-jwt"}, {ID: "mdoc", Format: "mso_mdoc"},
			},
			CredentialSets: sets,
		}
	}
	optional := false
	sdOnly := map[string]any{"dc+sd-jwt": nil}
	cases := []struct {
		name  string
		query dcql.Query
		want  bool
	}{
		{"every query required, one unanswerable", query(), false},
		{"a required set with an answerable option", query(dcql.CredentialSetQuery{Options: [][]string{{"mdoc"}, {"sd"}}}), true},
		{"a required set with none", query(dcql.CredentialSetQuery{Options: [][]string{{"mdoc"}, {"sd", "mdoc"}}}), false},
		{"an optional set with none", query(
			dcql.CredentialSetQuery{Options: [][]string{{"sd"}}},
			dcql.CredentialSetQuery{Options: [][]string{{"mdoc"}}, Required: &optional},
		), true},
	}
	for _, c := range cases {
		if got := answerable(c.query, sdOnly); got != c.want {
			t.Errorf("%s: answerable = %v, want %v", c.name, got, c.want)
		}
	}
	if !answerable(query(), map[string]any{"dc+sd-jwt": nil, "mso_mdoc": nil}) {
		t.Error("both formats supported: not answerable")
	}
}

func TestFitFormat(t *testing.T) {
	// An entry that isn't an object has nothing to narrow.
	got, keep, err := fitFormat("opaque", map[string]json.RawMessage{"x": json.RawMessage(`[1]`)})
	if err != nil || !keep || got != "opaque" {
		t.Errorf("a non-object entry: %v %v %v", got, keep, err)
	}
	// One that can't be encoded is the Verifier's own fault.
	if _, _, err := fitFormat(func() {}, nil); err == nil {
		t.Error("an unencodable entry was fitted")
	}
	// COSE algorithm numbers compare as JSON values.
	ours := map[string]any{"issuerauth_alg_values": []int{-7, -35}, "other": "kept"}
	got, keep, err = fitFormat(ours, map[string]json.RawMessage{"issuerauth_alg_values": json.RawMessage(`[ -35 , -8 ]`)})
	if err != nil || !keep {
		t.Fatalf("fitFormat: %v %v", keep, err)
	}
	want := map[string]json.RawMessage{"issuerauth_alg_values": json.RawMessage(`[-35]`), "other": json.RawMessage(`"kept"`)}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("fitFormat = %s, want %s", got, want)
	}
	var metadataErr *WalletMetadataError
	if _, _, err := fitFormat(ours, map[string]json.RawMessage{"issuerauth_alg_values": json.RawMessage(`{}`)}); !errors.As(err, &metadataErr) {
		t.Errorf("a non-array where ours is one: %v", err)
	}
}

package verifier

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// Begin's read-back compares the query with the store's copy, read back
// through JSON, by its numbers as written: a copy holding a values
// integer as another isn't the same query, even one a float64 can't
// tell apart from it (2^53 and 2^53 + 1), and a copy holding the same
// integer as a float64 is.
func TestSameQuery_ComparesNumbersAsWritten(t *testing.T) {
	query := func(value any) dcql.Query {
		return dcql.Query{Credentials: []dcql.CredentialQuery{{
			ID: "mdl", Format: "mso_mdoc", Meta: json.RawMessage(`{"doctype_value":"org.iso.18013.5.1.mDL"}`),
			Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("n")}, Values: []any{value}}},
		}}}
	}
	if !sameQuery(query(int64(1<<53-1)), query(float64(1<<53-1))) {
		t.Error("an integer and its copy's float64 of it compared as different queries")
	}
	if sameQuery(query(int64(1<<53+1)), query(float64(1<<53))) {
		t.Error("2^53 + 1 and its copy's 2^53 compared as the same query")
	}
}

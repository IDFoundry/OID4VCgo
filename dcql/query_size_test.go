package dcql_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// A query past any size bound is refused by Validate, before a wallet
// spends time matching it; one at the bounds is accepted.
func TestQueryValidate_SizeBounds(t *testing.T) {
	credential := func(id string, claims, claimSets, values, pathLen int) dcql.CredentialQuery {
		cq := dcql.CredentialQuery{ID: id, Format: "dc+sd-jwt", Meta: json.RawMessage(`{"vct_values":["urn:test"]}`)}
		for i := range claims {
			path := dcql.Path{}
			for j := range max(pathLen, 1) {
				path = append(path, dcql.PathKey(fmt.Sprintf("k%d_%d", i, j)))
			}
			c := dcql.ClaimsQuery{ID: fmt.Sprintf("c%d", i), Path: path}
			for v := range values {
				c.Values = append(c.Values, fmt.Sprint(v))
			}
			cq.Claims = append(cq.Claims, c)
		}
		for range claimSets {
			cq.ClaimSets = append(cq.ClaimSets, []string{"c0"})
		}
		return cq
	}
	credentials := func(n int) []dcql.CredentialQuery {
		out := make([]dcql.CredentialQuery, n)
		for i := range out {
			out[i] = credential(fmt.Sprintf("q%d", i), 1, 0, 0, 1)
		}
		return out
	}
	sets := func(n, options int) []dcql.CredentialSetQuery {
		out := make([]dcql.CredentialSetQuery, n)
		for i := range out {
			for range options {
				out[i].Options = append(out[i].Options, []string{"q0"})
			}
		}
		return out
	}
	for name, tc := range map[string]struct {
		q       dcql.Query
		refused string
	}{
		"at the bounds": {q: dcql.Query{
			Credentials:    append(credentials(dcql.MaxCredentialQueries-1), credential("big", dcql.MaxClaimsPerCredential, dcql.MaxClaimSets, dcql.MaxValuesPerClaim, dcql.MaxPathLength)),
			CredentialSets: sets(dcql.MaxCredentialSets, dcql.MaxCredentialSetOptions),
		}},
		"credential queries": {q: dcql.Query{Credentials: credentials(dcql.MaxCredentialQueries + 1)}, refused: "credential queries"},
		"credential sets":    {q: dcql.Query{Credentials: credentials(1), CredentialSets: sets(dcql.MaxCredentialSets+1, 1)}, refused: "credential sets"},
		"options in a set":   {q: dcql.Query{Credentials: credentials(1), CredentialSets: sets(1, dcql.MaxCredentialSetOptions+1)}, refused: "options"},
		"claims":             {q: dcql.Query{Credentials: []dcql.CredentialQuery{credential("q0", dcql.MaxClaimsPerCredential+1, 0, 0, 1)}}, refused: "claims"},
		"claim sets":         {q: dcql.Query{Credentials: []dcql.CredentialQuery{credential("q0", 1, dcql.MaxClaimSets+1, 0, 1)}}, refused: "claim sets"},
		"values":             {q: dcql.Query{Credentials: []dcql.CredentialQuery{credential("q0", 1, 0, dcql.MaxValuesPerClaim+1, 1)}}, refused: "values"},
		"path length":        {q: dcql.Query{Credentials: []dcql.CredentialQuery{credential("q0", 1, 0, 0, dcql.MaxPathLength+1)}}, refused: "path"},
	} {
		err := tc.q.Validate()
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused for %s", name, err, tc.refused)
		}
	}
}

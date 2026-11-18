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

// The bounds within one credential query: a claim_sets entry, the
// trusted_authorities entries and their values, and vct_values. A
// claim_sets entry naming one claim thousands of times, which once took
// a wallet minutes to match, is refused.
func TestQueryValidate_CredentialQueryBounds(t *testing.T) {
	repeat := func(s string, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = s
		}
		return out
	}
	vcts := func(n int) json.RawMessage {
		raw, err := json.Marshal(map[string][]string{"vct_values": repeat("urn:test", n)})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	authorities := func(n, values int) []dcql.TrustedAuthoritiesQuery {
		out := make([]dcql.TrustedAuthoritiesQuery, n)
		for i := range out {
			out[i] = dcql.TrustedAuthoritiesQuery{Type: dcql.TrustedAuthorityAKI, Values: repeat("s9tIpPmhxdiuNkHMEWNpYim8S8Y", values)}
		}
		return out
	}
	claims := func(n int) []dcql.ClaimsQuery {
		out := make([]dcql.ClaimsQuery, n)
		for i := range out {
			out[i] = dcql.ClaimsQuery{ID: fmt.Sprintf("c%d", i), Path: dcql.Path{dcql.PathKey(fmt.Sprintf("k%d", i))}}
		}
		return out
	}
	ids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("c%d", i)
		}
		return out
	}
	for name, tc := range map[string]struct {
		cq      dcql.CredentialQuery
		refused string
	}{
		"at the bounds": {cq: dcql.CredentialQuery{
			Meta:               vcts(dcql.MaxVCTValues),
			TrustedAuthorities: authorities(dcql.MaxTrustedAuthorities, dcql.MaxTrustedAuthorityValues),
			Claims:             claims(dcql.MaxClaimsPerCredential),
			ClaimSets:          [][]string{ids(dcql.MaxClaimsPerCredential)},
		}},
		"claim set naming a claim twice": {cq: dcql.CredentialQuery{Claims: claims(2), ClaimSets: [][]string{{"c0", "c1", "c0"}}}, refused: `claim_sets[0] lists claim id "c0" twice`},
		"claim set longer than the claims": {cq: dcql.CredentialQuery{
			Claims:    claims(1),
			ClaimSets: [][]string{{"c0"}, repeat("c0", dcql.MaxClaimsPerCredential+1)},
		}, refused: "claim_sets[1]: 257 claims"},
		"claim set of thousands":     {cq: dcql.CredentialQuery{Claims: claims(2), ClaimSets: [][]string{append(repeat("c0", 3499), "c1")}}, refused: "claim_sets[0]"},
		"trusted authorities":        {cq: dcql.CredentialQuery{TrustedAuthorities: authorities(dcql.MaxTrustedAuthorities+1, 1)}, refused: "trusted authorities"},
		"trusted authority values":   {cq: dcql.CredentialQuery{TrustedAuthorities: authorities(1, dcql.MaxTrustedAuthorityValues+1)}, refused: "trusted_authorities[0]: 65 values"},
		"vct_values":                 {cq: dcql.CredentialQuery{Meta: vcts(dcql.MaxVCTValues + 1)}, refused: "65 vct_values"},
		"meta at the bound":          {cq: dcql.CredentialQuery{Meta: paddedMeta(t, dcql.MaxMetaBytes)}},
		"meta":                       {cq: dcql.CredentialQuery{Meta: paddedMeta(t, dcql.MaxMetaBytes+1)}, refused: "a meta of 4097 bytes"},
		"meta of a format not known": {cq: dcql.CredentialQuery{Format: "jwt_vc_json", Meta: paddedMeta(t, dcql.MaxMetaBytes+1)}, refused: "a meta of 4097 bytes"},
	} {
		tc.cq.ID = "q"
		if tc.cq.Format == "" {
			tc.cq.Format = "dc+sd-jwt"
		}
		if tc.cq.Meta == nil {
			tc.cq.Meta = vcts(1)
		}
		err := dcql.Query{Credentials: []dcql.CredentialQuery{tc.cq}}.Validate()
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused for %s", name, err, tc.refused)
		}
	}
	if _, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: repeat("urn:test", dcql.MaxVCTValues+1)}); err == nil {
		t.Error("NewSDJWTVCMeta accepted more than MaxVCTValues vct_values")
	}
}

// paddedMeta is a "dc+sd-jwt" meta of exactly n bytes, its one vct
// followed by a member a wallet ignores.
func paddedMeta(t *testing.T, n int) json.RawMessage {
	t.Helper()
	const head, tail = `{"vct_values":["urn:test"],"x":"`, `"}`
	if n < len(head)+len(tail) {
		t.Fatalf("a meta of %d bytes is too short", n)
	}
	return json.RawMessage(head + strings.Repeat("a", n-len(head)-len(tail)) + tail)
}

// A real meta fits MaxMetaBytes with room to spare: MaxVCTValues
// vct_values of 60 bytes each, the longest a meta needs. The meta
// builders refuse one past the bound, as Validate would.
func TestNewMeta_SizeBound(t *testing.T) {
	vcts := make([]string, dcql.MaxVCTValues)
	for i := range vcts {
		vcts[i] = fmt.Sprintf("https://credentials.example.com/vct/%024d", i)
	}
	if len(vcts[0]) != 60 {
		t.Fatalf("vct is %d bytes, want 60", len(vcts[0]))
	}
	raw, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: vcts})
	if err != nil {
		t.Fatalf("%d vct_values of 60 bytes: %v", len(vcts), err)
	}
	if err := (dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "q", Format: "dc+sd-jwt", Meta: raw}}}).Validate(); err != nil {
		t.Errorf("a meta of %d bytes: %v", len(raw), err)
	}
	for i := range vcts {
		vcts[i] += strings.Repeat("x", 4)
	}
	if _, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: vcts}); err == nil || !strings.Contains(err.Error(), "more than 4096") {
		t.Errorf("%d vct_values of 64 bytes: %v, want refused for its size", len(vcts), err)
	}
	if _, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: strings.Repeat("d", dcql.MaxMetaBytes)}); err == nil || !strings.Contains(err.Error(), "more than 4096") {
		t.Errorf("an mdoc meta past the bound: %v, want refused for its size", err)
	}
}

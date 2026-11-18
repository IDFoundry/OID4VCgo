package wallet

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
)

// matchTestCredential is an unsigned "dc+sd-jwt" credential of type
// vct: matching reads it without verifying it.
func matchTestCredential(t *testing.T, vct string) HeldCredential {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(map[string]any{"vct": vct, "cnf": map[string]any{}, "given_name": "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	return HeldCredential{Format: sdjwtvc.CredentialFormat, Credential: b64([]byte(`{"alg":"ES256"}`)) + "." + b64(payload) + ".c2ln~"}
}

func matchTestQuery(t *testing.T, id, vct string) dcql.CredentialQuery {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{vct}})
	if err != nil {
		t.Fatal(err)
	}
	return dcql.CredentialQuery{ID: id, Format: sdjwtvc.CredentialFormat, Meta: meta}
}

// heavyQuery is a query at the size bounds whose every credential_sets
// option fails on its last id: MaxCredentialQueries queries, the last
// of a type no credential has, and MaxCredentialSets optional sets of
// MaxCredentialSetOptions options naming every query. Matching once
// re-decoded every held credential for every id of every option.
func heavyQuery(t *testing.T) dcql.Query {
	t.Helper()
	var q dcql.Query
	ids := make([]string, dcql.MaxCredentialQueries)
	for i := range ids {
		ids[i] = string("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"[i])
		vct := "urn:held"
		if i == len(ids)-1 {
			vct = "urn:other"
		}
		q.Credentials = append(q.Credentials, matchTestQuery(t, ids[i], vct))
	}
	optional := false
	for range dcql.MaxCredentialSets {
		cs := dcql.CredentialSetQuery{Required: &optional}
		for range dcql.MaxCredentialSetOptions {
			cs.Options = append(cs.Options, ids)
		}
		q.CredentialSets = append(q.CredentialSets, cs)
	}
	if err := q.Validate(); err != nil {
		t.Fatalf("heavy query is not valid: %v", err)
	}
	return q
}

// Matching decodes each held credential once and matches each
// credential query once, however many credential_sets options name
// them, so a query at the size bounds is matched quickly.
func TestMatchDCQLQuery_DecodesEachCandidateOnce(t *testing.T) {
	held := make([]HeldCredential, 10)
	for i := range held {
		held[i] = matchTestCredential(t, "urn:held")
	}
	m := newMatcher(held, nil)
	start := time.Now()
	matches, err := m.matchQuery(context.Background(), heavyQuery(t))
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("matching took %v", elapsed)
	}
	if len(matches) != 0 {
		t.Errorf("matches = %v, want none: every option needs the credential no one holds", matches)
	}
	if m.decodes != len(held) {
		t.Errorf("decoded %d candidates, want each of the %d once", m.decodes, len(held))
	}
	if len(m.results) != dcql.MaxCredentialQueries {
		t.Errorf("matched %d credential queries, want each of the %d once", len(m.results), dcql.MaxCredentialQueries)
	}
}

// A done context stops matching, with or without credential_sets, and
// is reported rather than taken as no credential matching.
func TestMatchDCQLQuery_StopsWhenContextDone(t *testing.T) {
	held := []HeldCredential{matchTestCredential(t, "urn:held")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, q := range map[string]dcql.Query{
		"credential sets":    heavyQuery(t),
		"no credential sets": {Credentials: []dcql.CredentialQuery{matchTestQuery(t, "q", "urn:held")}},
	} {
		_, err := MatchDCQLQuery(ctx, q, held, nil)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: err = %v, want context.Canceled", name, err)
		}
		if errors.Is(err, ErrNoMatchingCredential) {
			t.Errorf("%s: err = %v, reported as no matching credential", name, err)
		}
	}
	if err := ValidateSelection(ctx, dcql.Query{Credentials: []dcql.CredentialQuery{matchTestQuery(t, "q", "urn:held")}}, map[string][]HeldCredential{"q": held}, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("ValidateSelection: err = %v, want context.Canceled", err)
	}
}

// A held credential that doesn't decode matches nothing, and is decoded
// once however many queries try it.
func TestMatchDCQLQuery_MalformedCandidateDecodedOnce(t *testing.T) {
	held := []HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: "not an sd-jwt"}, matchTestCredential(t, "urn:held")}
	q := dcql.Query{Credentials: []dcql.CredentialQuery{matchTestQuery(t, "a", "urn:held"), matchTestQuery(t, "b", "urn:held")}}
	m := newMatcher(held, nil)
	matches, err := m.matchQuery(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b"} {
		if len(matches[id]) != 1 || matches[id][0].Credential != held[1].Credential {
			t.Errorf("matches[%q] = %v, want the well-formed credential", id, matches[id])
		}
	}
	if m.decodes != len(held) {
		t.Errorf("decoded %d candidates, want %d", m.decodes, len(held))
	}
}

// MatchEachCredentialQuery matches every credential query on its own,
// each against every candidate, decoding each candidate once however
// many queries there are: a wallet listing what can answer an unsigned
// request's MaxCredentialQueries queries decoded every held credential
// once per query.
func TestMatchEachCredentialQuery_DecodesEachCandidateOnce(t *testing.T) {
	held := []HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: "not an sd-jwt"}}
	for range 10 {
		held = append(held, matchTestCredential(t, "urn:held"))
	}
	var q dcql.Query
	for i := range dcql.MaxCredentialQueries {
		vct := "urn:held"
		if i == 0 {
			vct = "urn:other"
		}
		q.Credentials = append(q.Credentials, matchTestQuery(t, fmt.Sprintf("q%d", i), vct))
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	m := newMatcher(held, nil)
	matches, err := m.matchEach(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	if m.decodes != len(held) {
		t.Errorf("decoded %d candidates, want each of the %d once", m.decodes, len(held))
	}
	if _, ok := matches["q0"]; ok {
		t.Errorf("matches[q0] = %v, want no entry: no credential is of its type", matches["q0"])
	}
	for _, cq := range q.Credentials[1:] {
		// Every match, though multiple is false.
		if got := len(matches[cq.ID]); got != len(held)-1 {
			t.Errorf("matches[%q] has %d credentials, want the %d well-formed ones", cq.ID, got, len(held)-1)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := MatchEachCredentialQuery(ctx, q, held, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("done context: err = %v, want context.Canceled", err)
	}
}

// knownMeta keeps only the members a format defines, which matching
// reads once per candidate; a meta of another format is left as sent.
func TestKnownMeta(t *testing.T) {
	junk := `,"x":[` + strings.Repeat("0,", 1000) + `0]}`
	for _, tc := range []struct {
		format, meta, want string
	}{
		{sdjwtvc.CredentialFormat, `{"vct_values":["urn:a","urn:b"]` + junk, `{"vct_values":["urn:a","urn:b"]}`},
		{mdoc.CredentialFormat, `{"doctype_value":"org.iso.18013.5.1.mDL"` + junk, `{"doctype_value":"org.iso.18013.5.1.mDL"}`},
		{"jwt_vc_json", `{"type_values":[["a"]]` + junk, `{"type_values":[["a"]]` + junk},
		{sdjwtvc.CredentialFormat, `[]`, `[]`},
	} {
		got := knownMeta(dcql.CredentialQuery{ID: "q", Format: tc.format, Meta: json.RawMessage(tc.meta)})
		if string(got.Meta) != tc.want {
			t.Errorf("%s meta %.40s: %s, want %.60s", tc.format, tc.meta, got.Meta, tc.want)
		}
	}
}

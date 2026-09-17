package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

func mustSDJWTVCMeta(t *testing.T, vctValues ...string) json.RawMessage {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: vctValues})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return meta
}

func mustMdocMeta(t *testing.T, doctype string) json.RawMessage {
	t.Helper()
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: doctype})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	return meta
}

func TestMetaRoundTrip(t *testing.T) {
	cq := dcql.CredentialQuery{
		ID: "pid", Format: "dc+sd-jwt",
		Meta: mustSDJWTVCMeta(t, "https://credentials.example.com/identity_credential"),
	}
	meta, err := cq.SDJWTVCMeta()
	if err != nil {
		t.Fatalf("SDJWTVCMeta: %v", err)
	}
	if len(meta.VCTValues) != 1 || meta.VCTValues[0] != "https://credentials.example.com/identity_credential" {
		t.Errorf("VCTValues = %v", meta.VCTValues)
	}

	mdl := dcql.CredentialQuery{
		ID: "mdl", Format: "mso_mdoc",
		Meta: mustMdocMeta(t, "org.iso.18013.5.1.mDL"),
	}
	mdocMeta, err := mdl.MdocMeta()
	if err != nil {
		t.Fatalf("MdocMeta: %v", err)
	}
	if mdocMeta.DoctypeValue != "org.iso.18013.5.1.mDL" {
		t.Errorf("DoctypeValue = %q", mdocMeta.DoctypeValue)
	}
}

// TestQueryValidateAcceptsWorkedExample mirrors §6's own multi-format
// example (a "pid" as dc+sd-jwt and an "mdl" as mso_mdoc, combined via
// credential_sets), confirming Validate accepts real spec-published
// queries, not just hand-picked minimal ones.
func TestQueryValidateAcceptsWorkedExample(t *testing.T) {
	q := dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{
				ID: "pid", Format: "dc+sd-jwt",
				Meta: mustSDJWTVCMeta(t, "https://credentials.example.com/identity_credential"),
				Claims: []dcql.ClaimsQuery{
					{Path: dcql.Path{dcql.PathKey("given_name")}},
					{Path: dcql.Path{dcql.PathKey("family_name")}},
					{Path: dcql.Path{dcql.PathKey("address"), dcql.PathKey("street_address")}},
				},
			},
			{
				ID: "mdl", Format: "mso_mdoc",
				Meta: mustMdocMeta(t, "org.iso.7367.1.mVRC"),
				Claims: []dcql.ClaimsQuery{
					{Path: dcql.Path{dcql.PathKey("org.iso.7367.1"), dcql.PathKey("vehicle_holder")}},
					{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("first_name")}},
				},
			},
		},
		CredentialSets: []dcql.CredentialSetQuery{
			{Options: [][]string{{"pid"}, {"mdl"}}},
		},
	}
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if q.CredentialSets[0].IsRequired() != true {
		t.Errorf("IsRequired() = false, want true (default)")
	}
	if q.Credentials[0].RequiresCryptographicHolderBinding() != true {
		t.Errorf("RequiresCryptographicHolderBinding() = false, want true (default)")
	}
}

// claimSetsCredentialQuery mirrors §6.4.1's own worked example: a
// required claim plus an either/or pair, expressed as two claim_sets
// options — shared by TestQueryValidateAcceptsClaimSets (structural
// validation) and TestSatisfiedBySDJWTVCClaimsWithClaimSets (claim
// resolution) so the fixture exists exactly once.
func claimSetsCredentialQuery(t *testing.T) dcql.CredentialQuery {
	t.Helper()
	return dcql.CredentialQuery{
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
}

// TestQueryValidateAcceptsClaimSets mirrors §6.4.1's own worked
// example: required claims plus an either/or pair via claim_sets.
func TestQueryValidateAcceptsClaimSets(t *testing.T) {
	q := dcql.Query{Credentials: []dcql.CredentialQuery{claimSetsCredentialQuery(t)}}
	if err := q.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestQueryValidateRejects(t *testing.T) {
	validMeta := func(t *testing.T) json.RawMessage { return mustSDJWTVCMeta(t, "vct") }

	cases := map[string]func(t *testing.T) dcql.Query{
		"empty credentials": func(t *testing.T) dcql.Query {
			return dcql.Query{}
		},
		"duplicate credential id": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{
				{ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t)},
				{ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t)},
			}}
		},
		"missing id": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{Format: "dc+sd-jwt", Meta: validMeta(t)}}}
		},
		"id with invalid characters": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "not valid!", Format: "dc+sd-jwt", Meta: validMeta(t)}}}
		},
		"missing format": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "a", Meta: validMeta(t)}}}
		},
		"missing meta": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt"}}}
		},
		"meta not an object": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt", Meta: json.RawMessage(`"nope"`)}}}
		},
		"meta invalid json": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt", Meta: json.RawMessage(`{`)}}}
		},
		"claim id required with claim_sets": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				Claims:    []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("x")}}},
				ClaimSets: [][]string{{"missing-id"}},
			}}}
		},
		"duplicate claim id": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				Claims: []dcql.ClaimsQuery{
					{ID: "x", Path: dcql.Path{dcql.PathKey("x")}},
					{ID: "x", Path: dcql.Path{dcql.PathKey("y")}},
				},
			}}}
		},
		"duplicate claim path": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				Claims: []dcql.ClaimsQuery{
					{Path: dcql.Path{dcql.PathKey("x")}},
					{Path: dcql.Path{dcql.PathKey("x")}},
				},
			}}}
		},
		"claim_sets references unknown claim id": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				Claims:    []dcql.ClaimsQuery{{ID: "x", Path: dcql.Path{dcql.PathKey("x")}}},
				ClaimSets: [][]string{{"nonexistent"}},
			}}}
		},
		"empty claim path": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				Claims: []dcql.ClaimsQuery{{Path: dcql.Path{}}},
			}}}
		},
		"trusted authority missing type": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				TrustedAuthorities: []dcql.TrustedAuthoritiesQuery{{Values: []string{"x"}}},
			}}}
		},
		"trusted authority missing values": func(t *testing.T) dcql.Query {
			return dcql.Query{Credentials: []dcql.CredentialQuery{{
				ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t),
				TrustedAuthorities: []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI}},
			}}}
		},
		"credential_sets empty options": func(t *testing.T) dcql.Query {
			return dcql.Query{
				Credentials:    []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t)}},
				CredentialSets: []dcql.CredentialSetQuery{{}},
			}
		},
		"credential_sets references unknown credential id": func(t *testing.T) dcql.Query {
			return dcql.Query{
				Credentials:    []dcql.CredentialQuery{{ID: "a", Format: "dc+sd-jwt", Meta: validMeta(t)}},
				CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{"nonexistent"}}}},
			}
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			q := build(t)
			if err := q.Validate(); err == nil {
				t.Fatalf("Validate(%s) = nil error, want error", name)
			}
		})
	}
}

func TestCredentialSetQueryIsRequiredExplicitFalse(t *testing.T) {
	f := false
	cs := dcql.CredentialSetQuery{Options: [][]string{{"a"}}, Required: &f}
	if cs.IsRequired() {
		t.Errorf("IsRequired() = true, want false")
	}
}

func TestCredentialQueryRequiresCryptographicHolderBindingExplicitFalse(t *testing.T) {
	f := false
	cq := dcql.CredentialQuery{RequireCryptographicHolderBinding: &f}
	if cq.RequiresCryptographicHolderBinding() {
		t.Errorf("RequiresCryptographicHolderBinding() = true, want false")
	}
}

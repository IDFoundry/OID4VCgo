package dcql_test

import (
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// The constructors build the same query as setting Format and Meta by
// hand, and an empty type makes a query Validate refuses.
func TestQueryConstructors(t *testing.T) {
	sdjwtMeta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		t.Fatal(err)
	}
	mdocMeta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mDL"})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		got, want dcql.CredentialQuery
	}{
		"sd-jwt vc": {
			dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1", dcql.KeyPath("given_name"), dcql.KeyPath("address", "country")),
			dcql.CredentialQuery{ID: "pid", Format: "dc+sd-jwt", Meta: sdjwtMeta, Claims: []dcql.ClaimsQuery{
				{Path: dcql.Path{dcql.PathKey("given_name")}},
				{Path: dcql.Path{dcql.PathKey("address"), dcql.PathKey("country")}},
			}},
		},
		"mdoc": {
			dcql.MdocQuery("mdl", "org.iso.18013.5.1.mDL", dcql.KeyPath("org.iso.18013.5.1", "family_name")),
			dcql.CredentialQuery{ID: "mdl", Format: "mso_mdoc", Meta: mdocMeta, Claims: []dcql.ClaimsQuery{
				{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("family_name")}},
			}},
		},
		"no claims": {
			dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1"),
			dcql.CredentialQuery{ID: "pid", Format: "dc+sd-jwt", Meta: sdjwtMeta},
		},
	} {
		if !reflect.DeepEqual(tc.got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, tc.got, tc.want)
		}
		if err := (dcql.Query{Credentials: []dcql.CredentialQuery{tc.got}}).Validate(); err != nil {
			t.Errorf("%s: Validate: %v", name, err)
		}
	}
	for name, q := range map[string]dcql.CredentialQuery{
		"empty vct":     dcql.SDJWTVCQuery("pid", ""),
		"empty doctype": dcql.MdocQuery("mdl", ""),
		"empty path":    dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1", dcql.KeyPath()),
	} {
		if err := (dcql.Query{Credentials: []dcql.CredentialQuery{q}}).Validate(); err == nil {
			t.Errorf("%s: Validate accepted it", name)
		}
	}
}

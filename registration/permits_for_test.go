package registration_test

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/registration"
)

// Claims registered for one type of credential aren't registered for
// another: family_name from a loyalty card doesn't cover family_name from
// a PID.
func TestPermitsFor(t *testing.T) {
	familyName := dcql.Path{dcql.PathKey("family_name")}
	query := func(t *testing.T, format string, meta func() ([]byte, error)) dcql.CredentialQuery {
		t.Helper()
		m, err := meta()
		if err != nil {
			t.Fatal(err)
		}
		return dcql.CredentialQuery{ID: "q", Format: format, Meta: m}
	}
	sdjwt := func(vcts ...string) dcql.CredentialQuery {
		return query(t, "dc+sd-jwt", func() ([]byte, error) { return dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: vcts}) })
	}
	mdl := query(t, "mso_mdoc", func() ([]byte, error) { return dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: "org.iso.18013.5.1.mDL"}) })

	r := registration.Registration{Credentials: []registration.RegisteredCredential{
		{VCTValues: []string{"urn:example:loyalty"}, Claims: []dcql.Path{familyName}},
		{DoctypeValue: "org.iso.18013.5.1.mDL", Claims: []dcql.Path{{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("family_name")}}},
	}}
	for name, tc := range map[string]struct {
		cq   dcql.CredentialQuery
		path dcql.Path
		want bool
	}{
		"the registered type":             {sdjwt("urn:example:loyalty"), familyName, true},
		"another type":                    {sdjwt("urn:eudi:pid:1"), familyName, false},
		"the registered type and another": {sdjwt("urn:example:loyalty", "urn:eudi:pid:1"), familyName, false},
		"the registered doctype":          {mdl, dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("family_name")}, true},
		"an unregistered element":         {mdl, dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("portrait")}, false},
	} {
		if got := r.PermitsFor(tc.cq, tc.path); got != tc.want {
			t.Errorf("%s: PermitsFor = %v, want %v", name, got, tc.want)
		}
	}
	// Claims, without a type, still cover any.
	if !(registration.Registration{Claims: []dcql.Path{familyName}}).PermitsFor(sdjwt("urn:eudi:pid:1"), familyName) {
		t.Error("claims without a type don't cover a PID")
	}
}

// Credentials survive Issue and Verify; an entry naming neither type, or
// both, is refused.
func TestIssueVerify_Credentials(t *testing.T) {
	reg := newRegistrar(t)
	r := shop()
	r.Claims = nil
	r.Credentials = []registration.RegisteredCredential{{VCTValues: []string{"urn:example:loyalty"}, Claims: []dcql.Path{path("family_name")}}}
	token, err := registration.Issue(r, reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verify(token, reg.roots, clientID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Credentials) != 1 || got.Credentials[0].VCTValues[0] != "urn:example:loyalty" || len(got.Credentials[0].Claims) != 1 {
		t.Errorf("Credentials = %+v", got.Credentials)
	}
	for _, bad := range []registration.RegisteredCredential{
		{Claims: []dcql.Path{path("family_name")}},
		{VCTValues: []string{"urn:x"}, DoctypeValue: "org.iso.18013.5.1.mDL"},
	} {
		r.Credentials = []registration.RegisteredCredential{bad}
		if _, err := registration.Issue(r, reg.key, reg.chain); err == nil {
			t.Errorf("Issue accepted %+v", bad)
		}
	}
}

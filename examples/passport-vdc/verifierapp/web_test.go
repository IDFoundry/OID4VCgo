package verifierapp

import (
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// Each page state maps to the coarse state the status endpoint reports,
// an answer winning over the rest.
func TestPageState_Coarse(t *testing.T) {
	for _, tc := range []struct {
		st   pageState
		want string
	}{
		{pageState{}, stateWaiting},
		{pageState{lastError: "bad"}, stateWaiting},
		{pageState{awaiting: true}, stateAwaiting},
		{pageState{closed: true, lastError: "bad"}, stateClosed},
		{pageState{outcome: &Outcome{}, awaiting: true}, stateAnswered},
	} {
		if got := tc.st.coarse(); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.st, got, tc.want)
		}
	}
}

// What a scenario asked for is read from its own query, per format, and
// set against what the credential disclosed.
func TestAskedForAndReceived(t *testing.T) {
	q, err := buildQuery(ScenarioSignup, "https://issuer.example/vct", dcql.TrustedAuthoritiesQuery{Type: "aki", Values: []string{"AAAA"}})
	if err != nil {
		t.Fatal(err)
	}
	sdjwt := map[string]any{
		credential.FamilyName: "DOE", credential.GivenName: "JANE", credential.SDJWTAgeEqualOrOver: map[string]any{"18": true},
		"vct": "https://issuer.example/vct", "exp": float64(0),
	}
	asked := askedFor(q, "dc+sd-jwt", sdjwt)
	want := []requested{{"Family name", true}, {"Given names", true}, {"Over 18", true}, {"Photo", false}}
	if !slices.Equal(asked, want) {
		t.Errorf("asked (SD-JWT) = %v, want %v", asked, want)
	}
	if got := demoui.DisclosedLabels("dc+sd-jwt", sdjwt); !slices.Equal(got, []string{"Family name", "Given names", "Over 18"}) {
		t.Errorf("received (SD-JWT) = %v", got)
	}
	mdoc := map[string]any{credential.FamilyName: "DOE", credential.GivenName: "JANE", "age_over_18": true, credential.Portrait: []byte{0xff}}
	asked = askedFor(q, "mso_mdoc", mdoc)
	want = []requested{{"Family name", true}, {"Given names", true}, {"Over 18", true}, {"Photo", true}}
	if !slices.Equal(asked, want) {
		t.Errorf("asked (mdoc) = %v, want %v", asked, want)
	}
	if got := demoui.DisclosedLabels("mso_mdoc", mdoc); !slices.Equal(got, []string{"Family name", "Given names", "Over 18", "Photo"}) {
		t.Errorf("received (mdoc) = %v", got)
	}
}

// A person of several is headed by number and name: the disclosed one,
// or the re-verified passport's.
func TestPersonHeading(t *testing.T) {
	for _, tc := range []struct {
		p    Person
		want string
	}{
		{Person{Claims: map[string]any{credential.FamilyName: "DOE", credential.GivenName: "JANE"}}, "Person 1 — DOE, JANE"},
		{Person{Claims: map[string]any{credential.PassportFile: "…"}, ICAO: &ICAOResult{Verified: true, Identity: passport.Identity{FamilyName: "ROE", GivenNames: "JOHN"}}}, "Person 1 — ROE, JOHN"},
		{Person{Claims: map[string]any{}, ICAO: &ICAOResult{Identity: passport.Identity{FamilyName: "ROE"}}}, "Person 1"},
	} {
		if got := personHeading(0, tc.p); got != tc.want {
			t.Errorf("personHeading = %q, want %q", got, tc.want)
		}
	}
}

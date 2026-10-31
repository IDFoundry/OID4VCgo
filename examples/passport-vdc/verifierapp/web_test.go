package verifierapp

import (
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
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

// Claims are labelled for people, in either format: expiry_date is the
// credential's in an mdoc and the passport's in an SD-JWT VC.
func TestClaimLabel(t *testing.T) {
	for _, tc := range []struct{ format, key, want string }{
		{"mso_mdoc", credential.FamilyName, "Family name"},
		{"dc+sd-jwt", credential.GivenName, "Given names"},
		{"mso_mdoc", credential.BirthDate, "Date of birth"},
		{"dc+sd-jwt", credential.SDJWTBirthDate, "Date of birth"},
		{"mso_mdoc", credential.Nationality, "Nationality"},
		{"dc+sd-jwt", credential.SDJWTNationalities, "Nationality"},
		{"mso_mdoc", credential.TravelDocumentNumber, "Passport number"},
		{"dc+sd-jwt", credential.DocumentNumber, "Passport number"},
		{"mso_mdoc", credential.ExpiryDate, "Credential expiry"},
		{"dc+sd-jwt", credential.ExpiryDate, "Passport expiry"},
		{"mso_mdoc", credential.PassportExpiryDate, "Passport expiry"},
		{"mso_mdoc", "age_over_18", "Over 18"},
		{"mso_mdoc", "age_over_65", "Over 65"},
		{"dc+sd-jwt", credential.SDJWTPicture, "Photo"},
		{"dc+sd-jwt", "vct", "Credential type"},
		{"dc+sd-jwt", "something_new", "something_new"},
	} {
		if got := claimLabel(tc.format, tc.key); got != tc.want {
			t.Errorf("claimLabel(%s, %s) = %q, want %q", tc.format, tc.key, got, tc.want)
		}
	}
}

// Values read as words: dates, sexes, booleans, lists; raw data and
// structures are flagged for collapsing.
func TestFormatClaim(t *testing.T) {
	long := string(make([]byte, maxShown+1))
	for _, tc := range []struct {
		name, format, key string
		v                 any
		want              string
		raw               bool
	}{
		{"SD-JWT date", "dc+sd-jwt", credential.ExpiryDate, "2031-10-31", "31 October 2031", false},
		{"mdoc full-date", "mso_mdoc", credential.PassportExpiryDate, cbor.Tag{Number: 1004, Content: "2031-10-31"}, "31 October 2031", false},
		{"mdoc birth_date", "mso_mdoc", credential.BirthDate, map[any]any{credential.BirthDate: cbor.Tag{Number: 1004, Content: "1980-01-02"}}, "2 January 1980", false},
		{"approximate birth_date", "mso_mdoc", credential.BirthDate, map[string]any{credential.BirthDate: "2010-01-02", "approximate_mask": "11000000"}, "2 January 2010 (approximate)", false},
		{"mdoc sex", "mso_mdoc", credential.Sex, uint64(2), "Female", false},
		{"SD-JWT sex", "dc+sd-jwt", credential.Sex, "M", "Male", false},
		{"unknown sex", "mso_mdoc", credential.Sex, uint64(0), "Unspecified", false},
		{"true", "mso_mdoc", credential.NamesFromMRZ, true, "✓ Yes", false},
		{"false", "mso_mdoc", credential.NamesFromMRZ, false, "✗ No", false},
		{"list", "dc+sd-jwt", credential.SDJWTNationalities, []any{"SGP", "GBR"}, "SGP, GBR", false},
		{"text", "dc+sd-jwt", credential.FamilyName, "DOE", "DOE", false},
		{"exp", "dc+sd-jwt", "exp", float64(1824940800), "31 October 2027, 00:00 UTC", false},
		{"bytes", "mso_mdoc", credential.PassportFile, []byte{1, 2, 3}, "3 bytes", true},
		{"base64url", "dc+sd-jwt", credential.PassportFile, long, "201 characters (base64url)", true},
		{"structure", "dc+sd-jwt", "cnf", map[string]any{"jwk": map[string]any{"kty": "EC"}}, `{"jwk":{"kty":"EC"}}`, true},
	} {
		got, raw := formatClaim(tc.format, tc.key, tc.v)
		if got != tc.want || raw != tc.raw {
			t.Errorf("%s: %q (raw %v), want %q (raw %v)", tc.name, got, raw, tc.want, tc.raw)
		}
	}
}

// displayRows puts who the holder is first, shows ages as "✓ Over 18",
// leaves the portrait to the image, and collapses the credential's own
// claims and the raw data.
func TestDisplayRows(t *testing.T) {
	rows, raw := displayRows("dc+sd-jwt", map[string]any{
		credential.DocumentNumber: "K0000000A", credential.FamilyName: "DOE", credential.GivenName: "JANE",
		credential.SDJWTBirthDate: "1980-01-01", credential.SDJWTAgeEqualOrOver: map[string]any{"18": true, "65": false},
		credential.SDJWTPicture: "data:image/jpeg;base64,AAAA", credential.PassportFile: string(make([]byte, 300)),
		"vct": "https://issuer.example/vct", "cnf": map[string]any{},
	})
	want := []claimRow{
		{"Family name", "DOE"}, {"Given names", "JANE"}, {"Date of birth", "1 January 1980"},
		{"Age", "✓ Over 18"}, {"Age", "✗ Under 65"}, {"Passport number", "K0000000A"},
	}
	if !slices.Equal(rows, want) {
		t.Errorf("rows = %v, want %v", rows, want)
	}
	var rawLabels []string
	for _, r := range raw {
		rawLabels = append(rawLabels, r.Label)
	}
	slices.Sort(rawLabels)
	if !slices.Equal(rawLabels, []string{"Credential type", "Holder key", "Passport file (chip data)"}) {
		t.Errorf("raw rows = %v", rawLabels)
	}

	rows, _ = displayRows("mso_mdoc", map[string]any{"age_over_18": true, credential.FamilyName: "DOE"})
	if !slices.Equal(rows, []claimRow{{"Family name", "DOE"}, {"Age", "✓ Over 18"}}) {
		t.Errorf("mdoc rows = %v", rows)
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
	if got := received("dc+sd-jwt", sdjwt); !slices.Equal(got, []string{"Family name", "Given names", "Over 18"}) {
		t.Errorf("received (SD-JWT) = %v", got)
	}
	mdoc := map[string]any{credential.FamilyName: "DOE", credential.GivenName: "JANE", "age_over_18": true, credential.Portrait: []byte{0xff}}
	asked = askedFor(q, "mso_mdoc", mdoc)
	want = []requested{{"Family name", true}, {"Given names", true}, {"Over 18", true}, {"Photo", true}}
	if !slices.Equal(asked, want) {
		t.Errorf("asked (mdoc) = %v, want %v", asked, want)
	}
	if got := received("mso_mdoc", mdoc); !slices.Equal(got, []string{"Family name", "Given names", "Over 18", "Photo"}) {
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

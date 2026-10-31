package demoui

import (
	"slices"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

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
		if got := ClaimLabel(tc.format, tc.key); got != tc.want {
			t.Errorf("ClaimLabel(%s, %s) = %q, want %q", tc.format, tc.key, got, tc.want)
		}
	}
}

// Values read as words: dates, sexes, booleans, lists; raw data and
// structures are flagged for collapsing.
func TestFormatClaim(t *testing.T) {
	long := string(make([]byte, MaxShown+1))
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
		got, raw := FormatClaim(tc.format, tc.key, tc.v)
		if got != tc.want || raw != tc.raw {
			t.Errorf("%s: %q (raw %v), want %q (raw %v)", tc.name, got, raw, tc.want, tc.raw)
		}
	}
}

// DisplayRows puts who the holder is first, shows ages as "✓ Over 18",
// leaves the portrait to the image, and collapses the credential's own
// claims and the raw data.
func TestDisplayRows(t *testing.T) {
	rows, raw := DisplayRows("dc+sd-jwt", map[string]any{
		credential.DocumentNumber: "K0000000A", credential.FamilyName: "DOE", credential.GivenName: "JANE",
		credential.SDJWTBirthDate: "1980-01-01", credential.SDJWTAgeEqualOrOver: map[string]any{"18": true, "65": false},
		credential.SDJWTPicture: "data:image/jpeg;base64,AAAA", credential.PassportFile: string(make([]byte, 300)),
		"vct": "https://issuer.example/vct", "cnf": map[string]any{},
	})
	want := []ClaimRow{
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

	rows, _ = DisplayRows("mso_mdoc", map[string]any{"age_over_18": true, credential.FamilyName: "DOE"})
	if !slices.Equal(rows, []ClaimRow{{"Family name", "DOE"}, {"Age", "✓ Over 18"}}) {
		t.Errorf("mdoc rows = %v", rows)
	}
}

// A claim path is labelled as its claim: an mdoc's without its
// namespace, an SD-JWT VC's age_equal_or_over by its age.
func TestPathLabel(t *testing.T) {
	for _, tc := range []struct {
		format string
		path   []string
		want   string
	}{
		{"mso_mdoc", []string{credential.ISONamespace, credential.FamilyName}, "Family name"},
		{"mso_mdoc", []string{credential.FileNamespace, credential.PassportFile}, "Passport file (chip data)"},
		{"mso_mdoc", []string{credential.ISONamespace, "age_over_18"}, "Over 18"},
		{"dc+sd-jwt", []string{credential.SDJWTAgeEqualOrOver, "21"}, "Over 21"},
		{"dc+sd-jwt", []string{credential.ExpiryDate}, "Passport expiry"},
		{"mso_mdoc", []string{credential.ISONamespace, credential.ExpiryDate}, "Credential expiry"},
		{"mso_mdoc", []string{credential.ISONamespace}, "(unnamed claim)"},
		{"dc+sd-jwt", nil, "(unnamed claim)"},
	} {
		if got := PathLabel(tc.format, tc.path); got != tc.want {
			t.Errorf("PathLabel(%s, %v) = %q, want %q", tc.format, tc.path, got, tc.want)
		}
	}
}

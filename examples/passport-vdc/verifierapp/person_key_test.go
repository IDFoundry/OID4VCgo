package verifierapp

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// A group scenario re-verifying passport files takes one passport once,
// however its file is encoded: two files that verify as the same
// passport (issuing country and document number) are one person, so the
// hotel can't check one passport in twice from two reads of its chip,
// or from one file re-encoded. A file that doesn't verify, which the
// decision refuses anyway, is told apart by its bytes, and a scenario
// without files by the identity disclosed.
func TestPersonKey(t *testing.T) {
	verified := func(country, number string) *ICAOResult {
		return &ICAOResult{Verified: true, Identity: passport.Identity{IssuingCountry: country, DocumentNumber: number}}
	}
	file := func(b ...byte) map[string]any { return map[string]any{credential.PassportFile: b} }
	named := func(family string) map[string]any {
		return map[string]any{credential.FamilyName: family, credential.DocumentNumber: "K0000000A"}
	}
	for _, tc := range []struct {
		name   string
		claims [2]map[string]any
		icao   [2]*ICAOResult
		same   bool
	}{
		{"one passport, two files", [2]map[string]any{file(1), file(2)}, [2]*ICAOResult{verified("GBR", "1"), verified("GBR", "1")}, true},
		{"two passports", [2]map[string]any{file(1), file(1)}, [2]*ICAOResult{verified("GBR", "1"), verified("GBR", "2")}, false},
		{"one number, two countries", [2]map[string]any{file(1), file(2)}, [2]*ICAOResult{verified("GBR", "1"), verified("IRL", "1")}, false},
		{"one unverified file twice", [2]map[string]any{file(1), file(1)}, [2]*ICAOResult{{}, {}}, true},
		{"two unverified files", [2]map[string]any{file(1), file(2)}, [2]*ICAOResult{{}, {}}, false},
		{"one identity, no file", [2]map[string]any{named("DOE"), named("DOE")}, [2]*ICAOResult{}, true},
		{"two identities, no file", [2]map[string]any{named("DOE"), named("ROE")}, [2]*ICAOResult{}, false},
	} {
		a, errA := personKey(tc.claims[0], tc.icao[0])
		b, errB := personKey(tc.claims[1], tc.icao[1])
		if errA != nil || errB != nil || (a == b) != tc.same {
			t.Errorf("%s: same = %v (%v, %v), want %v", tc.name, a == b, errA, errB, tc.same)
		}
	}
	if _, err := personKey(map[string]any{}, &ICAOResult{}); err == nil {
		t.Error("an unverified file not disclosed: nil error")
	}
}

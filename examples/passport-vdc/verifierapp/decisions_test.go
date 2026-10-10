package verifierapp

import (
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// TestDecide covers what each scenario's relying party decides, in
// either format's claims.
func TestDecide(t *testing.T) {
	verified := &ICAOResult{Verified: true, Identity: passport.Identity{IssuingCountry: "SGP"}}
	expired := &ICAOResult{Verified: true, Expired: true}
	failed := &ICAOResult{Error: "x"}
	sdjwtAge := func(over bool) map[string]any {
		return map[string]any{credential.SDJWTAgeEqualOrOver: map[string]any{"18": over}}
	}
	for _, c := range []struct {
		name     string
		sc       Scenario
		out      Outcome
		approved bool
		text     string
	}{
		{"age, mdoc, over", ScenarioAge, Outcome{Claims: map[string]any{"age_over_18": true}}, true, "Sale allowed"},
		{"age, sd-jwt, under", ScenarioAge, Outcome{Claims: sdjwtAge(false)}, false, "under 18"},
		{"age, no claim", ScenarioAge, Outcome{Claims: map[string]any{}}, false, "didn't say"},
		{"signup", ScenarioSignup, Outcome{Claims: map[string]any{credential.GivenName: "JANE", credential.FamilyName: "DOE", "age_over_18": true}}, true, "Account created for JANE DOE"},
		{"signup, under 18", ScenarioSignup, Outcome{Claims: sdjwtAge(false)}, false, "Sign-up refused"},
		{"signup, age withheld", ScenarioSignup, Outcome{Claims: map[string]any{credential.GivenName: "JANE", credential.FamilyName: "DOE"}}, false, "Sign-up refused"},
		{"bank, verified", ScenarioBank, Outcome{ICAO: verified}, true, "Account opened: passport verified with its issuing country (SGP)"},
		{"bank, expired", ScenarioBank, Outcome{ICAO: expired}, false, "expired"},
		{"bank, not verified", ScenarioBank, Outcome{ICAO: failed}, false, "couldn't be verified"},
		{"unknown", ScenarioUnknown, Outcome{ICAO: verified}, false, "shouldn't have"},
		{"hotel, all verified", ScenarioHotel, Outcome{People: []Person{{ICAO: verified}, {ICAO: expired}}}, true, "Checked in 2 guests"},
		{"hotel, one guest", ScenarioHotel, Outcome{People: []Person{{ICAO: verified}}}, true, "Checked in 1 guest"},
		{"over-asking, names given", ScenarioOverAsking, Outcome{Claims: map[string]any{"age_over_18": true, credential.GivenName: "JANE", credential.FamilyName: "DOE"}}, true, "now has JANE DOE's name"},
		{"over-asking, under 18", ScenarioOverAsking, Outcome{Claims: sdjwtAge(false)}, false, "Sale refused"},
		{"hotel, one failed", ScenarioHotel, Outcome{People: []Person{{ICAO: verified}, {ICAO: failed}}}, false, "1 of 2 passports"},
	} {
		got := decide(c.sc, &c.out)
		if got.Approved != c.approved || !strings.Contains(got.Text, c.text) {
			t.Errorf("%s: decision = %+v, want approved %v, %q", c.name, got, c.approved, c.text)
		}
	}
}

// TestScenarios_Queries: each scenario's query asks for what its card
// says — one derived fact, a few claims, or the passport file — and
// only the hotel's takes several credentials.
func TestScenarios_Queries(t *testing.T) {
	for _, s := range Scenarios {
		info, ok := s.Info()
		if !ok || info.Verifier == "" || info.Title == "" {
			t.Fatalf("%s: no description", s)
		}
		q, err := buildQuery(s, "https://issuer.example/vct", trustedForTest(t))
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		for _, cq := range q.Credentials {
			if cq.Multiple != (s == ScenarioHotel) {
				t.Errorf("%s: multiple = %v", s, cq.Multiple)
			}
			var paths []string
			for _, c := range cq.Claims {
				var keys []string
				for _, e := range c.Path {
					if e.IsKey() {
						keys = append(keys, e.Key())
					}
				}
				paths = append(paths, strings.Join(keys, "/"))
			}
			joined := strings.Join(paths, " ")
			switch {
			case info.Evidence && (len(paths) != 1 || !strings.Contains(joined, credential.PassportFile)):
				t.Errorf("%s %s: claims %v, want only the passport file", s, cq.ID, paths)
			case s == ScenarioAge && (len(paths) != 1 || !strings.Contains(joined, "18")):
				t.Errorf("%s %s: claims %v, want only the over-18 claim", s, cq.ID, paths)
			}
		}
	}
	if _, err := buildQuery("nope", "https://issuer.example/vct", trustedForTest(t)); err == nil {
		t.Error("an unknown scenario built a query")
	}
}

func trustedForTest(t *testing.T) dcql.TrustedAuthoritiesQuery {
	t.Helper()
	ca, _, err := newCA(time.Now(), "test issuer CA")
	if err != nil {
		t.Fatal(err)
	}
	q, err := dcql.AKITrustedAuthorities(ca)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

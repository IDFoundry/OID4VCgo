package verifierapp

import (
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// decide is what scenario sc's relying party decides from out, a
// verified presentation.
func decide(sc Scenario, out *Outcome) Decision {
	switch sc {
	case ScenarioAge:
		switch over, ok := over18(out.Claims); {
		case !ok:
			return Decision{Text: "Sale refused: the credential didn't say whether the customer is over 18"}
		case !over:
			return Decision{Text: "Sale refused: the customer is under 18"}
		}
		return Decision{Approved: true, Text: "Sale allowed: the customer is over 18"}
	case ScenarioSignup:
		if over, ok := over18(out.Claims); ok && !over {
			return Decision{Text: "Sign-up refused: under 18"}
		}
		return Decision{Approved: true, Text: "Account created for " + nameOf(out.Claims)}
	case ScenarioBank:
		switch icao := out.ICAO; {
		case icao == nil || !icao.Verified:
			return Decision{Text: "Account not opened: the passport couldn't be verified with its issuing country"}
		case icao.Expired:
			return Decision{Text: "Account not opened: the passport has expired"}
		default:
			return Decision{Approved: true, Text: fmt.Sprintf("Account opened: passport verified with its issuing country (%s)", icao.Identity.IssuingCountry)}
		}
	case ScenarioUnknown:
		// No wallet trusting only the demo's verifier CA answers this.
		return Decision{Text: "CheapFlights received the passport file: the wallet trusted a verifier it shouldn't have"}
	case ScenarioHotel:
		failed := 0
		for _, p := range out.People {
			if p.ICAO == nil || !p.ICAO.Verified {
				failed++
			}
		}
		if failed > 0 {
			return Decision{Text: fmt.Sprintf("Check-in refused: %d of %d passports couldn't be verified with their issuing country", failed, len(out.People))}
		}
		guests := "guest"
		if len(out.People) != 1 {
			guests += "s"
		}
		return Decision{Approved: true, Text: fmt.Sprintf("Checked in %d %s", len(out.People), guests)}
	}
	return Decision{}
}

// over18 reads the over-18 claim, in either format: an mdoc's
// age_over_18, or an SD-JWT VC's age_equal_or_over["18"].
func over18(claims map[string]any) (over, ok bool) {
	if v, found := claims["age_over_18"].(bool); found {
		return v, true
	}
	if ages, found := claims[credential.SDJWTAgeEqualOrOver].(map[string]any); found {
		v, found := ages["18"].(bool)
		return v, found
	}
	return false, false
}

// nameOf is the holder's given and family names, from the claims.
func nameOf(claims map[string]any) string {
	var parts []string
	for _, k := range []string{credential.GivenName, credential.FamilyName} {
		if v, ok := claims[k].(string); ok && v != "" {
			parts = append(parts, v)
		}
	}
	if len(parts) == 0 {
		return "the holder"
	}
	return strings.Join(parts, " ")
}

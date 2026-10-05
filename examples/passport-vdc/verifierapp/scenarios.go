// Package verifierapp is the passport-vdc demo's Verifier: relying
// parties asking a wallet for its passport-derived credential over
// OpenID4VP, in either format, each for its own purpose (a Scenario).
// Together they show three things growing: what a verifier needs, from
// one derived fact to the passport itself; how much the wallet presents,
// from selected claims to several credentials; and who is asking, a
// trusted verifier or one the wallet refuses outright.
//
// A scenario either trusts the issuer for identity attributes (the
// credential's issuer signature, chained to the demo issuer's CA), or
// trusts only the issuing country: it requests the gmrtd portable
// passport file and re-verifies it with gmrtd against the CSCA master
// list, so the demo issuer can't have altered the data. The file is one
// claim, so that discloses everything the chip held. Either way the
// issuer signature is checked, and the credential's device key binds it
// to the presenter.
package verifierapp

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// Scenario is a demo use case: a relying party, what it asks for, and
// what it decides from the answer.
type Scenario string

const (
	// ScenarioAge is age assurance: one derived fact, over 18 or not.
	ScenarioAge Scenario = "age"
	// ScenarioSignup is a low-risk sign-up: a name, an over-18 check
	// and, if the passport has one, a photo.
	ScenarioSignup Scenario = "signup"
	// ScenarioBank is bank KYC: the passport file, re-verified with its
	// issuing country.
	ScenarioBank Scenario = "bank"
	// ScenarioUnknown asks for what the bank does, but signs its
	// requests under a CA no demo wallet trusts: a wallet refuses it
	// without opening the request.
	ScenarioUnknown Scenario = "unknown"
	// ScenarioHotel is a family hotel check-in: the passport file of
	// each guest, re-verified, in one presentation (DCQL multiple,
	// OpenID4VP 1.0 §6.1).
	ScenarioHotel Scenario = "hotel"
	// ScenarioOverAsking is age assurance from a shop registered to ask
	// only whether you're over 18, which asks for your name too: a
	// wallet checking its registration warns before you share.
	ScenarioOverAsking Scenario = "overasking"
)

// Scenarios are the scenarios in the order the demo runs them.
var Scenarios = []Scenario{ScenarioAge, ScenarioSignup, ScenarioBank, ScenarioUnknown, ScenarioHotel, ScenarioOverAsking}

// ScenarioInfo describes a scenario on the verifier's home page.
type ScenarioInfo struct {
	Scenario Scenario
	Icon     string
	Title    string
	// Verifier is the relying party's name: its request-signing
	// certificate's common name, which a wallet shows as who's asking.
	Verifier string
	// Asks is what it requests, in words; Shows, what it demonstrates.
	Asks, Shows string
	// Evidence: it requests the passport file and re-verifies it
	// (trusting the issuing country), rather than identity claims.
	Evidence bool
	// Multiple: it takes several credentials, one per person.
	Multiple bool
	// Trusted: its requests are signed under the verifier CA wallets
	// trust (VerifierCACertificate); otherwise under one they don't.
	Trusted bool
	// RegisteredAs is the scenario whose query its registration covers,
	// when not its own: a relying party registered for less than it
	// asks. A trusted scenario's requests carry its registration.
	RegisteredAs Scenario
}

var scenarioInfo = map[Scenario]ScenarioInfo{
	ScenarioAge: {
		Icon: "🔞", Title: "Age assurance", Verifier: "Corner Bottle Shop", Trusted: true,
		Asks:  "whether you're over 18 — nothing else",
		Shows: "Minimal disclosure: one derived fact, not who you are.",
	},
	ScenarioSignup: {
		Icon: "👤", Title: "Low-risk sign-up", Verifier: "Chirp Social", Trusted: true,
		Asks:  "your name, an over-18 check and, if your passport has one, a photo",
		Shows: "Selective disclosure: just enough identity, trusting the issuer.",
	},
	ScenarioBank: {
		Icon: "🏦", Title: "Bank KYC", Verifier: "Harbour Bank", Trusted: true, Evidence: true,
		Asks:  "your passport file, read from the chip",
		Shows: "High assurance: the bank re-verifies the passport with its issuing country, so the demo issuer can't have altered it.",
	},
	ScenarioUnknown: {
		Icon: "❓", Title: "Unknown verifier", Verifier: "CheapFlights", Evidence: true,
		Asks:  "your passport file — the same as the bank",
		Shows: "Verifier trust: a valid request from a verifier your wallet doesn't trust is refused unopened. Nothing is shared.",
	},
	ScenarioHotel: {
		Icon: "🏨", Title: "Family hotel check-in", Verifier: "Grand Hotel", Trusted: true, Evidence: true, Multiple: true,
		Asks:  "the passport file of each guest",
		Shows: "Several credentials in one presentation, each passport re-verified — as hotels scan passports today.",
	},
	ScenarioOverAsking: {
		Icon: "⚠️", Title: "Over-asking shop", Verifier: "Late Night Liquor", Trusted: true, RegisteredAs: ScenarioAge,
		Asks:  "whether you're over 18 — and your name, which it isn't registered to ask for",
		Shows: "Verifier registration: the shop is registered to ask only whether you're over 18, so your wallet warns that it asks for more. Trust alone isn't entitlement.",
	},
}

// Info describes s, and reports whether it's a known scenario.
func (s Scenario) Info() (ScenarioInfo, bool) {
	info, ok := scenarioInfo[s]
	info.Scenario = s
	return info, ok
}

// ScenarioInfos describes every scenario, in Scenarios order.
func ScenarioInfos() []ScenarioInfo {
	out := make([]ScenarioInfo, len(Scenarios))
	for i, s := range Scenarios {
		out[i], _ = s.Info()
	}
	return out
}

// Credential query IDs: one per format, offered as alternatives.
const (
	mdocQueryID  = "passport_mdoc"
	sdjwtQueryID = "passport_sdjwt"
)

// buildQuery returns a DCQL query for s that accepts the passport
// credential in either format (a credential set with one option per
// format), requesting only what s needs, from an issuer the trusted
// query names (DCQL trusted_authorities, the "aki" type HAIP 1.0 §5
// requires).
func buildQuery(s Scenario, vct string, trusted dcql.TrustedAuthoritiesQuery) (dcql.Query, error) {
	info, ok := s.Info()
	if !ok {
		return dcql.Query{}, fmt.Errorf("verifierapp: unknown scenario %q", s)
	}
	var mdocClaims, sdjwtClaims []dcql.ClaimsQuery
	var claimSets [][]string
	switch {
	case info.Evidence:
		mdocClaims = []dcql.ClaimsQuery{claim(credential.FileNamespace, credential.PassportFile)}
		sdjwtClaims = []dcql.ClaimsQuery{claim(credential.PassportFile)}
	case s == ScenarioAge:
		mdocClaims = []dcql.ClaimsQuery{claim(credential.IdentityNamespace, "age_over_18")}
		sdjwtClaims = []dcql.ClaimsQuery{claim(credential.SDJWTAgeEqualOrOver, "18")}
	case s == ScenarioOverAsking:
		mdocClaims = []dcql.ClaimsQuery{
			claim(credential.IdentityNamespace, "age_over_18"),
			claim(credential.IdentityNamespace, credential.GivenName), claim(credential.IdentityNamespace, credential.FamilyName),
		}
		sdjwtClaims = []dcql.ClaimsQuery{claim(credential.SDJWTAgeEqualOrOver, "18"), claim(credential.GivenName), claim(credential.FamilyName)}
	case s == ScenarioSignup:
		for _, el := range []string{credential.FamilyName, credential.GivenName, "age_over_18", credential.Portrait} {
			mdocClaims = append(mdocClaims, claim(credential.IdentityNamespace, el))
		}
		sdjwtClaims = []dcql.ClaimsQuery{
			claim(credential.FamilyName), claim(credential.GivenName),
			claim(credential.SDJWTAgeEqualOrOver, "18"), claim(credential.SDJWTPicture),
		}
		// The photo is asked for, not required: a passport without a
		// usable face image has none, and still answers with the rest
		// (DCQL claim_sets, most preferred first).
		identified(mdocClaims)
		identified(sdjwtClaims)
		claimSets = [][]string{{"c0", "c1", "c2", "c3"}, {"c0", "c1", "c2"}}
	default:
		return dcql.Query{}, fmt.Errorf("verifierapp: no query for scenario %q", s)
	}

	mdocQuery, sdjwtQuery := dcql.MdocQuery(mdocQueryID, credential.DocType), dcql.SDJWTVCQuery(sdjwtQueryID, vct)
	mdocQuery.Claims, sdjwtQuery.Claims = mdocClaims, sdjwtClaims
	for _, cq := range []*dcql.CredentialQuery{&mdocQuery, &sdjwtQuery} {
		cq.Multiple, cq.ClaimSets, cq.TrustedAuthorities = info.Multiple, claimSets, []dcql.TrustedAuthoritiesQuery{trusted}
	}
	q := dcql.Query{
		Credentials:    []dcql.CredentialQuery{mdocQuery, sdjwtQuery},
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{mdocQueryID}, {sdjwtQueryID}}}},
	}
	if err := q.Validate(); err != nil {
		return dcql.Query{}, fmt.Errorf("verifierapp: query: %w", err)
	}
	return q, nil
}

func claim(path ...string) dcql.ClaimsQuery { return dcql.ClaimsQuery{Path: dcql.KeyPath(path...)} }

// identified gives each claim query the id "c<index>", for claim_sets
// to refer to.
func identified(claims []dcql.ClaimsQuery) {
	for i := range claims {
		claims[i].ID = fmt.Sprintf("c%d", i)
	}
}

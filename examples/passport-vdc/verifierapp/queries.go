// Package verifierapp is the passport-vdc demo's Verifier: it requests a
// passport-derived credential over OpenID4VP, in either format, and
// checks it along one of two trust paths.
//
//   - Trust the issuer: request identity attributes and accept them on
//     the strength of the credential's issuer signature, chained to the
//     demo issuer's CA.
//   - Trust ICAO: request the gmrtd portable passport file and
//     re-verify it with gmrtd against the CSCA master list — trusting
//     the issuing country, not the demo issuer, for the data. The file
//     is one claim, so this discloses everything the chip held.
//     The issuer signature is still checked, and the credential's
//     device key still binds it to the presenter.
package verifierapp

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
)

// Mode is which trust path a request exercises.
type Mode string

const (
	// ModeIssuer trusts the credential issuer for identity attributes.
	ModeIssuer Mode = "issuer"
	// ModeICAO trusts only the issuing country, via the passport file.
	ModeICAO Mode = "icao"
)

// Credential query IDs: one per format, offered as alternatives.
const (
	mdocQueryID  = "passport_mdoc"
	sdjwtQueryID = "passport_sdjwt"
)

// buildQuery returns a DCQL query for mode that accepts the passport
// credential in either format (a credential set with one option per
// format), requesting only what mode needs, from an issuer the
// trusted query names (DCQL trusted_authorities, the "aki" type HAIP
// 1.0 §5 requires).
func buildQuery(mode Mode, vct string, trusted dcql.TrustedAuthoritiesQuery) (dcql.Query, error) {
	mdocMeta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: credential.DocType})
	if err != nil {
		return dcql.Query{}, err
	}
	sdjwtMeta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{vct}})
	if err != nil {
		return dcql.Query{}, err
	}

	var mdocClaims, sdjwtClaims []dcql.ClaimsQuery
	var claimSets [][]string
	switch mode {
	case ModeIssuer:
		for _, el := range []string{credential.FamilyName, credential.GivenName, credential.Nationality, "age_over_18", credential.Portrait} {
			mdocClaims = append(mdocClaims, claim(credential.IdentityNamespace, el))
		}
		sdjwtClaims = []dcql.ClaimsQuery{
			claim(credential.FamilyName), claim(credential.GivenName),
			claim(credential.SDJWTNationalities), claim(credential.SDJWTAgeEqualOrOver, "18"),
			claim(credential.SDJWTPicture),
		}
		// The portrait is asked for, not required: a passport without a
		// usable face image has none, and still answers with the rest
		// (DCQL claim_sets, most preferred first).
		identified(mdocClaims)
		identified(sdjwtClaims)
		claimSets = [][]string{{"c0", "c1", "c2", "c3", "c4"}, {"c0", "c1", "c2", "c3"}}
	case ModeICAO:
		mdocClaims = []dcql.ClaimsQuery{claim(credential.FileNamespace, credential.PassportFile)}
		sdjwtClaims = []dcql.ClaimsQuery{claim(credential.PassportFile)}
	default:
		return dcql.Query{}, fmt.Errorf("verifierapp: unknown mode %q", mode)
	}

	trustedAuthorities := []dcql.TrustedAuthoritiesQuery{trusted}
	q := dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{ID: mdocQueryID, Format: mdoc.CredentialFormat, Meta: mdocMeta, Claims: mdocClaims, ClaimSets: claimSets, TrustedAuthorities: trustedAuthorities},
			{ID: sdjwtQueryID, Format: sdjwtvc.CredentialFormat, Meta: sdjwtMeta, Claims: sdjwtClaims, ClaimSets: claimSets, TrustedAuthorities: trustedAuthorities},
		},
		CredentialSets: []dcql.CredentialSetQuery{{Options: [][]string{{mdocQueryID}, {sdjwtQueryID}}}},
	}
	if err := q.Validate(); err != nil {
		return dcql.Query{}, fmt.Errorf("verifierapp: query: %w", err)
	}
	return q, nil
}

func claim(path ...string) dcql.ClaimsQuery {
	p := make(dcql.Path, len(path))
	for i, k := range path {
		p[i] = dcql.PathKey(k)
	}
	return dcql.ClaimsQuery{Path: p}
}

// identified gives each claim query the id "c<index>", for claim_sets
// to refer to.
func identified(claims []dcql.ClaimsQuery) {
	for i := range claims {
		claims[i].ID = fmt.Sprintf("c%d", i)
	}
}

package verifierapp

import (
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
)

// requested is one claim a scenario asked for, and whether the
// credential disclosed it.
type requested struct {
	Label    string
	Received bool
}

// askedFor is what query asked of format's credential, by label, each
// with whether claims (the credential's disclosed claims, flattened)
// has it.
func askedFor(query dcql.Query, format string, claims map[string]any) []requested {
	id := sdjwtQueryID
	if format == "mso_mdoc" {
		id = mdocQueryID
	}
	var out []requested
	for _, cq := range query.Credentials {
		if cq.ID != id {
			continue
		}
		for _, cl := range cq.Claims {
			out = append(out, requestedClaim(format, cl.Path, claims))
		}
	}
	return out
}

// requestedClaim is the claim at path in format's credential: an mdoc's
// path is a namespace and an element, an SD-JWT VC's a claim name and,
// for age_equal_or_over, the age.
func requestedClaim(format string, path dcql.Path, claims map[string]any) requested {
	var keys []string
	for _, p := range path {
		if !p.IsKey() {
			break
		}
		keys = append(keys, p.Key())
	}
	label := demoui.PathLabel(format, keys)
	if format == "mso_mdoc" && len(keys) > 0 {
		keys = keys[1:] // the namespace: flattened away
	}
	if len(keys) == 0 {
		return requested{Label: label}
	}
	v, ok := claims[keys[0]]
	if keys[0] == credential.SDJWTAgeEqualOrOver && len(keys) > 1 {
		ages, _ := v.(map[string]any)
		_, ok = ages[keys[1]]
	}
	return requested{Label: label, Received: ok}
}

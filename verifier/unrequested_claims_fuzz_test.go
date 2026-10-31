package verifier_test

import (
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// sdJWTFuzzPaths are the claim paths of overDisclosureFixture's
// credential that a query asks for, and a presentation discloses, by a
// bit each.
var sdJWTFuzzPaths = []dcql.Path{
	path("given_name"), path("national_id"), path("family_name"),
	path("address"), path("address", "country"), path("address", "street_address"),
	path("nationalities"), path("nationalities", 0), path("nationalities", 1), path("nationalities", nil),
}

// pathsOf is the paths whose bits mask sets.
func pathsOf[T any](all []T, mask uint16) []T {
	out := []T{}
	for i, p := range all {
		if mask&(1<<i) != 0 {
			out = append(out, p)
		}
	}
	return out
}

// FuzzVerifyResponseUnrequestedSDJWTVCClaims verifies presentations of
// one SD-JWT VC disclosing any set of its selectively disclosable
// claims, against queries asking for any set of its claims (S-12). An
// answer that verifies without AllowUnrequestedClaims holds no
// selectively disclosable claim the query didn't ask for, or doesn't
// need to reach one it did: an object a requested claim is in, but
// none of its siblings.
func FuzzVerifyResponseUnrequestedSDJWTVCClaims(f *testing.F) {
	fx := newOverDisclosureFixture(f)
	f.Add(uint16(0b1), uint16(0b1), false)
	f.Add(uint16(0b1), uint16(1<<15), false)
	f.Add(uint16(0b10000), uint16(0b1000), false)
	f.Add(uint16(0b10000), uint16(0b10000|1<<7), false)
	f.Add(uint16(1<<9), uint16(1<<9), false)
	f.Add(uint16(1<<7), uint16(1<<15), false)
	f.Add(uint16(0), uint16(0b1), true)
	f.Fuzz(func(t *testing.T, askedMask, disclosedMask uint16, allow bool) {
		asked := pathsOf(sdJWTFuzzPaths, askedMask)
		var disclosed []dcql.Path // nil: every disclosure
		if disclosedMask&(1<<15) == 0 {
			disclosed = pathsOf(sdJWTFuzzPaths, disclosedMask)
		}
		result, err := fx.verify(t, asked, disclosed, allow)
		if err != nil || allow {
			return
		}
		claims := result.Credentials[0].Claims
		address, _ := claims["address"].(map[string]any)
		nationalities, _ := claims["nationalities"].([]any)
		for _, c := range []struct {
			shown bool
			path  dcql.Path
		}{
			{claims["given_name"] != nil, path("given_name")},
			{claims["national_id"] != nil, path("national_id")},
			{claims["address"] != nil, path("address")},
			{address["country"] != nil, path("address", "country")},
			{address["street_address"] != nil, path("address", "street_address")},
			{len(nationalities) > 0, path("nationalities", 0)},
		} {
			if c.shown && !askedFor(asked, c.path) {
				t.Fatalf("asked %v, disclosed %v: the answer verified with %v, unrequested (claims %v)", asked, disclosed, c.path, claims)
			}
		}
	})
}

// askedFor reports whether a query asking for asked requests p, or
// needs it to reach a claim it requests: some asked path leads to p, or
// through it. An array index in an asked path stands for every element,
// as checkRequestedDisclosures widens it.
func askedFor(asked []dcql.Path, p dcql.Path) bool {
	for _, a := range asked {
		n := min(len(a), len(p))
		match := true
		for i := range n {
			if a[i].IsKey() != p[i].IsKey() || (a[i].IsKey() && a[i].Key() != p[i].Key()) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// mdocFuzzElements are the elements of the mdoc
// FuzzVerifyResponseUnrequestedMdocElements presents, by a bit each.
var mdocFuzzElements = [][2]string{
	{"org.iso.18013.5.1", "given_name"}, {"org.iso.18013.5.1", "family_name"},
	{"org.iso.18013.5.1", "age_over_18"}, {"org.iso.18013.5.1", "birth_date"},
	{"org.example.1", "member_id"}, {"org.example.1", "given_name"},
}

// FuzzVerifyResponseUnrequestedMdocElements verifies presentations of
// one mdoc disclosing any set of its elements, against queries asking
// for any set of them (S-12). An answer that verifies without
// AllowUnrequestedClaims holds only elements the query asked for.
func FuzzVerifyResponseUnrequestedMdocElements(f *testing.F) {
	mf := newMdocVerifyFixture(f)
	full := testmdoc.IssueWith(f, func(c *mdoc.Claims) {
		c.NameSpaces["org.iso.18013.5.1"]["age_over_18"] = true
		c.NameSpaces["org.iso.18013.5.1"]["birth_date"] = "1990-01-01"
		c.NameSpaces["org.example.1"] = map[string]any{"member_id": uint64(7), "given_name": "Al"}
	})
	baseQuery := testmdoc.Query(f)
	f.Add(uint8(0b1), uint8(0b1), false)
	f.Add(uint8(0b1), uint8(0b11), false)
	f.Add(uint8(0b110000), uint8(0b100001), false)
	f.Add(uint8(0b111111), uint8(0b111111), false)
	f.Add(uint8(0b1), uint8(0b111111), true)
	f.Fuzz(func(t *testing.T, askedMask, disclosedMask uint8, allow bool) {
		asked := pathsOf(mdocFuzzElements, uint16(askedMask))
		query := baseQuery
		query.Credentials = slices.Clone(baseQuery.Credentials)
		query.Credentials[0].Claims = nil
		for _, e := range asked {
			query.Credentials[0].Claims = append(query.Credentials[0].Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(e[0]), dcql.PathKey(e[1])}})
		}
		m := mf
		m.query = query
		m.f = full
		m.f.IssuerSigned = full.IssuerSigned.SelectNameSpaces(pathsOf(mdocFuzzElements, uint16(disclosedMask)))
		result, err := m.verifyWith(t, m.nonce, func(r *verifier.VerifyResponseRequest) { r.AllowUnrequestedClaims = allow })
		if err != nil || allow {
			return
		}
		for ns, elements := range result.Credentials[0].Claims {
			values, _ := elements.(map[string]any)
			for name := range values {
				if !slices.Contains(asked, [2]string{ns, name}) {
					t.Fatalf("asked %v: the answer verified with %s/%s, unrequested", asked, ns, name)
				}
			}
		}
	})
}

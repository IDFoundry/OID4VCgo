package dcql

import "encoding/json"

// SDJWTVCQuery is a Credential Query, named id, for a "dc+sd-jwt"
// credential of type vct, asking for each claim in claims:
//
//	q := dcql.SDJWTVCQuery("pid", "urn:eudi:pid:1", dcql.KeyPath("given_name"), dcql.KeyPath("address", "country"))
//
// It doesn't fail: an empty id or vct, or an empty path, makes a query
// Query.Validate refuses. For several allowed types, set Meta from
// NewSDJWTVCMeta instead; for claim values or claim_sets, extend the
// result.
func SDJWTVCQuery(id, vct string, claims ...Path) CredentialQuery {
	return newCredentialQuery(id, formatSDJWTVC, SDJWTVCMeta{VCTValues: []string{vct}}, claims)
}

// MdocQuery is a Credential Query, named id, for an "mso_mdoc"
// credential of docType, asking for each data element in claims — each
// a namespace then an element identifier:
//
//	q := dcql.MdocQuery("mdl", "org.iso.18013.5.1.mDL", dcql.KeyPath("org.iso.18013.5.1", "family_name"))
//
// It doesn't fail: an empty id or docType, or an empty path, makes a
// query Query.Validate refuses; a path that isn't a namespace then an
// element identifier matches no mdoc.
func MdocQuery(id, docType string, claims ...Path) CredentialQuery {
	return newCredentialQuery(id, formatMdoc, MdocMeta{DoctypeValue: docType}, claims)
}

// KeyPath is a claims path of object keys only — the common case:
// KeyPath("address", "country") selects the country of the address
// claim.
func KeyPath(keys ...string) Path {
	p := make(Path, len(keys))
	for i, k := range keys {
		p[i] = PathKey(k)
	}
	return p
}

func newCredentialQuery(id, format string, meta any, claims []Path) CredentialQuery {
	// Marshalling a struct of strings can't fail.
	raw, _ := json.Marshal(meta)
	q := CredentialQuery{ID: id, Format: format, Meta: raw}
	for _, p := range claims {
		q.Claims = append(q.Claims, ClaimsQuery{Path: p})
	}
	return q
}

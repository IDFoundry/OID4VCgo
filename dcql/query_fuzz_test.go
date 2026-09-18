package dcql

import (
	"encoding/json"
	"testing"
)

// FuzzQuery exercises json.Unmarshal/Query.Validate against arbitrary
// bytes — a DCQL query (an Authorization Request's own "dcql_query"
// parameter) is Verifier-supplied and, from a Wallet's perspective,
// genuinely untrusted: a malicious or compromised Verifier could send
// anything. Only checks for panics/hangs.
func FuzzQuery(f *testing.F) {
	mdocMeta, err := NewMdocMeta(MdocMeta{DoctypeValue: "org.iso.18013.5.1.mDL"})
	if err != nil {
		f.Fatalf("NewMdocMeta: %v", err)
	}
	sdjwtMeta, err := NewSDJWTVCMeta(SDJWTVCMeta{VCTValues: []string{"https://credentials.example.com/identity_credential"}})
	if err != nil {
		f.Fatalf("NewSDJWTVCMeta: %v", err)
	}

	mdocQuery, err := json.Marshal(Query{Credentials: []CredentialQuery{{
		ID: "mdl", Format: "mso_mdoc", Meta: mdocMeta,
		Claims: []ClaimsQuery{{Path: Path{PathKey("org.iso.18013.5.1"), PathKey("given_name")}}},
	}}})
	if err != nil {
		f.Fatalf("marshal mdoc query: %v", err)
	}
	sdjwtQuery, err := json.Marshal(Query{Credentials: []CredentialQuery{{
		ID: "pid", Format: "dc+sd-jwt", Meta: sdjwtMeta,
		Claims: []ClaimsQuery{{Path: Path{PathKey("given_name")}}},
	}}})
	if err != nil {
		f.Fatalf("marshal sdjwt query: %v", err)
	}
	withSets, err := json.Marshal(Query{
		Credentials: []CredentialQuery{
			{ID: "a", Format: "dc+sd-jwt", Meta: sdjwtMeta},
			{ID: "b", Format: "mso_mdoc", Meta: mdocMeta},
		},
		CredentialSets: []CredentialSetQuery{{Options: [][]string{{"a"}, {"b"}}}},
	})
	if err != nil {
		f.Fatalf("marshal query with sets: %v", err)
	}

	f.Add(mdocQuery)
	f.Add(sdjwtQuery)
	f.Add(withSets)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"credentials":[]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"credentials":[{"id":"a","format":"x","meta":{}}],"credential_sets":[{"options":[["missing"]]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var q Query
		if err := json.Unmarshal(data, &q); err != nil {
			return
		}
		_ = q.Validate()
	})
}

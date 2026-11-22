package dcql_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// Validate refuses what OpenID4VP 6.1, 6.3 and 7.2 rule out: empty
// claims, claim_sets or values arrays, values that aren't strings,
// integers or booleans, an mso_mdoc path that isn't [namespace,
// element], and intent_to_retain outside mso_mdoc.
func TestValidateStrictShapes(t *testing.T) {
	const sdjwt = `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"]},`
	const mdoc = `{"id":"q","format":"mso_mdoc","meta":{"doctype_value":"org.iso.18013.5.1.mDL"},`
	for name, tc := range map[string]struct {
		query   string
		refused string
	}{
		"valid sd-jwt":            {query: sdjwt + `"claims":[{"path":["a",null,0],"values":["x",3,true]}]}`},
		"valid mdoc":              {query: mdoc + `"claims":[{"path":["org.iso.18013.5.1","age_over_18"],"values":[true],"intent_to_retain":true}]}`},
		"empty claims":            {query: sdjwt + `"claims":[]}`, refused: "claims must be non-empty"},
		"empty claim_sets":        {query: sdjwt + `"claims":[{"id":"a","path":["a"]}],"claim_sets":[]}`, refused: "claim_sets must be non-empty"},
		"empty values":            {query: sdjwt + `"claims":[{"path":["a"],"values":[]}]}`, refused: "values must be non-empty"},
		"float value":             {query: sdjwt + `"claims":[{"path":["a"],"values":[1.5]}]}`, refused: "values[0]"},
		"object value":            {query: sdjwt + `"claims":[{"path":["a"],"values":[{}]}]}`, refused: "values[0]"},
		"null value":              {query: sdjwt + `"claims":[{"path":["a"],"values":["x",null]}]}`, refused: "values[1]"},
		"mdoc path of one":        {query: mdoc + `"claims":[{"path":["org.iso.18013.5.1"]}]}`, refused: "two strings"},
		"mdoc path with index":    {query: mdoc + `"claims":[{"path":["org.iso.18013.5.1",0]}]}`, refused: "two strings"},
		"intent_to_retain sd-jwt": {query: sdjwt + `"claims":[{"path":["a"],"intent_to_retain":true}]}`, refused: "intent_to_retain"},
		// A values integer must be one a float64 holds exactly: 2^53 + 1
		// decodes as 2^53, as 2^53 itself does.
		"value of ±(2^53 − 1)":  {query: sdjwt + `"claims":[{"path":["a"],"values":[9007199254740991,-9007199254740991]}]}`},
		"value beyond 2^53 − 1": {query: sdjwt + `"claims":[{"path":["a"],"values":[1,9007199254740993]}]}`, refused: "values[1] is an integer beyond"},
		// meta is read as the format's type, and another parser reads
		// vct_values or doctype_value exactly: neither may hide behind a
		// member that differs only in case, or appear twice.
		"case-variant vct_values": {query: `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"],"VCT_VALUES":["urn:y"]}}`, refused: "VCT_VALUES"},
		"vct_values twice":        {query: `{"id":"q","format":"dc+sd-jwt","meta":{"vct_values":["urn:x"],"vct_values":["urn:y"]}}`, refused: "twice"},
		"case-variant doctype":    {query: `{"id":"q","format":"mso_mdoc","meta":{"Doctype_Value":"org.iso.18013.5.1.mDL"}}`, refused: "Doctype_Value"},
	} {
		var q dcql.Query
		if err := json.Unmarshal([]byte(`{"credentials":[`+tc.query+`]}`), &q); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err := q.Validate()
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want refused (%s)", name, err, tc.refused)
		}
	}
}

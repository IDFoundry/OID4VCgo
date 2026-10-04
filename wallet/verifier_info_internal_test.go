package wallet

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// TestParseVerifierInfo_Refuses checks the structure OpenID4VP 1.0 §5.1
// defines for verifier_info.
func TestParseVerifierInfo_Refuses(t *testing.T) {
	q := dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "cred1"}}}
	for name, raw := range map[string]string{
		"not an array":          `{"format":"jwt","data":"x"}`,
		"empty":                 `[]`,
		"no format":             `[{"data":"x"}]`,
		"no data":               `[{"format":"jwt"}]`,
		"empty data":            `[{"format":"jwt","data":""}]`,
		"number data":           `[{"format":"jwt","data":7}]`,
		"empty credential_ids":  `[{"format":"jwt","data":"x","credential_ids":[]}]`,
		"unknown credential id": `[{"format":"jwt","data":"x","credential_ids":["other"]}]`,
		"too many entries":      "[" + strings.Repeat(`{"format":"jwt","data":"x"},`, MaxVerifierInfo) + `{"format":"jwt","data":"x"}]`,
	} {
		if _, err := parseVerifierInfo(json.RawMessage(raw), q); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	got, err := parseVerifierInfo(json.RawMessage(`[{"format":"x-object","data":{"a":1}}]`), q)
	if err != nil || len(got) != 1 || got[0].Format != "x-object" || !got[0].AppliesTo("cred1") {
		t.Errorf("an object data entry: %+v, %v", got, err)
	}
	if _, ok := got[0].DataString(); ok {
		t.Error("object data read as a string")
	}
	if got, err := parseVerifierInfo(nil, q); got != nil || err != nil {
		t.Errorf("absent: %+v, %v", got, err)
	}
}

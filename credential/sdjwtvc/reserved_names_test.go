package sdjwtvc

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A reserved name inside a claim value with an encoding of its own — a
// json.RawMessage or struct holding user input, say — is refused like
// one in a map[string]any: otherwise the Issuer signs an _sd array (or
// {"...": digest} element) whose digest the Holder chose, and the
// Holder later presents a Disclosure for it that Verify resolves as an
// Issuer-attested claim.
func TestIssue_RefusesReservedNamesInOpaqueValues(t *testing.T) {
	forged, err := NewObjectDisclosure("age_over_18", true)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := forged.Digest(SHA256)
	if err != nil {
		t.Fatal(err)
	}
	type profile struct {
		Extra map[string]any `json:"extra"`
	}
	type list struct {
		Items []any `json:"items"`
	}
	for name, value := range map[string]any{
		"_sd in a RawMessage":        json.RawMessage(`{"nickname":"mallory","_sd":["` + digest + `"]}`),
		"_sd in a struct":            profile{Extra: map[string]any{"_sd": []any{digest}}},
		"_sd in a pointer to struct": &profile{Extra: map[string]any{"_sd": []any{digest}}},
		"... in a RawMessage array":  json.RawMessage(`["a",{"...":"` + digest + `"}]`),
		"... in a struct":            list{Items: []any{map[string]any{"...": digest}}},
		"_sd_alg in a RawMessage":    json.RawMessage(`{"_sd_alg":"sha-256"}`),
		"_sd in a disclosed value":   SD(json.RawMessage(`{"_sd":["` + digest + `"]}`)),
	} {
		_, _, err := Issue(testKey(t), jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{"c": value}}, IssueOptions{})
		if err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("%s: Issue = %v, want it refused", name, err)
		}
	}
}

// Status and CNF are signed as given, so a reserved name in either is
// refused too, rather than issued in a credential Verify refuses.
func TestIssue_RefusesReservedNamesInStatusAndCNF(t *testing.T) {
	for name, claims := range map[string]Claims{
		"status": {VCT: "urn:x", Status: map[string]any{"status_list": map[string]any{"_sd": []any{"x"}}}},
		"cnf":    {VCT: "urn:x", CNF: map[string]any{"jwk": json.RawMessage(`{"...":"x"}`)}},
		// Inside an array, at any depth.
		"status, in an array": {VCT: "urn:x", Status: map[string]any{"lists": []any{"a", map[string]any{"_sd_alg": "sha-256"}}}},
		"cnf, nested arrays":  {VCT: "urn:x", CNF: map[string]any{"keys": []any{[]any{map[string]any{"...": "x"}}}}},
	} {
		if _, _, err := Issue(testKey(t), jose.ES256, claims, IssueOptions{}); err == nil || !strings.Contains(err.Error(), "is reserved") {
			t.Errorf("%s: Issue = %v, want it refused", name, err)
		}
	}
}

// A RawMessage or struct claim with no reserved name is signed as the
// same JSON as before, numbers intact (an object's key order aside),
// and a disclosed one verifies as its value.
func TestIssue_OpaqueValuesIssueAsBefore(t *testing.T) {
	type address struct {
		Street string      `json:"street"`
		Number json.Number `json:"number"`
	}
	raw := json.RawMessage(`{"big":9007199254740991,"f":1.5,"list":[1,"a",null]}`)
	key := testKey(t)
	sdjwt, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{
		"raw": raw, "addr": address{Street: "Main", Number: "10"}, "hidden": SD(raw),
	}}, IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	_, signed, err := jose.DecodeUnverified(sdjwt[:strings.Index(sdjwt, "~")])
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(signed, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["raw"]) != string(raw) {
		t.Errorf("raw = %s, want %s", got["raw"], raw)
	}
	var addr address
	if err := json.Unmarshal(got["addr"], &addr); err != nil || addr != (address{Street: "Main", Number: "10"}) {
		t.Errorf("addr = %s, want {street: Main, number: 10}", got["addr"])
	}

	payload, _, err := Verify(sdjwt, &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var want any
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(payload["hidden"], want) {
		t.Errorf("hidden = %v, want %v", payload["hidden"], want)
	}
}

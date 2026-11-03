package sdjwtvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A disclosure's form is its arity, not its name: a property named ""
// (a valid JSON name) is a property, never an array element (RFC 9901
// §4.2.1, §4.2.2), and it round-trips through Issue and Verify.
func TestDisclosure_EmptyNameIsAProperty(t *testing.T) {
	salt := b64.EncodeToString([]byte("salt-salt-salt-1"))
	raw, _ := json.Marshal([]any{salt, "", "v"})
	d, err := ParseDisclosure(b64.EncodeToString(raw))
	if err != nil || d.IsArrayElement() {
		t.Fatalf("ParseDisclosure([salt, \"\", v]) = array element %v, %v; want a property", d.IsArrayElement(), err)
	}
	raw, _ = json.Marshal([]any{salt, "v"})
	if d, err := ParseDisclosure(b64.EncodeToString(raw)); err != nil || !d.IsArrayElement() {
		t.Fatalf("ParseDisclosure([salt, v]) = array element %v, %v; want one", d.IsArrayElement(), err)
	}

	key := testKey(t)
	sdjwt, _, err := Issue(key, jose.ES256, Claims{VCT: "vc-type", Additional: map[string]any{"": SD("v")}}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := Verify(sdjwt, &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
	if err != nil || payload[""] != "v" {
		t.Errorf("Verify = %v, %v; want the property named \"\" disclosed", payload[""], err)
	}
}

// A non-string _sd_alg is refused, not replaced by the default (RFC
// 9901 §4.1.1).
func TestVerify_RefusesNonStringSDAlg(t *testing.T) {
	key := testKey(t)
	for _, alg := range []any{5, "", []any{"sha-256"}} {
		payload, _ := json.Marshal(map[string]any{"vct": "vc-type", "_sd_alg": alg})
		jwt, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dc+sd-jwt"}, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := Verify(jwt+"~", &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil || !strings.Contains(err.Error(), "_sd_alg") {
			t.Errorf("_sd_alg %v: %v, want refused", alg, err)
		}
	}
}

// _sd_alg belongs at the payload's top level alone: "It MUST NOT be
// used in any object nested within the payload" (RFC 9901 §4.1.1).
func TestVerify_RefusesNestedSDAlg(t *testing.T) {
	key := testKey(t)
	payload, _ := json.Marshal(map[string]any{"vct": "vc-type", "address": map[string]any{"_sd_alg": "sha-256", "street": "x"}})
	jwt, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dc+sd-jwt"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(jwt+"~", &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil || !strings.Contains(err.Error(), "_sd_alg") {
		t.Errorf("a nested _sd_alg: %v, want refused", err)
	}
}

// Issue refuses a credential its own Verify couldn't accept: here an
// issuer JWT over jose.MaxCompactBytes.
func TestIssue_RefusesAnIssuerJWTVerifyWouldRefuse(t *testing.T) {
	key := testKey(t)
	claims := Claims{VCT: "vc-type", Additional: map[string]any{"note": strings.Repeat("x", 8<<10), "sd": SD("1")}}
	if _, _, err := Issue(key, jose.ES256, claims, IssueOptions{Decoys: MaxDecoys}); err == nil {
		t.Error("issued an issuer JWT over jose.MaxCompactBytes")
	}
}

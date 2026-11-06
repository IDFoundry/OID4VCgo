package sdjwtvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Verify accepts the dc+sd-jwt typ (draft-19 §2.2.1) and, only when
// AcceptLegacyTyp is set, the transitional vc+sd-jwt (draft-13 §3.2.1);
// none, or another, is refused. typ is a media type (RFC 7515 §4.1.9), so its
// application/ form and any case name it too.
func TestVerify_Typ(t *testing.T) {
	key := testKey(t)
	raw, err := json.Marshal(map[string]any{"vct": "urn:example:1"})
	if err != nil {
		t.Fatal(err)
	}
	for typ, accepted := range map[string][2]bool{ // by default, with AcceptLegacyTyp
		"dc+sd-jwt": {true, true}, "application/dc+sd-jwt": {true, true}, "DC+SD-JWT": {true, true},
		"vc+sd-jwt": {false, true}, "application/vc+sd-jwt": {false, true},
		"JWT": {false, false}, "": {false, false},
	} {
		header := map[string]any{"alg": "ES256"}
		if typ != "" {
			header["typ"] = typ
		}
		jwt, err := jose.Sign(jose.ES256, key, header, raw)
		if err != nil {
			t.Fatal(err)
		}
		for i, legacy := range []bool{false, true} {
			_, _, err = Verify(jwt+"~", &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired, AcceptLegacyTyp: legacy})
			if accepted[i] && err != nil {
				t.Errorf("typ %q, AcceptLegacyTyp %v: Verify = %v, want accepted", typ, legacy, err)
			}
			if !accepted[i] && (err == nil || !strings.Contains(err.Error(), "typ")) {
				t.Errorf("typ %q, AcceptLegacyTyp %v: Verify = %v, want a typ refusal", typ, legacy, err)
			}
		}
	}
}

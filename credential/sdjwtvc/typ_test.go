package sdjwtvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// Verify accepts only the dc+sd-jwt typ (SD-JWT VC draft-19 §2.2.1):
// draft-13's transitional vc+sd-jwt is refused, as is none. typ is a
// media type (RFC 7515 §4.1.9), so its application/ form and any case
// name it too.
func TestVerify_TypMustBeDCSDJWT(t *testing.T) {
	key := testKey(t)
	raw, err := json.Marshal(map[string]any{"vct": "urn:example:1"})
	if err != nil {
		t.Fatal(err)
	}
	for typ, accepted := range map[string]bool{
		"dc+sd-jwt": true, "application/dc+sd-jwt": true, "DC+SD-JWT": true,
		"vc+sd-jwt": false, "JWT": false, "": false,
	} {
		header := map[string]any{"alg": "ES256"}
		if typ != "" {
			header["typ"] = typ
		}
		jwt, err := jose.Sign(jose.ES256, key, header, raw)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Verify(jwt+"~", &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
		if accepted && err != nil {
			t.Errorf("typ %q: Verify = %v, want accepted", typ, err)
		}
		if !accepted && (err == nil || !strings.Contains(err.Error(), "typ")) {
			t.Errorf("typ %q: Verify = %v, want a typ refusal", typ, err)
		}
	}
}

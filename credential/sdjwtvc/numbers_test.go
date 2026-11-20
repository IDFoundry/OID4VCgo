package sdjwtvc

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A number beyond ±(2^53 − 1) decodes to a float64 another number
// shares, so two values an issuer signed apart would verify as one:
// Issue refuses to sign one, in the payload or a disclosure, and Verify
// and ParseDisclosure refuse one signed anyway. Numbers within it issue
// and verify as they were.
func TestNumbersBeyondSafeIntegers(t *testing.T) {
	key := testKey(t)
	beyond := []string{"9007199254740992", "9007199254740993", "-9007199254740993", "1e16", "9007199254740992.5", "1e400"}
	for _, n := range beyond {
		raw := json.RawMessage(`{"n":` + n + `}`)
		for where, value := range map[string]any{"payload": raw, "disclosure": SD(raw)} {
			_, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{"c": value}}, IssueOptions{})
			if err == nil || !strings.Contains(err.Error(), "2^53") {
				t.Errorf("Issue of %s in the %s = %v, want it refused", n, where, err)
			}
		}

		payload := []byte(`{"iss":"https://issuer.example","vct":"urn:x","n":` + n + `}`)
		jwt, err := jose.Sign(jose.ES256, key, issuerJWTHeader(IssueOptions{}), payload)
		if err != nil {
			t.Fatal(err)
		}
		// 1e400 overflows a float64 outright, so decoding the payload
		// refuses it first.
		if _, _, err := Verify(jwt+"~", &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}); err == nil {
			t.Errorf("Verify of a payload holding %s = nil error, want it refused", n)
		}
		if _, err := ParseDisclosure(b64.EncodeToString([]byte(`["salt","n",` + n + `]`))); err == nil || !strings.Contains(err.Error(), "2^53") {
			t.Errorf("ParseDisclosure of %s = %v, want it refused", n, err)
		}
	}

	for _, n := range []string{"9007199254740991", "-9007199254740991", "1.5", "0", "1e3"} {
		var want any
		if err := json.Unmarshal([]byte(n), &want); err != nil {
			t.Fatal(err)
		}
		for where, value := range map[string]any{"payload": json.RawMessage(n), "disclosure": SD(json.RawMessage(n))} {
			sdjwt, _, err := Issue(key, jose.ES256, Claims{VCT: "urn:x", Additional: map[string]any{"n": value}}, IssueOptions{})
			if err != nil {
				t.Fatalf("Issue of %s in the %s: %v", n, where, err)
			}
			got, _, err := Verify(sdjwt, &key.PublicKey, jose.ES256, VerifyOptions{RequireKeyBinding: KeyBindingNotRequired})
			if err != nil || got["n"] != want {
				t.Errorf("Verify of %s in the %s = %v, %v; want %v", n, where, got["n"], err, want)
			}
		}
	}
}

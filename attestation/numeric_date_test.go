package attestation

import (
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// A Key Attestation's iat and exp are NumericDates, which may be
// fractional (RFC 7519 §2), within jwtdate's range.
func TestParse_NumericDates(t *testing.T) {
	key := testKey(t)
	attested := `[{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}]`
	for name, tc := range map[string]struct {
		times string
		want  string // "" for accepted
	}{
		"integers":       {`"iat":1800000000,"exp":1800000600`, ""},
		"fractional":     {`"iat":1800000000.25,"exp":1800000600.75`, ""},
		"negative iat":   {`"iat":-5`, "iat"},
		"exp past 9999":  {`"iat":1800000000,"exp":1e19`, "exp"},
		"iat not a date": {`"iat":"soon"`, "unmarshal"},
	} {
		payload := fmt.Sprintf(`{%s,"attested_keys":%s}`, tc.times, attested)
		compact, err := jose.Sign(jose.ES256, key, map[string]any{"typ": TypHeader}, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse(compact)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want an error naming %q", name, err, tc.want)
		}
	}
}

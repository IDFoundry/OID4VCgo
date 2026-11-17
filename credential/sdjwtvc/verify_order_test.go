package sdjwtvc

import (
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

var notRequired = VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}

// RFC 9901 §7.1's order: the Issuer-signed JWT is verified before any
// Disclosure is decoded, so a presentation whose JWT doesn't verify is
// refused for it, whatever its Disclosures — here undecodable ones,
// which decoding first would have reported.
func TestVerifyPresentation_IssuerJWTBeforeDisclosures(t *testing.T) {
	issuerKey, otherKey := testKey(t), testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type", Additional: map[string]any{"a": SD("x")}}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var junk strings.Builder
	junk.WriteString(sdjwt)
	for i := range 1000 {
		fmt.Fprintf(&junk, "!not-base64url-%d!~", i)
	}
	if _, err := VerifyPresentation(junk.String(), &otherKey.PublicKey, jose.ES256, notRequired); err == nil || !strings.Contains(err.Error(), "verify issuer JWT") {
		t.Errorf("another key: %v, want the issuer JWT refused first", err)
	}
	// Under the right key, a Disclosure no digest references is refused
	// without being decoded.
	if _, err := VerifyPresentation(junk.String(), &issuerKey.PublicKey, jose.ES256, notRequired); err == nil || !strings.Contains(err.Error(), "not referenced") {
		t.Errorf("unreferenced junk: %v, want it refused as unreferenced", err)
	}
	v, err := VerifyPresentation(sdjwt, &issuerKey.PublicKey, jose.ES256, notRequired)
	if err != nil {
		t.Fatalf("the genuine presentation: %v", err)
	}
	if v.Payload["a"] != "x" || len(v.Presentation.Disclosures) != 1 || v.Presentation.IssuerJWT != sdjwt[:strings.IndexByte(sdjwt, '~')] {
		t.Errorf("VerifyPresentation = %v, %+v; want the disclosed claim and the parsed presentation", v.Payload, v.Presentation)
	}
}

// Disclosures referenced only from inside another Disclosure (RFC 9901
// §4.2.6) are decoded too, in any presented order, and keep that order.
func TestVerifyPresentation_NestedDisclosuresInAnyOrder(t *testing.T) {
	issuerKey := testKey(t)
	claims := Claims{VCT: "vc-type", Additional: map[string]any{
		"address": SD(map[string]any{"street": SD("Main St"), "city": SD("Berlin")}),
		"list":    []any{SDElement("one"), SDElement(map[string]any{"inner": SD("deep")})},
	}}
	sdjwt, disclosures, err := Issue(issuerKey, jose.ES256, claims, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issuerJWT := sdjwt[:strings.IndexByte(sdjwt, '~')]
	for _, reversed := range []bool{false, true} {
		pres := Presentation{IssuerJWT: issuerJWT, Disclosures: append([]Disclosure(nil), disclosures...)}
		if reversed {
			for i, j := 0, len(pres.Disclosures)-1; i < j; i, j = i+1, j-1 {
				pres.Disclosures[i], pres.Disclosures[j] = pres.Disclosures[j], pres.Disclosures[i]
			}
		}
		s, err := pres.SDJWT()
		if err != nil {
			t.Fatal(err)
		}
		v, err := VerifyPresentation(s, &issuerKey.PublicKey, jose.ES256, notRequired)
		if err != nil {
			t.Fatalf("reversed %v: %v", reversed, err)
		}
		if got, _ := v.Presentation.SDJWT(); got != s {
			t.Errorf("reversed %v: the parsed presentation doesn't reserialize to the presented one", reversed)
		}
		if addr, _ := v.Payload["address"].(map[string]any); addr["city"] != "Berlin" {
			t.Errorf("reversed %v: payload %v, want the nested claims", reversed, v.Payload)
		}
	}
}

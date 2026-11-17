package sdjwtvc

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

var notRequired = VerifyOptions{RequireKeyBinding: KeyBindingNotRequired}

// allocatedBy is the bytes f allocates.
func allocatedBy(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// paddedWith is sdjwt followed by n distinct parts of three characters
// each.
func paddedWith(sdjwt string, n int) string {
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	var b strings.Builder
	b.WriteString(sdjwt)
	for i := range n {
		b.Write([]byte{b64[i>>12&63], b64[i>>6&63], b64[i&63], '~'})
	}
	return b.String()
}

// A genuine Issuer-signed JWT followed by more parts than its digests,
// and the digests the parts' length leaves room for, could reference
// is refused before any part is split off or hashed.
func TestVerifyPresentation_BoundsPartsByDigests(t *testing.T) {
	issuerKey := testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type", Additional: map[string]any{"a": SD("x")}}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	padded := paddedWith(sdjwt, 150_000)
	var verr error
	allocated := allocatedBy(func() {
		_, verr = VerifyPresentation(padded, &issuerKey.PublicKey, jose.ES256, notRequired)
	})
	if verr == nil || !strings.Contains(verr.Error(), "more than the payload's digests could reference") {
		t.Fatalf("err = %v, want the parts refused by count", verr)
	}
	if allocated > 1<<20 {
		t.Errorf("%d KiB allocated refusing %d bytes of parts, want them neither split nor hashed", allocated>>10, len(padded))
	}
}

// A presentation's Disclosures aren't split apart before its
// Issuer-signed JWT verifies.
func TestVerifyPresentation_SplitsDisclosuresAfterTheSignature(t *testing.T) {
	issuerKey, otherKey := testKey(t), testKey(t)
	sdjwt, _, err := Issue(issuerKey, jose.ES256, Claims{VCT: "vc-type"}, IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	s := sdjwt + strings.Repeat("a~", (MaxBytes-len(sdjwt))/2-1)
	var verr error
	allocated := allocatedBy(func() {
		_, verr = VerifyPresentation(s, &otherKey.PublicKey, jose.ES256, notRequired)
	})
	if verr == nil || !strings.Contains(verr.Error(), "verify issuer JWT") {
		t.Fatalf("err = %v, want the issuer JWT refused", verr)
	}
	if allocated > 1<<20 {
		t.Errorf("%d KiB allocated refusing an unsigned presentation, want its parts left unsplit", allocated>>10)
	}
}

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
		fmt.Fprintf(&junk, "!not-base64url-%057d!~", i)
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

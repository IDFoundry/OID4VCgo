package mdoc

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// twoNamespaceFixture is newFixture's own twin, adding a second
// namespace ("org.iso.18013.5.1.aamva") with its own element —
// SelectNameSpaces needs at least two namespaces to actually exercise
// "drop a whole namespace" behavior.
func twoNamespaceFixture(t *testing.T) fixture {
	t.Helper()
	f := newFixture(t)
	claims := f.claims
	claims.NameSpaces = map[string]map[string]interface{}{
		"org.iso.18013.5.1": {
			"family_name": "Doe",
			"given_name":  "John",
		},
		"org.iso.18013.5.1.aamva": {
			"organ_donor": 1,
		},
	}
	signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	f.claims = claims
	f.signed = signed
	return f
}

func verifyFixture(t *testing.T, f fixture, signed IssuerSigned) VerifiedMSO {
	t.Helper()
	verified, err := Verify(signed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
		Now: func() time.Time { return f.claims.Signed.Add(time.Hour) },
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return verified
}

func TestSelectNameSpaces_TrimsToRequiredElements(t *testing.T) {
	f := twoNamespaceFixture(t)

	trimmed := f.signed.SelectNameSpaces([][2]string{{"org.iso.18013.5.1", "given_name"}})

	if len(trimmed.NameSpaces) != 1 {
		t.Fatalf("got %d namespaces, want 1", len(trimmed.NameSpaces))
	}
	items := trimmed.NameSpaces["org.iso.18013.5.1"]
	if len(items) != 1 || items[0].ElementIdentifier != "given_name" {
		t.Fatalf("org.iso.18013.5.1 items = %v, want exactly [given_name]", items)
	}
	if _, hasAAMVA := trimmed.NameSpaces["org.iso.18013.5.1.aamva"]; hasAAMVA {
		t.Errorf("trimmed result still has org.iso.18013.5.1.aamva, want dropped entirely")
	}

	verified := verifyFixture(t, f, trimmed)
	if got := verified.NameSpaces["org.iso.18013.5.1"]["given_name"]; got != "John" {
		t.Errorf("given_name = %v, want John", got)
	}
	if _, hasFamilyName := verified.NameSpaces["org.iso.18013.5.1"]["family_name"]; hasFamilyName {
		t.Errorf("verified result discloses family_name, which wasn't selected")
	}
}

func TestSelectNameSpaces_SkipsUnknownPath(t *testing.T) {
	f := twoNamespaceFixture(t)

	trimmed := f.signed.SelectNameSpaces([][2]string{
		{"org.iso.18013.5.1", "given_name"},
		{"org.iso.18013.5.1", "no_such_element"},
		{"no_such_namespace", "x"},
	})

	items := trimmed.NameSpaces["org.iso.18013.5.1"]
	if len(items) != 1 || items[0].ElementIdentifier != "given_name" {
		t.Fatalf("org.iso.18013.5.1 items = %v, want exactly [given_name]", items)
	}
	if len(trimmed.NameSpaces) != 1 {
		t.Fatalf("got %d namespaces, want 1", len(trimmed.NameSpaces))
	}
}

func TestSelectNameSpaces_EmptyPathsDropsEverything(t *testing.T) {
	f := twoNamespaceFixture(t)

	trimmed := f.signed.SelectNameSpaces(nil)

	if len(trimmed.NameSpaces) != 0 {
		t.Errorf("NameSpaces = %v, want empty", trimmed.NameSpaces)
	}
}

// TestSelectNameSpaces_WireRoundTrip mirrors
// TestIssuerSignedMarshalUnmarshalRoundTrip, but trims before
// marshaling — the shape wallet.PresentMdocSelective actually produces
// (trim, then marshal into a DeviceResponse).
func TestSelectNameSpaces_WireRoundTrip(t *testing.T) {
	f := twoNamespaceFixture(t)
	trimmed := f.signed.SelectNameSpaces([][2]string{{"org.iso.18013.5.1", "family_name"}})

	wire, err := trimmed.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	decoded, err := UnmarshalIssuerSigned(wire)
	if err != nil {
		t.Fatalf("UnmarshalIssuerSigned: %v", err)
	}

	verified := verifyFixture(t, f, decoded)
	if got := verified.NameSpaces["org.iso.18013.5.1"]["family_name"]; got != "Doe" {
		t.Errorf("family_name = %v, want Doe", got)
	}
	if len(verified.NameSpaces) != 1 || len(verified.NameSpaces["org.iso.18013.5.1"]) != 1 {
		t.Errorf("verified.NameSpaces = %v, want exactly one namespace with one element", verified.NameSpaces)
	}
}

// TestSelectNameSpaces_PreservesDigestSafetyForMapValuedElement mirrors
// TestMapValuedElementValueVerifiesReliably: SelectNameSpaces must
// carry the rawItems cache forward index-aligned with the trimmed
// NameSpaces, never falling back to re-deriving a kept item's bytes
// from its own decoded (possibly map-valued) ElementValue — run
// several iterations, since the bug this guards against (Go's
// randomized map iteration order producing different bytes on
// re-encoding) is probabilistic.
func TestSelectNameSpaces_PreservesDigestSafetyForMapValuedElement(t *testing.T) {
	for i := 0; i < 20; i++ {
		f := newFixture(t)
		claims := testClaims(t, &f.deviceKey.PublicKey)
		claims.NameSpaces["org.iso.18013.5.1"] = map[string]interface{}{
			"given_name": "John",
			"nested": map[string]interface{}{
				"alpha": 1, "bravo": 2, "charlie": 3, "delta": 4,
				"echo": 5, "foxtrot": 6, "golf": 7, "hotel": 8,
			},
		}
		signed, err := Issue(f.issuerKey, cose.ES256, claims, IssueOptions{X5Chain: [][]byte{f.cert}})
		if err != nil {
			t.Fatalf("iteration %d: Issue: %v", i, err)
		}
		wire, err := signed.Marshal()
		if err != nil {
			t.Fatalf("iteration %d: Marshal: %v", i, err)
		}
		decoded, err := UnmarshalIssuerSigned(wire)
		if err != nil {
			t.Fatalf("iteration %d: UnmarshalIssuerSigned: %v", i, err)
		}

		trimmed := decoded.SelectNameSpaces([][2]string{{"org.iso.18013.5.1", "nested"}})
		if _, err := Verify(trimmed, &f.issuerKey.PublicKey, cose.ES256, VerifyOptions{
			Now: func() time.Time { return claims.Signed.Add(time.Hour) },
		}); err != nil {
			t.Fatalf("iteration %d: Verify(trimmed): %v", i, err)
		}
	}
}

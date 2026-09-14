package sdjwtvc

import (
	"reflect"
	"testing"
)

func TestSealResolve_ObjectProperty(t *testing.T) {
	tree := map[string]any{
		"given_name":  "Alice",
		"family_name": SD("Möbius"),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if len(disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclosures))
	}
	if _, hasFamilyName := sealed["family_name"]; hasFamilyName {
		t.Errorf("sealed payload still contains family_name in the clear")
	}
	if _, hasSD := sealed["_sd"]; !hasSD {
		t.Errorf("sealed payload is missing _sd")
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, disclosures)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	if resolved["given_name"] != "Alice" || resolved["family_name"] != "Möbius" {
		t.Errorf("resolved = %+v", resolved)
	}
	if _, hasSD := resolved["_sd"]; hasSD {
		t.Errorf("resolved payload still has _sd")
	}
}

func TestSealResolve_ArrayElement_PartialDisclosure(t *testing.T) {
	// Reproduces RFC 9901 §4.2.4.2's own note: disclosing only the "DE"
	// and "US" elements of ["DE", SDElement("FR"), "US"] must yield the
	// two-element array ["DE", "US"], not three with a gap.
	tree := map[string]any{
		"nationalities": []any{"DE", SDElement("FR"), "US"},
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if len(disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclosures))
	}

	// Resolve with zero disclosures presented: FR must be absent.
	resolved, err := ResolveDisclosures(sealed, SHA256, nil)
	if err != nil {
		t.Fatalf("ResolveDisclosures (no disclosures): %v", err)
	}
	want := []any{"DE", "US"}
	if got, _ := resolved["nationalities"].([]any); !reflect.DeepEqual(got, want) {
		t.Errorf("nationalities = %v, want %v", got, want)
	}

	// Resolve with the FR disclosure presented: all three elements.
	resolved, err = ResolveDisclosures(sealed, SHA256, disclosures)
	if err != nil {
		t.Fatalf("ResolveDisclosures (with disclosure): %v", err)
	}
	want = []any{"DE", "FR", "US"}
	if got, _ := resolved["nationalities"].([]any); !reflect.DeepEqual(got, want) {
		t.Errorf("nationalities = %v, want %v", got, want)
	}
}

func TestSealResolve_RecursiveDisclosure(t *testing.T) {
	// Reproduces RFC 9901 §4.2.6: the whole "nationalities" array is
	// itself selectively disclosable, and its own elements are too.
	tree := map[string]any{
		"family_name": "Möbius",
		"nationalities": SD([]any{
			SDElement("DE"),
			SDElement("FR"),
			SDElement("UK"),
		}),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	// One disclosure for the "nationalities" field itself, plus one per
	// element = 4 total.
	if len(disclosures) != 4 {
		t.Fatalf("got %d disclosures, want 4", len(disclosures))
	}
	if _, has := sealed["nationalities"]; has {
		t.Errorf("sealed payload still exposes nationalities directly")
	}

	// Disclosing everything yields the original tree.
	resolved, err := ResolveDisclosures(sealed, SHA256, disclosures)
	if err != nil {
		t.Fatalf("ResolveDisclosures (all): %v", err)
	}
	want := []any{"DE", "FR", "UK"}
	if got, _ := resolved["nationalities"].([]any); !reflect.DeepEqual(got, want) {
		t.Errorf("nationalities = %v, want %v", got, want)
	}

	// Disclosing only the field-level disclosure (not the per-element
	// ones) yields an array with no visible elements at all.
	var fieldDisclosure Disclosure
	for _, d := range disclosures {
		if !d.IsArrayElement() && d.Name == "nationalities" {
			fieldDisclosure = d
		}
	}
	resolved, err = ResolveDisclosures(sealed, SHA256, []Disclosure{fieldDisclosure})
	if err != nil {
		t.Fatalf("ResolveDisclosures (field only): %v", err)
	}
	if got, _ := resolved["nationalities"].([]any); len(got) != 0 {
		t.Errorf("nationalities = %v, want empty", got)
	}

	// Presenting an element-level disclosure without the field-level
	// one it depends on must be rejected (RFC 9901 §4.2.6: "it would be
	// illegal to include" one without the other) — the field digest
	// never appears in the top-level payload without it, so the
	// element disclosure is simply never referenced and step 5 fires.
	var elementDisclosure Disclosure
	for _, d := range disclosures {
		if d.IsArrayElement() {
			elementDisclosure = d
			break
		}
	}
	if _, err := ResolveDisclosures(sealed, SHA256, []Disclosure{elementDisclosure}); err == nil {
		t.Errorf("ResolveDisclosures accepted an element disclosure without its parent field disclosure")
	}
}

func TestResolveDisclosures_RejectsUnusedDisclosure(t *testing.T) {
	sealed, _, err := sealMap(map[string]any{"a": SD("1")}, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	unrelated, err := NewObjectDisclosure("b", "2")
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	if _, err := ResolveDisclosures(sealed, SHA256, []Disclosure{unrelated}); err == nil {
		t.Errorf("ResolveDisclosures accepted a disclosure with no matching digest")
	}
}

func TestResolveDisclosures_RejectsDuplicateDigest(t *testing.T) {
	sealed, ds, err := sealMap(map[string]any{"a": SD("1")}, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if _, err := ResolveDisclosures(sealed, SHA256, append(ds, ds...)); err == nil {
		t.Errorf("ResolveDisclosures accepted the same disclosure twice")
	}
}

func TestSealMap_RejectsMarkerMisuse(t *testing.T) {
	if _, _, err := sealMap(map[string]any{"a": []any{SD("x")}}, SHA256); err == nil {
		t.Errorf("sealMap accepted SD() used as an array element")
	}
	if _, _, err := sealMap(map[string]any{"a": SDElement("x")}, SHA256); err == nil {
		t.Errorf("sealMap accepted SDElement() used as an object property value")
	}
}

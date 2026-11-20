package sdjwtvc

import (
	"fmt"
	"testing"
)

func TestSelectDisclosuresTopLevel(t *testing.T) {
	tree := map[string]any{
		"given_name":  SD("Alice"),
		"family_name": SD("Möbius"),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}

	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"given_name"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(selected))
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, selected)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	if resolved["given_name"] != "Alice" {
		t.Errorf("given_name = %v, want Alice", resolved["given_name"])
	}
	if _, hasFamilyName := resolved["family_name"]; hasFamilyName {
		t.Errorf("resolved payload discloses family_name, which wasn't selected")
	}
}

// TestSelectDisclosuresNested mirrors RFC 9901 §4.2.6's own "recursive
// Disclosures": address itself is a selectively-disclosable object
// property whose own value has two further selectively-disclosable
// sub-properties. Selecting only address.street_address must disclose
// address's own Disclosure (needed to reach street_address at all) and
// street_address's own Disclosure, but not locality's — a sibling at
// the same nesting level that wasn't asked for.
func TestSelectDisclosuresNested(t *testing.T) {
	tree := map[string]any{
		"address": SD(map[string]any{
			"street_address": SD("123 Main St"),
			"locality":       SD("Anytown"),
		}),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if len(disclosures) != 3 {
		t.Fatalf("got %d disclosures, want 3 (address, street_address, locality)", len(disclosures))
	}

	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"address", "street_address"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 2 {
		t.Fatalf("got %d disclosures, want 2 (address, street_address)", len(selected))
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, selected)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	address, ok := resolved["address"].(map[string]any)
	if !ok {
		t.Fatalf("resolved[address] = %v, want an object", resolved["address"])
	}
	if address["street_address"] != "123 Main St" {
		t.Errorf("address.street_address = %v, want %q", address["street_address"], "123 Main St")
	}
	if _, hasLocality := address["locality"]; hasLocality {
		t.Errorf("resolved payload discloses address.locality, which wasn't selected")
	}
}

// TestSelectDisclosuresObjectValueIncludesNestedDisclosures selects a
// path terminating at an object-valued claim itself (not one of its
// own nested sub-properties) — per SelectDisclosures's own doc
// comment, RFC 9901 §4.2.6's "recursive Disclosures": every Disclosure
// the target value transitively references must come along too, or
// the disclosed object would be missing its own internal selectively-
// disclosed pieces. Found unexercised by any existing test in a
// repo-wide coverage review: every other test here selects a path
// ending at a leaf or an array, never at a nested object itself, so
// includeAllDisclosuresInObject's own recursion had never run.
func TestSelectDisclosuresObjectValueIncludesNestedDisclosures(t *testing.T) {
	tree := map[string]any{
		"address": SD(map[string]any{
			"street_address": SD("123 Main St"),
			"locality":       SD("Anytown"),
		}),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if len(disclosures) != 3 {
		t.Fatalf("got %d disclosures, want 3 (address, street_address, locality)", len(disclosures))
	}

	// Selecting "address" alone (not "address"/"street_address") must
	// still disclose every nested Disclosure "address" itself
	// transitively references.
	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"address"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 3 {
		t.Fatalf("got %d disclosures, want all 3", len(selected))
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, selected)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	address, ok := resolved["address"].(map[string]any)
	if !ok {
		t.Fatalf("resolved[address] = %v, want an object", resolved["address"])
	}
	if address["street_address"] != "123 Main St" {
		t.Errorf("address.street_address = %v, want %q", address["street_address"], "123 Main St")
	}
	if address["locality"] != "Anytown" {
		t.Errorf("address.locality = %v, want %q", address["locality"], "Anytown")
	}
}

// TestSelectDisclosuresArrayValue checks that a path terminating at an
// array-valued claim discloses every one of that array's own
// SDElement-wrapped entries — the "disclose the target value in full"
// half of SelectDisclosures's own doc comment.
func TestSelectDisclosuresArrayValue(t *testing.T) {
	tree := map[string]any{
		"nationalities": SD([]any{SDElement("DE"), SDElement("FR"), SDElement("US")}),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}

	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"nationalities"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != len(disclosures) {
		t.Fatalf("got %d disclosures, want all %d", len(selected), len(disclosures))
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, selected)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	nationalities, ok := resolved["nationalities"].([]any)
	if !ok || len(nationalities) != 3 {
		t.Fatalf("resolved[nationalities] = %v, want a 3-element array", resolved["nationalities"])
	}
}

// sealedGivenNameFixture builds the one-claim {"given_name":
// SD("Alice")} tree both TestSelectDisclosuresMissingPath and
// TestSelectDisclosuresEmptyPaths need, failing the test on error.
func sealedGivenNameFixture(t *testing.T) (map[string]any, []Disclosure) {
	t.Helper()
	sealed, disclosures, err := sealMap(map[string]any{"given_name": SD("Alice")}, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	return sealed, disclosures
}

func TestSelectDisclosuresMissingPath(t *testing.T) {
	sealed, disclosures := sealedGivenNameFixture(t)
	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"no_such_claim"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 0 {
		t.Errorf("got %d disclosures, want 0", len(selected))
	}
}

func TestSelectDisclosuresEmptyPaths(t *testing.T) {
	sealed, disclosures := sealedGivenNameFixture(t)
	selected, err := SelectDisclosures(sealed, SHA256, disclosures, nil)
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 0 {
		t.Errorf("got %d disclosures, want 0", len(selected))
	}
}

// TestSelectDisclosuresMandatoryClaimInPath mirrors a path that walks
// through a mandatory (non-selectively-disclosable) object property
// on its way to a nested selectively-disclosable one.
func TestSelectDisclosuresMandatoryClaimInPath(t *testing.T) {
	tree := map[string]any{
		"address": map[string]any{
			"street_address": SD("123 Main St"),
		},
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	if len(disclosures) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclosures))
	}

	selected, err := SelectDisclosures(sealed, SHA256, disclosures, [][]string{{"address", "street_address"}})
	if err != nil {
		t.Fatalf("SelectDisclosures: %v", err)
	}
	if len(selected) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(selected))
	}

	resolved, err := ResolveDisclosures(sealed, SHA256, selected)
	if err != nil {
		t.Fatalf("ResolveDisclosures: %v", err)
	}
	address, ok := resolved["address"].(map[string]any)
	if !ok || address["street_address"] != "123 Main St" {
		t.Errorf("resolved[address] = %v", resolved["address"])
	}
}

// Paths walk into arrays (OpenID4VP 7.1): an index discloses that
// element, a nil every element, each with only what the rest of the
// path needs; a decoy placeholder isn't counted as an element.
func TestSelectDisclosuresAtArrays(t *testing.T) {
	tree := map[string]any{
		"nationalities": []any{SDElement("DE"), SDElement("FR"), SDElement("IT")},
		"degrees": []any{
			map[string]any{"type": SD("BSc"), "university": SD("A")},
			map[string]any{"type": SD("MSc"), "university": SD("B")},
		},
		"other": SD("hidden"),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	// A decoy, first in nationalities: index 1 is still FR.
	nats := sealed["nationalities"].([]any)
	sealed["nationalities"] = append([]any{map[string]any{"...": "decoy-digest-without-a-disclosure"}}, nats...)

	resolve := func(paths ...[]any) map[string]any {
		t.Helper()
		selected, err := SelectDisclosuresAt(sealed, SHA256, disclosures, paths)
		if err != nil {
			t.Fatalf("SelectDisclosuresAt(%v): %v", paths, err)
		}
		resolved, err := ResolveDisclosures(sealed, SHA256, selected)
		if err != nil {
			t.Fatalf("ResolveDisclosures: %v", err)
		}
		return resolved
	}
	if got := resolve([]any{"nationalities", 1}); fmt.Sprint(got["nationalities"]) != "[FR]" {
		t.Errorf("index 1: nationalities = %v, want [FR]", got["nationalities"])
	}
	if got := resolve([]any{"nationalities", nil}); fmt.Sprint(got["nationalities"]) != "[DE FR IT]" {
		t.Errorf("wildcard: nationalities = %v, want [DE FR IT]", got["nationalities"])
	}
	got := resolve([]any{"degrees", nil, "type"})
	if fmt.Sprint(got["degrees"]) != "[map[type:BSc] map[type:MSc]]" {
		t.Errorf("degrees[*].type: degrees = %v, want only the types", got["degrees"])
	}
	if _, leaked := got["other"]; leaked {
		t.Error("disclosed a claim no path named")
	}
	if got := resolve([]any{"nationalities", 9}); fmt.Sprint(got["nationalities"]) != "[]" {
		t.Errorf("an index past the end: nationalities = %v, want none", got["nationalities"])
	}
	if _, err := SelectDisclosuresAt(sealed, SHA256, disclosures, [][]any{{"other", 0}}); err == nil {
		t.Error("indexed into a value that isn't an array")
	}
}

// TestSelectDisclosuresAtOrderIndependent: a path through an array
// element selects its Disclosure but not its other members, and a path
// to the whole array, before or after it, still discloses all of it:
// the paths' order doesn't change what is selected, with an index or a
// wildcard (OpenID4VP §7.1).
func TestSelectDisclosuresAtOrderIndependent(t *testing.T) {
	tree := map[string]any{
		"c": []any{
			SDElement(map[string]any{"p": SD(2), "q": SD(2)}),
			SDElement(map[string]any{"p": SD(1)}),
		},
		"other": SD("hidden"),
	}
	sealed, disclosures, err := sealMap(tree, SHA256)
	if err != nil {
		t.Fatalf("sealMap: %v", err)
	}
	for _, narrow := range [][]any{{"c", 0, "q"}, {"c", nil, "q"}} {
		for _, paths := range [][][]any{{narrow, {"c"}}, {{"c"}, narrow}} {
			selected, err := SelectDisclosuresAt(sealed, SHA256, disclosures, paths)
			if err != nil {
				t.Fatalf("SelectDisclosuresAt(%v): %v", paths, err)
			}
			resolved, err := ResolveDisclosures(sealed, SHA256, selected)
			if err != nil {
				t.Fatalf("ResolveDisclosures: %v", err)
			}
			if got := fmt.Sprint(resolved["c"]); len(selected) != 5 || got != "[map[p:2 q:2] map[p:1]]" {
				t.Errorf("%v: %d disclosures, c = %s; want all 5 under c, c whole", paths, len(selected), got)
			}
		}
	}
}

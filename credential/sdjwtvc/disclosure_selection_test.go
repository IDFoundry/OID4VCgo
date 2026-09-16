package sdjwtvc

import "testing"

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

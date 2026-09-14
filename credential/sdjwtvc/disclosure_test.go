package sdjwtvc

import "testing"

// Known-answer tests reproducing RFC 9901's own worked examples
// verbatim (§4.2.1, §4.2.2, §4.2.3, §4.2.4.2) — these must match the
// spec's exact bytes, independent of anything this package's own
// encoder does, since they parse/hash strings taken directly from the
// RFC text rather than round-tripping through NewObjectDisclosure.

func TestParseDisclosure_RFC9901_ObjectProperty(t *testing.T) {
	// RFC 9901 §4.2.1: ["_26bc4LT-ac6q2KI6cBW5es", "family_name", "Möbius"]
	const encoded = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"

	d, err := ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	if d.Salt != "_26bc4LT-ac6q2KI6cBW5es" {
		t.Errorf("Salt = %q", d.Salt)
	}
	if d.Name != "family_name" {
		t.Errorf("Name = %q", d.Name)
	}
	if d.Value != "Möbius" {
		t.Errorf("Value = %q", d.Value)
	}
	if d.IsArrayElement() {
		t.Errorf("IsArrayElement() = true, want false")
	}
}

func TestDisclosureDigest_RFC9901_ObjectProperty(t *testing.T) {
	const encoded = "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
	const wantDigest = "X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0"

	d, err := ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	got, err := d.Digest(SHA256)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != wantDigest {
		t.Errorf("Digest = %q, want %q", got, wantDigest)
	}
}

func TestParseDisclosure_RFC9901_ArrayElement(t *testing.T) {
	// RFC 9901 §4.2.2: ["lklxF5jMYlGTPUovMNIvCA", "FR"]
	const encoded = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"

	d, err := ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	if d.Salt != "lklxF5jMYlGTPUovMNIvCA" {
		t.Errorf("Salt = %q", d.Salt)
	}
	if d.Value != "FR" {
		t.Errorf("Value = %q", d.Value)
	}
	if !d.IsArrayElement() {
		t.Errorf("IsArrayElement() = false, want true")
	}
}

func TestDisclosureDigest_RFC9901_ArrayElement(t *testing.T) {
	// RFC 9901 §4.2.4.2: digest of the §4.2.2 array-element Disclosure.
	const encoded = "WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0"
	const wantDigest = "w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs"

	d, err := ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	got, err := d.Digest(SHA256)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if got != wantDigest {
		t.Errorf("Digest = %q, want %q", got, wantDigest)
	}
}

func TestNewObjectDisclosure_RoundTrip(t *testing.T) {
	d, err := NewObjectDisclosure("given_name", "Alice")
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	encoded, err := d.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	parsed, err := ParseDisclosure(encoded)
	if err != nil {
		t.Fatalf("ParseDisclosure: %v", err)
	}
	if parsed.Salt != d.Salt || parsed.Name != d.Name || parsed.Value != d.Value {
		t.Errorf("round trip mismatch: got %+v, want %+v", parsed, d)
	}

	d1, err := NewObjectDisclosure("x", "y")
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	d2, err := NewObjectDisclosure("x", "y")
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	if d1.Salt == d2.Salt {
		t.Errorf("two disclosures for identical input got the same salt")
	}
}

func TestNewObjectDisclosure_RejectsReservedNames(t *testing.T) {
	for _, name := range []string{"_sd", "..."} {
		if _, err := NewObjectDisclosure(name, "v"); err == nil {
			t.Errorf("NewObjectDisclosure(%q, ...) succeeded, want error", name)
		}
	}
}

func TestParseDisclosure_RejectsReservedNames(t *testing.T) {
	// ["salt", "_sd", "v"] base64url-encoded.
	d := mustEncodeJSONArray(t, []any{"c2FsdA", "_sd", "v"})
	if _, err := ParseDisclosure(d); err == nil {
		t.Errorf("ParseDisclosure accepted claim name \"_sd\"")
	}
}

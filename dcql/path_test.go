package dcql_test

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcigo/dcql"
)

// TestPathRoundTripsWorkedExamples exercises §7.3's own worked
// examples: ["name"], ["address", "street_address"],
// ["degrees", null, "type"], ["nationalities", 1].
func TestPathRoundTripsWorkedExamples(t *testing.T) {
	cases := []struct {
		name string
		json string
		want dcql.Path
	}{
		{"name", `["name"]`, dcql.Path{dcql.PathKey("name")}},
		{"nested object member", `["address","street_address"]`, dcql.Path{dcql.PathKey("address"), dcql.PathKey("street_address")}},
		{"wildcard across array", `["degrees",null,"type"]`, dcql.Path{dcql.PathKey("degrees"), dcql.Wildcard, dcql.PathKey("type")}},
		{"array index", `["nationalities",1]`, dcql.Path{dcql.PathKey("nationalities"), dcql.PathIndex(1)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got dcql.Path
			if err := json.Unmarshal([]byte(tc.json), &got); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %d elements, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("element %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}

			encoded, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(encoded) != tc.json {
				t.Errorf("re-encoded = %s, want %s", encoded, tc.json)
			}
		})
	}
}

func TestPathElementUnmarshalRejectsNegativeIndex(t *testing.T) {
	var p dcql.PathElement
	if err := json.Unmarshal([]byte("-1"), &p); err == nil {
		t.Fatalf("Unmarshal(-1) = nil error, want error")
	}
}

func TestPathElementUnmarshalRejectsInvalidType(t *testing.T) {
	var p dcql.PathElement
	if err := json.Unmarshal([]byte("1.5"), &p); err == nil {
		t.Fatalf("Unmarshal(1.5) = nil error, want error")
	}
	if err := json.Unmarshal([]byte("true"), &p); err == nil {
		t.Fatalf("Unmarshal(true) = nil error, want error")
	}
}

func TestPathValidateRejectsEmpty(t *testing.T) {
	if err := (dcql.Path{}).Validate(); err == nil {
		t.Fatalf("Validate() = nil error, want error")
	}
}

func TestPathMdocNamespaceAndElement(t *testing.T) {
	ns, el, ok := dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")}.MdocNamespaceAndElement()
	if !ok || ns != "org.iso.18013.5.1" || el != "given_name" {
		t.Fatalf("MdocNamespaceAndElement() = (%q, %q, %v)", ns, el, ok)
	}

	cases := []dcql.Path{
		{dcql.PathKey("only-one")},
		{dcql.PathKey("a"), dcql.PathKey("b"), dcql.PathKey("c")},
		{dcql.PathKey("a"), dcql.Wildcard},
		{dcql.PathKey("a"), dcql.PathIndex(0)},
	}
	for _, p := range cases {
		if _, _, ok := p.MdocNamespaceAndElement(); ok {
			t.Errorf("MdocNamespaceAndElement(%v) ok = true, want false", p)
		}
	}
}

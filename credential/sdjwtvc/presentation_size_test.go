package sdjwtvc

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

func TestParseRejectsOversizedPresentation(t *testing.T) {
	padding, err := NewObjectDisclosure("padding", strings.Repeat("a", jose.MaxCompactBytes))
	if err != nil {
		t.Fatalf("NewObjectDisclosure: %v", err)
	}
	compact, err := Presentation{IssuerJWT: "issuer-jwt", Disclosures: []Disclosure{padding}}.Compact()
	if err != nil {
		t.Fatalf("Compact: %v", err)
	}
	if len(compact) <= jose.MaxCompactBytes {
		t.Fatalf("compact is %d bytes, want > jose.MaxCompactBytes (%d)", len(compact), jose.MaxCompactBytes)
	}

	if _, err := Parse(compact); err == nil {
		t.Error("Parse = nil error, want error (oversized presentation)")
	}

	// ParseMax with a raised ceiling accepts the same input Parse
	// rejects.
	if _, err := ParseMax(compact, len(compact)); err != nil {
		t.Errorf("ParseMax with a raised ceiling: %v", err)
	}
}

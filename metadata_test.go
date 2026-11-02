package oid4vci_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo"
)

// TestMetadataUnmarshalJSON_NonceEndpoint covers
// parseOptionalEndpointURL's three branches (absent, valid, invalid)
// via Metadata.UnmarshalJSON's own nonce_endpoint field — found
// unexercised by any existing test in a repo-wide coverage review; in
// particular the malformed-URL error path had never run anywhere in
// this repo.
func TestMetadataUnmarshalJSON_NonceEndpoint(t *testing.T) {
	base := `{"credential_issuer":"https://issuer.example.com","credential_endpoint":"https://issuer.example.com/credential","credential_configurations_supported":{}`

	t.Run("absent", func(t *testing.T) {
		var m oid4vci.Metadata
		if err := m.UnmarshalJSON([]byte(base + `}`)); err != nil {
			t.Fatalf("UnmarshalJSON: %v", err)
		}
		if m.NonceEndpoint != nil {
			t.Errorf("NonceEndpoint = %v, want nil", m.NonceEndpoint)
		}
	})

	t.Run("valid", func(t *testing.T) {
		var m oid4vci.Metadata
		raw := base + `,"nonce_endpoint":"https://issuer.example.com/nonce"}`
		if err := m.UnmarshalJSON([]byte(raw)); err != nil {
			t.Fatalf("UnmarshalJSON: %v", err)
		}
		if m.NonceEndpoint == nil || m.NonceEndpoint.String() != "https://issuer.example.com/nonce" {
			t.Errorf("NonceEndpoint = %v, want https://issuer.example.com/nonce", m.NonceEndpoint)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		var m oid4vci.Metadata
		raw := base + `,"nonce_endpoint":""}`
		if err := m.UnmarshalJSON([]byte(raw)); err == nil {
			t.Error("UnmarshalJSON accepted an empty nonce_endpoint")
		}
	})
}

// One display object per language identifier (§12.2.4, Appendix B.2),
// compared case-insensitively, and one description per claim path
// (Appendix B.3).
func TestMetadataRefusesDuplicates(t *testing.T) {
	if err := oid4vci.ValidateDisplays([]oid4vci.Display{{Locale: "en-US"}, {Locale: "de"}}); err != nil {
		t.Errorf("distinct locales: %v", err)
	}
	if err := oid4vci.ValidateDisplays([]oid4vci.Display{{Locale: "en-US"}, {Locale: "en-us"}}); err == nil {
		t.Error("two issuer displays for one language were accepted")
	}
	for name, cm := range map[string]oid4vci.CredentialMetadata{
		"two credential displays for one language": {Display: []oid4vci.CredentialDisplay{{Name: "a"}, {Name: "b"}}},
		"two claim displays for one language": {Claims: []oid4vci.ClaimsDescription{{Path: []any{"name"},
			Display: []oid4vci.ClaimDisplay{{Locale: "de"}, {Locale: "DE"}}}}},
		"one path described twice": {Claims: []oid4vci.ClaimsDescription{{Path: []any{"address", "street"}}, {Path: []any{"address", "street"}}}},
	} {
		if err := cm.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	ok := oid4vci.CredentialMetadata{Claims: []oid4vci.ClaimsDescription{{Path: []any{"address", "street"}}, {Path: []any{"address", nil}}}}
	if err := ok.Validate(); err != nil {
		t.Errorf("distinct paths: %v", err)
	}
}

// A path decoded from JSON holds its indices as float64: an integral,
// non-negative one is an index, any other number isn't.
func TestClaimsDescriptionValidate_DecodedIndex(t *testing.T) {
	if err := (oid4vci.ClaimsDescription{Path: []any{"nationalities", float64(0)}}).Validate(); err != nil {
		t.Errorf("decoded index 0: %v", err)
	}
	for _, v := range []float64{-1, 1.5, 1 << 60} {
		if err := (oid4vci.ClaimsDescription{Path: []any{"nationalities", v}}).Validate(); err == nil {
			t.Errorf("decoded %v: accepted", v)
		}
	}
}

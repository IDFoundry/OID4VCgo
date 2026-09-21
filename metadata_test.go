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

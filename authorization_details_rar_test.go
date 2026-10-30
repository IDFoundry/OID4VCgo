package oid4vci_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/idfoundry/fapigo/extension"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

func credentialRARRegistry(t *testing.T) *extension.RARRegistry {
	t.Helper()
	registry, err := extension.NewRARRegistry(8<<10, 6, oid4vci.AuthorizationDetailRARDefinition(2, 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// A client starting a grant may not choose credential_identifiers
// (OpenID4VCI 1.0 §6.2): they're the Authorization Server's to mint.
// The same object granted by the server is accepted.
func TestAuthorizationDetailRARDefinition_RefusesClientCredentialIdentifiers(t *testing.T) {
	registry := credentialRARRegistry(t)
	withIDs := json.RawMessage(`[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["victim-dataset"]}]`)
	if _, err := registry.ParseRequest(withIDs); !errors.Is(err, oid4vci.ErrClientCredentialIdentifiers) {
		t.Fatalf("ParseRequest = %v, want ErrClientCredentialIdentifiers", err)
	}
	if _, err := registry.Parse(withIDs); err != nil {
		t.Fatalf("Parse of a granted object with identifiers: %v", err)
	}
	if _, err := registry.ParseRequest(json.RawMessage(`[{"type":"openid_credential","credential_configuration_id":"pid"}]`)); err != nil {
		t.Fatalf("ParseRequest without identifiers: %v", err)
	}
	for name, raw := range map[string]string{
		"no configuration":     `[{"type":"openid_credential"}]`,
		"an empty identifier":  `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":[""]}]`,
		"an identifier twice":  `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","a"]}]`,
		"a member not defined": `[{"type":"openid_credential","credential_configuration_id":"pid","dataset":"x"}]`,
	} {
		if _, err := registry.Parse(json.RawMessage(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// A grant may add credential_identifiers to what was requested, and
// otherwise only narrow it; a token request narrowing a grant with
// identifiers may only keep some of them.
func TestAuthorizationDetailRARDefinition_ValidateGrant(t *testing.T) {
	registry := credentialRARRegistry(t)
	parse := func(raw string) extension.RARValues {
		t.Helper()
		v, err := registry.Parse(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("Parse(%s): %v", raw, err)
		}
		return v
	}
	requested := `[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example"],` +
		`"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	minted := `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","b"],` +
		`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	for name, tc := range map[string]struct {
		requested, granted string
		ok                 bool
	}{
		"identifiers added": {requested, minted, true},
		"claims narrowed": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]}]}]`, true},
		"identifiers narrowed at the token endpoint": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["b"],"locations":["https://issuer.example"],"claims":[{"path":["given_name"]}]}]`, true},
		"another configuration": {requested, `[{"type":"openid_credential","credential_configuration_id":"mdl"}]`, false},
		"another location": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"locations":["https://other.example"]}]`, false},
		"another claim": {requested, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"claims":[{"path":["birth_date"]}]}]`, false},
		"claims where none were requested": {`[{"type":"openid_credential","credential_configuration_id":"pid"}]`,
			`[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}]`, false},
		"an identifier the grant doesn't hold": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["victim-dataset"]}]`, false},
	} {
		err := registry.ValidateGrant(parse(tc.requested), parse(tc.granted))
		if (err == nil) != tc.ok {
			t.Errorf("%s: ValidateGrant = %v, want ok %v", name, err, tc.ok)
		}
	}
}

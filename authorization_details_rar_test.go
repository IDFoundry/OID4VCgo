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

// parseCredentialDetails parses raw with registry, failing t.
func parseCredentialDetails(t *testing.T, registry *extension.RARRegistry, raw string) extension.RARValues {
	t.Helper()
	v, err := registry.Parse(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("Parse(%s): %v", raw, err)
	}
	return v
}

// A grant may add credential_identifiers to what was requested, and
// otherwise only narrow it.
func TestAuthorizationDetailRARDefinition_ValidateGrant(t *testing.T) {
	registry := credentialRARRegistry(t)
	parse := func(raw string) extension.RARValues { t.Helper(); return parseCredentialDetails(t, registry, raw) }
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
		"identifiers narrowed": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
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

// A token request narrowing its grant (S-31) may keep or drop the
// grant's credential_identifiers, and otherwise only narrow it, but may
// add neither an identifier nor any member the grant lacks — even where
// the grant holds no identifiers, which consent may add to.
func TestAuthorizationDetailRARDefinition_ValidateNarrowing(t *testing.T) {
	registry := credentialRARRegistry(t)
	const (
		bare   = `[{"type":"openid_credential","credential_configuration_id":"pid"}]`
		minted = `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","b"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}]`
	)
	for name, tc := range map[string]struct {
		granted, narrowed string
		ok                bool
	}{
		"unchanged":                   {minted, minted, true},
		"bare unchanged":              {bare, bare, true},
		"identifiers kept in part":    {minted, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["b"]}]`, true},
		"identifiers dropped":         {minted, `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}]`, true},
		"identifiers added to a bare": {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["victim-dataset"]}]`, false},
		"an identifier the grant doesn't hold": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"credential_identifiers":["a","victim-dataset"]}]`, false},
		"claims added to a bare":    {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}]`, false},
		"locations added to a bare": {bare, `[{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example"]}]`, false},
		"another claim": {minted, `[{"type":"openid_credential","credential_configuration_id":"pid",` +
			`"claims":[{"path":["birth_date"]}]}]`, false},
		"another configuration": {minted, `[{"type":"openid_credential","credential_configuration_id":"mdl"}]`, false},
	} {
		err := registry.ValidateNarrowing(parseCredentialDetails(t, registry, tc.granted), parseCredentialDetails(t, registry, tc.narrowed))
		if (err == nil) != tc.ok {
			t.Errorf("%s: ValidateNarrowing = %v, want ok %v", name, err, tc.ok)
		}
	}
}

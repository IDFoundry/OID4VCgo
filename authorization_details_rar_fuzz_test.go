package oid4vci_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/idfoundry/fapigo/extension"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// FuzzAuthorizationDetailRARDefinition runs the openid_credential
// definition's checks, through fapigo's RARRegistry, on arbitrary
// authorization_details objects: a requested, a granted and a narrowed
// one. Besides never panicking: a request (ParseRequest) never carries
// credential_identifiers; a narrowing (ValidateNarrowing) never names
// an identifier the grant doesn't hold for that configuration, nor
// leaves out locations or claims every granted object for it carries;
// a grant adds identifiers only where the request had none, and
// otherwise only keeps them; and a grant that parses narrows to itself.
func FuzzAuthorizationDetailRARDefinition(f *testing.F) {
	def := oid4vci.AuthorizationDetailRARDefinition(2, 4<<10)
	registry, err := extension.NewRARRegistry(8<<10, 6, def)
	if err != nil {
		f.Fatal(err)
	}
	const (
		bare   = `{"type":"openid_credential","credential_configuration_id":"pid"}`
		minted = `{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","b"],` +
			`"locations":["https://issuer.example"],"claims":[{"path":["given_name"]},{"path":["family_name"]}]}`
		narrowed = `{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["b"],` +
			`"claims":[{"path":["given_name"]}]}`
		other = `{"type":"openid_credential","credential_configuration_id":"mdl","credential_identifiers":["c"]}`
	)
	f.Add(bare, minted, narrowed)
	f.Add(bare, bare, bare)
	f.Add(minted, minted, minted)
	f.Add(bare, minted, `{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["victim"]}`)
	f.Add(bare+","+other, minted+","+other, other)
	f.Add(bare, minted, `{"type":"openid_credential","credential_configuration_id":"pid","claims":[{"path":["given_name"]}]}`)
	f.Add(bare, minted, `{"type":"openid_credential","credential_configuration_id":"pid","locations":["https://issuer.example"]}`)
	f.Add(minted, `{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a"]}`, bare)
	f.Add(`{"type":"openid_credential"}`, `{"type":"x"}`, `{}`)
	f.Add(`{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["a","a"]}`, `null`, `1`)
	f.Fuzz(func(t *testing.T, requestedObjs, grantedObjs, narrowedObjs string) {
		requested, reqErr := registry.Parse(json.RawMessage("[" + requestedObjs + "]"))
		granted, grantErr := registry.Parse(json.RawMessage("[" + grantedObjs + "]"))
		narrower, narrowErr := registry.Parse(json.RawMessage("[" + narrowedObjs + "]"))

		if asRequest, err := registry.ParseRequest(json.RawMessage("[" + requestedObjs + "]")); err == nil {
			for _, d := range rarDetails(t, asRequest, def) {
				if len(d.CredentialIdentifiers) > 0 {
					t.Fatalf("ParseRequest accepted credential_identifiers %q", d.CredentialIdentifiers)
				}
			}
		}
		if grantErr != nil {
			return
		}
		grantDetails := rarDetails(t, granted, def)
		if err := registry.ValidateNarrowing(granted, granted); err != nil {
			t.Fatalf("a grant doesn't narrow to itself: %v (%s)", err, grantedObjs)
		}
		if narrowErr == nil && registry.ValidateNarrowing(granted, narrower) == nil {
			for _, d := range rarDetails(t, narrower, def) {
				if held := rarIdentifiersFor(grantDetails, d.CredentialConfigurationID); !rarSubset(d.CredentialIdentifiers, held) {
					t.Fatalf("narrowing accepted identifiers %q for %q, the grant holds %q",
						d.CredentialIdentifiers, d.CredentialConfigurationID, held)
				}
				if len(d.Locations) == 0 && rarAllCarry(grantDetails, d.CredentialConfigurationID, func(g oid4vci.AuthorizationDetail) bool { return len(g.Locations) > 0 }) {
					t.Fatalf("narrowing accepted %q without the grant's locations", d.CredentialConfigurationID)
				}
				if len(d.Claims) == 0 && rarAllCarry(grantDetails, d.CredentialConfigurationID, func(g oid4vci.AuthorizationDetail) bool { return len(g.Claims) > 0 }) {
					t.Fatalf("narrowing accepted %q without the grant's claims", d.CredentialConfigurationID)
				}
			}
		}
		if reqErr == nil && registry.ValidateGrant(requested, granted) == nil {
			requestedDetails := rarDetails(t, requested, def)
			for _, d := range grantDetails {
				asked := rarIdentifiersFor(requestedDetails, d.CredentialConfigurationID)
				if len(asked) > 0 && !rarSubset(d.CredentialIdentifiers, asked) {
					t.Fatalf("grant accepted identifiers %q for %q, which requested only %q",
						d.CredentialIdentifiers, d.CredentialConfigurationID, asked)
				}
			}
		}
	})
}

// rarDetails is values' openid_credential objects.
func rarDetails(t *testing.T, values extension.RARValues, def extension.RARDefinition[oid4vci.AuthorizationDetail]) []oid4vci.AuthorizationDetail {
	t.Helper()
	got, err := extension.RARGet(values, def)
	if err != nil {
		t.Fatalf("RARGet of parsed values: %v", err)
	}
	out := make([]oid4vci.AuthorizationDetail, len(got))
	for i, d := range got {
		out[i] = d.Fields
	}
	return out
}

// rarIdentifiersFor is every credential_identifier ds hold for the
// configuration id.
func rarIdentifiersFor(ds []oid4vci.AuthorizationDetail, id string) []string {
	var out []string
	for _, d := range ds {
		if d.CredentialConfigurationID == id {
			out = append(out, d.CredentialIdentifiers...)
		}
	}
	return out
}

// rarAllCarry reports whether ds hold an object for the configuration
// id and every such object satisfies carries.
func rarAllCarry(ds []oid4vci.AuthorizationDetail, id string, carries func(oid4vci.AuthorizationDetail) bool) bool {
	found := false
	for _, d := range ds {
		if d.CredentialConfigurationID == id {
			if !carries(d) {
				return false
			}
			found = true
		}
	}
	return found
}

func rarSubset(sub, super []string) bool {
	for _, s := range sub {
		if !slices.Contains(super, s) {
			return false
		}
	}
	return true
}

package issuer_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A request by credential_configuration_id is refused whenever one of
// the token's authorization details for the configuration carries
// credential_identifiers (§8.2), whatever order they come in; one the
// token grants is authorized for the claims of the details without
// identifiers alone.
func TestConfigurationIDRequestIgnoresDetailOrder(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	ageOver18 := oid4vci.ClaimsDescription{Path: []any{"age_over_18"}}
	givenName := oid4vci.ClaimsDescription{Path: []any{"given_name"}}
	familyName := oid4vci.ClaimsDescription{Path: []any{"family_name"}}
	detail := func(identifier string, claims ...oid4vci.ClaimsDescription) oid4vci.AuthorizationDetail {
		d := oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: testSDJWTConfigID, Claims: claims}
		if identifier != "" {
			d.CredentialIdentifiers = []string{identifier}
		}
		return d
	}
	byConfiguration := issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID}
	resolve := func(req issuer.CredentialRequest, details ...oid4vci.AuthorizationDetail) ([]oid4vci.ClaimsDescription, error) {
		return f.iss.ResolveAuthorizedClaims(issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), AuthorizationDetails: details}, req)
	}

	mixed := []oid4vci.AuthorizationDetail{detail("", ageOver18), detail("pid-2", familyName)}
	for _, order := range [][]oid4vci.AuthorizationDetail{mixed, {mixed[1], mixed[0]}} {
		_, err := resolve(byConfiguration, order...)
		var e *issuer.Error
		if !errors.As(err, &e) || e.Code() != issuer.ErrorInvalidCredentialRequest {
			t.Errorf("by credential_configuration_id, details %v first: %v, want invalid_credential_request", order[0].CredentialIdentifiers, err)
		}
		claims, err := resolve(issuer.CredentialRequest{CredentialIdentifier: "pid-2"}, order...)
		if err != nil || !reflect.DeepEqual(claims, []oid4vci.ClaimsDescription{familyName}) {
			t.Errorf("by credential_identifier, details %v first: %v, %v; want the identifier's detail's claims", order[0].CredentialIdentifiers, claims, err)
		}
	}

	claims, err := resolve(byConfiguration, detail("", givenName), detail("", familyName))
	if err != nil || !reflect.DeepEqual(claims, []oid4vci.ClaimsDescription{givenName, familyName}) {
		t.Errorf("two details without identifiers: %v, %v; want both's claims", claims, err)
	}
}

// UndetailedScopes leaves out the scope of each of this Credential
// Issuer's configurations a granted openid_credential object names,
// and passes by every other scope and object.
func TestUndetailedScopes(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	raw := func(d oid4vci.AuthorizationDetail) json.RawMessage {
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	forThisIssuer := oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: testSDJWTConfigID}
	elsewhere := forThisIssuer
	elsewhere.Locations = []string{"https://other-issuer.example"}
	unknown := forThisIssuer
	unknown.CredentialConfigurationID = "NoSuchConfiguration"
	scopes := []string{"identity_credential", "offline_access"}
	for name, tc := range map[string]struct {
		details []json.RawMessage
		want    []string
	}{
		"an object for the configuration": {[]json.RawMessage{raw(forThisIssuer)}, []string{"offline_access"}},
		"another issuer's object":         {[]json.RawMessage{raw(elsewhere)}, scopes},
		"an unknown configuration":        {[]json.RawMessage{raw(unknown)}, scopes},
		"an object that doesn't parse":    {[]json.RawMessage{json.RawMessage(`{"type":`)}, scopes},
		"no objects":                      {nil, scopes},
	} {
		if got := f.iss.UndetailedScopes(scopes, tc.details); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: UndetailedScopes = %v, want %v", name, got, tc.want)
		}
	}
	if got := f.iss.UndetailedScopes(scopes, []json.RawMessage{raw(forThisIssuer)}); &got[0] == &scopes[0] || scopes[0] != "identity_credential" {
		t.Error("UndetailedScopes changed the slice it was given")
	}
}

// A consent step granting a configuration's object, for a request
// asking for it by both its object and its scope, keeps the scope out
// with UndetailedScopes: a code exchange asking for
// authorization_details=[] then gets a token holding neither the
// narrowed object nor the scope, which would grant the configuration
// whole. Without it, that token carries the scope.
func TestUndetailedScopesWithEmptyTokenDetails(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	for name, tc := range map[string]struct {
		grantScope func([]string, []json.RawMessage) []string
		wantScope  bool
	}{
		"the requested scope granted beside the object": {nil, true},
		"UndetailedScopes": {f.iss.UndetailedScopes, false},
	} {
		t.Run(name, func(t *testing.T) {
			flow, code := authorizeCredentialDetailsGranting(t, []string{"minted-1"}, tc.grantScope, "example_extra")
			tok, err := flow.exchange(t, code, "[]")
			if err != nil {
				t.Fatalf("ExchangeAuthorizationCode with authorization_details=[]: %v", err)
			}
			if got := slices.Contains(strings.Fields(tok.Scope), "identity_credential"); got != tc.wantScope {
				t.Errorf("token scope %q holds identity_credential: %t, want %t", tok.Scope, got, tc.wantScope)
			}
		})
	}
}

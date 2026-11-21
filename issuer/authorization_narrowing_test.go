package issuer_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"

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

// A code exchange asking for authorization_details=[] leaves the
// granted object out. While the grant holds the configuration's scope
// beside it, which would then grant the configuration whole, the
// exchange is refused (AuthorizationDetailRARDefinition). With
// UndetailedScopes the grant holds no such scope, and the token holds
// neither the object nor the scope.
func TestUndetailedScopesWithEmptyTokenDetails(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	t.Run("the requested scope granted beside the object", func(t *testing.T) {
		flow, code := authorizeCredentialDetailsGranting(t, []string{"minted-1"}, nil, "example_extra")
		_, err := flow.exchange(t, code, "[]")
		requireInvalidAuthorizationDetails(t, "ExchangeAuthorizationCode with authorization_details=[]", err)
	})
	t.Run("UndetailedScopes", func(t *testing.T) {
		flow, code := authorizeCredentialDetailsGranting(t, []string{"minted-1"}, f.iss.UndetailedScopes, "example_extra")
		tok, err := flow.exchange(t, code, "[]")
		if err != nil {
			t.Fatalf("ExchangeAuthorizationCode with authorization_details=[]: %v", err)
		}
		if slices.Contains(strings.Fields(tok.Scope), "identity_credential") {
			t.Errorf("token scope %q holds identity_credential", tok.Scope)
		}
	})
}

// AuthorizationDetailRARDefinition refuses a token request leaving out
// a granted openid_credential object for this Credential Issuer while
// the access token keeps its configuration's scope (OpenID4VCI 1.0
// §5.1.2: the object governs), and allows every other omission.
func TestAuthorizationDetailRARDefinition_ValidateOmission(t *testing.T) {
	const otherIssuer = "https://other-issuer.example.com"
	object := func(id string, locations ...string) string {
		raw, err := json.Marshal(oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: id, Locations: locations})
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	pid, mdl := object("pid"), object("mdl")
	for name, tc := range map[string]struct {
		granted, narrowed, scope  []string
		listsAuthorizationServers bool
		refused                   bool
	}{
		"left out while its scope is kept":         {granted: []string{pid}, scope: []string{"pid_scope"}, refused: true},
		"left out with its scope":                  {granted: []string{pid}, scope: []string{"openid"}},
		"one of two, the other's scope not kept":   {granted: []string{pid, mdl}, narrowed: []string{pid}, scope: []string{"pid_scope"}},
		"one of two, the other's scope kept":       {granted: []string{pid, mdl}, narrowed: []string{pid}, scope: []string{"pid_scope", "mdl_scope"}, refused: true},
		"one of two sharing a scope that is kept":  {granted: []string{object("diploma"), object("transcript")}, narrowed: []string{object("diploma")}, scope: []string{"education"}, refused: true},
		"a configuration without a scope":          {granted: []string{object("unscoped")}, scope: []string{"pid_scope"}},
		"a configuration the issuer doesn't offer": {granted: []string{object("unknown")}, scope: []string{"pid_scope"}},
		"another Credential Issuer's object":       {granted: []string{object("pid", otherIssuer)}, scope: []string{"pid_scope"}},
		"this Credential Issuer's, by location":    {granted: []string{object("pid", testIssuer)}, scope: []string{"pid_scope"}, refused: true},
		"no locations, with authorization servers": {granted: []string{pid}, scope: []string{"pid_scope"}, listsAuthorizationServers: true},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := issuer.Config{
				Issuer: mustIssuerURL(t, testIssuer),
				CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
					"pid": {Scope: "pid_scope"}, "mdl": {Scope: "mdl_scope"},
					"diploma": {Scope: "education"}, "transcript": {Scope: "education"}, "unscoped": {},
				},
			}
			if tc.listsAuthorizationServers {
				cfg.AuthorizationServers = []fapi.URL{mustIssuerURL(t, otherIssuer)}
			}
			registry, err := extension.NewRARRegistry(8<<10, 6, issuer.AuthorizationDetailRARDefinition(cfg, 4, 1<<10))
			if err != nil {
				t.Fatalf("NewRARRegistry: %v", err)
			}
			parse := func(objects []string) extension.RARValues {
				if len(objects) == 0 {
					return extension.RARValues{}
				}
				values, err := registry.Parse(json.RawMessage("[" + strings.Join(objects, ",") + "]"))
				if err != nil {
					t.Fatalf("Parse: %v", err)
				}
				return values
			}
			err = registry.ValidateNarrowing(parse(tc.granted), parse(tc.narrowed), tc.scope)
			if refused := errors.Is(err, extension.ErrRAROmissionRefused); refused != tc.refused || (err != nil && !refused) {
				t.Fatalf("ValidateNarrowing = %v, want refused %t", err, tc.refused)
			}
		})
	}
}

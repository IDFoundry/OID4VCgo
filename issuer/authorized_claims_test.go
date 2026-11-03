package issuer_test

import (
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// The claims a Credential Request is authorized for are those its
// authorization detail asks for, so Prepare can issue only them
// (§5.1.1, Appendix B.1); nil, every claim, for a detail naming none or
// a grant by scope.
func TestResolveAuthorizedClaims(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	givenName := oid4vci.ClaimsDescription{Path: []any{"given_name"}}
	familyName := oid4vci.ClaimsDescription{Path: []any{"family_name"}}
	detail := func(identifier string, claims ...oid4vci.ClaimsDescription) oid4vci.AuthorizationDetail {
		d := oid4vci.AuthorizationDetail{Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: testSDJWTConfigID, Claims: claims}
		if identifier != "" {
			d.CredentialIdentifiers = []string{identifier}
		}
		return d
	}
	for name, tc := range map[string]struct {
		auth issuer.AuthorizedRequest
		req  issuer.CredentialRequest
		want []oid4vci.ClaimsDescription
	}{
		"by scope": {
			auth: issuer.AuthorizedRequest{Scopes: []string{"identity_credential"}},
			req:  issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID},
		},
		"a detail naming claims": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail("", givenName)}},
			req:  issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID},
			want: []oid4vci.ClaimsDescription{givenName},
		},
		"a detail naming none": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail("")}},
			req:  issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID},
		},
		"the detail holding the identifier": {
			auth: issuer.AuthorizedRequest{AuthorizationDetails: []oid4vci.AuthorizationDetail{detail("pid-1", givenName), detail("pid-2", familyName)}},
			req:  issuer.CredentialRequest{CredentialIdentifier: "pid-2"},
			want: []oid4vci.ClaimsDescription{familyName},
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc.auth.ClientIdentity = issuer.KnownClientID("test-client")
			got, err := f.iss.ResolveAuthorizedClaims(tc.auth, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ResolveAuthorizedClaims = %v, want %v", got, tc.want)
			}
		})
	}
}

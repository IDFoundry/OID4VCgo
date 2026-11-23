package issuer_test

import (
	"errors"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
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

// claimPaths are claims descriptions of paths.
func claimPaths(paths ...[]any) []oid4vci.ClaimsDescription {
	out := make([]oid4vci.ClaimsDescription, len(paths))
	for i, p := range paths {
		out[i] = oid4vci.ClaimsDescription{Path: p}
	}
	return out
}

// NarrowToAuthorizedClaims keeps the claims a token's authorization
// detail asks for, the registered ones and those the configuration
// marks mandatory (Appendix B.2), and leaves the maps it was given
// alone.
func TestNarrowToAuthorizedClaims(t *testing.T) {
	yes := true
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		c := cfg.CredentialConfigurationsSupported[testSDJWTConfigID]
		c.CredentialMetadata = &oid4vci.CredentialMetadata{Claims: []oid4vci.ClaimsDescription{{Path: []any{"family_name"}, Mandatory: &yes}}}
		c.TypeMetadata = &sdjwtvc.TypeMetadata{VCT: c.VCT, Claims: []sdjwtvc.ClaimMetadata{{Path: sdjwtvc.ClaimPath("nationality"), Mandatory: true}}}
		cfg.CredentialConfigurationsSupported[testSDJWTConfigID] = c
		m := cfg.CredentialConfigurationsSupported[testMdocConfigID]
		m.CredentialMetadata = &oid4vci.CredentialMetadata{Claims: []oid4vci.ClaimsDescription{{Path: []any{"org.iso.18013.5.1", "issuing_country"}, Mandatory: &yes}}}
		cfg.CredentialConfigurationsSupported[testMdocConfigID] = m
	})
	additional := map[string]any{
		"given_name": sdjwtvc.SD("Erika"), "family_name": sdjwtvc.SD("Mustermann"), "nationality": "DE",
		"birthdate": sdjwtvc.SD("1964-08-12"), "address": map[string]any{"locality": sdjwtvc.SD("Berlin"), "street_address": sdjwtvc.SD("Heidestraße 17")},
		"iat": 1, "sub": "holder",
	}
	nameSpaces := map[string]map[string]any{
		"org.iso.18013.5.1":    {"given_name": "Erika", "family_name": "Mustermann", "issuing_country": "DE"},
		"org.iso.18013.5.1.aa": {"document_number": "T22000129"},
	}
	for name, tc := range map[string]struct {
		configID   string
		authorized []oid4vci.ClaimsDescription
		members    []string
		elements   map[string][]string
		decoys     map[string]int
	}{
		"every claim": {
			configID: testSDJWTConfigID, members: slices.Collect(maps.Keys(additional)),
			elements: map[string][]string{"org.iso.18013.5.1": {"family_name", "given_name", "issuing_country"}, "org.iso.18013.5.1.aa": {"document_number"}},
			decoys:   map[string]int{"org.iso.18013.5.1": 2, "org.iso.18013.5.1.aa": 3},
		},
		"an SD-JWT VC's claims": {
			configID: testSDJWTConfigID, authorized: claimPaths([]any{"given_name"}, []any{"address", "locality"}, []any{"no_such_claim"}, []any{nil}),
			members:  []string{"address", "family_name", "given_name", "iat", "nationality"},
			elements: map[string][]string{},
		},
		"an SD-JWT VC's sub, when asked for": {
			configID: testSDJWTConfigID, authorized: claimPaths([]any{"sub"}),
			members:  []string{"family_name", "iat", "nationality", "sub"},
			elements: map[string][]string{},
		},
		"an mdoc's data elements": {
			configID: testMdocConfigID, authorized: claimPaths([]any{"org.iso.18013.5.1", "given_name"}, []any{"org.iso.18013.5.1.aa"}, []any{"org.iso.18013.5.1", "family_name", 0}),
			members:  []string{"iat"},
			elements: map[string][]string{"org.iso.18013.5.1": {"given_name", "issuing_country"}},
			decoys:   map[string]int{"org.iso.18013.5.1": 2},
		},
	} {
		t.Run(name, func(t *testing.T) {
			sdjwtClaims := &sdjwtvc.Claims{VCT: testVCT, Additional: maps.Clone(additional)}
			mdocClaims := &mdoc.Claims{DocType: "org.iso.18013.5.1.mDL", NameSpaces: map[string]map[string]any{}, Decoys: map[string]int{"org.iso.18013.5.1": 2, "org.iso.18013.5.1.aa": 3}}
			for ns, elements := range nameSpaces {
				mdocClaims.NameSpaces[ns] = maps.Clone(elements)
			}
			gotSDJWT, gotMdoc, err := f.iss.NarrowToAuthorizedClaims(tc.configID, tc.authorized, sdjwtClaims, mdocClaims)
			if err != nil {
				t.Fatal(err)
			}
			if got := slices.Sorted(maps.Keys(gotSDJWT.Additional)); !slices.Equal(got, slices.Sorted(slices.Values(tc.members))) {
				t.Errorf("SD-JWT VC claims = %v, want %v", got, slices.Sorted(slices.Values(tc.members)))
			}
			if gotSDJWT.VCT != testVCT {
				t.Errorf("vct = %q, want it kept", gotSDJWT.VCT)
			}
			got := map[string][]string{}
			for ns, elements := range gotMdoc.NameSpaces {
				got[ns] = slices.Sorted(maps.Keys(elements))
			}
			if !reflect.DeepEqual(got, tc.elements) {
				t.Errorf("mdoc data elements = %v, want %v", got, tc.elements)
			}
			if !reflect.DeepEqual(gotMdoc.Decoys, tc.decoys) {
				t.Errorf("mdoc decoys = %v, want %v", gotMdoc.Decoys, tc.decoys)
			}
			if len(sdjwtClaims.Additional) != len(additional) || len(mdocClaims.NameSpaces["org.iso.18013.5.1"]) != 3 || len(mdocClaims.NameSpaces) != 2 {
				t.Error("NarrowToAuthorizedClaims changed the claims it was given")
			}
		})
	}
}

// An mdoc left with no data element can't be issued, so it's refused
// with credential_request_denied; an unknown configuration is an
// error.
func TestNarrowToAuthorizedClaims_Refusals(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, _, err := f.iss.NarrowToAuthorizedClaims(testMdocConfigID, claimPaths([]any{"org.iso.18013.5.1", "no_such_element"}), nil, testMdocClaims(t))
	var ierr *issuer.Error
	if !errors.As(err, &ierr) || ierr.Code() != issuer.ErrorCredentialRequestDenied {
		t.Errorf("an mdoc with nothing authorized: %v, want credential_request_denied", err)
	}
	if _, _, err := f.iss.NarrowToAuthorizedClaims(testSDJWTConfigID, claimPaths([]any{"given_name"}), &sdjwtvc.Claims{VCT: testVCT}, testMdocClaims(t)); err != nil {
		t.Errorf("an SD-JWT VC configuration whose unused mdoc claims are left empty: %v", err)
	}
	if _, _, err := f.iss.NarrowToAuthorizedClaims("no-such-configuration", nil, nil, nil); err == nil {
		t.Error("narrowed the claims of an unknown configuration")
	}
}

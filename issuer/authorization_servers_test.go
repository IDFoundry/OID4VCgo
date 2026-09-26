package issuer_test

import (
	"context"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func mustAS(t *testing.T, raw string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseIssuerURL(raw)
	if err != nil {
		t.Fatalf("ParseIssuerURL(%q): %v", raw, err)
	}
	return u
}

func TestNewRejectsInvalidAuthorizationServers(t *testing.T) {
	for name, servers := range map[string][]fapi.URL{
		"unset entry": {{}},
		"duplicate":   {mustAS(t, "https://as.example.com"), mustAS(t, "https://as.example.com")},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(t)
			cfg.AuthorizationServers = servers
			if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
				t.Fatal("New = nil error, want error")
			}
		})
	}
}

func TestMetadataAdvertisesAuthorizationServers(t *testing.T) {
	cfg := validConfig(t)
	cfg.AuthorizationServers = []fapi.URL{mustAS(t, "https://as1.example.com"), mustAS(t, "https://as2.example.com")}
	iss := newTestIssuer(t, cfg, validDependencies(t))
	md := iss.Metadata()
	if len(md.AuthorizationServers) != 2 || md.AuthorizationServers[1].String() != "https://as2.example.com" {
		t.Fatalf("Metadata().AuthorizationServers = %v", md.AuthorizationServers)
	}

	// Metadata owns a copy: mutating it doesn't change the issuer's.
	md.AuthorizationServers[0] = mustAS(t, "https://evil.example.com")
	if got := iss.Metadata().AuthorizationServers[0].String(); got != "https://as1.example.com" {
		t.Errorf("issuer's authorization_servers changed to %s", got)
	}

	if md := newTestIssuer(t, validConfig(t), validDependencies(t)).Metadata(); md.AuthorizationServers != nil {
		t.Errorf("unconfigured issuer advertises authorization_servers %v", md.AuthorizationServers)
	}
}

// TestCreateCredentialOffer_GrantAuthorizationServer checks §4.1.1: a
// grant's authorization_server is allowed only when the issuer
// advertises more than one authorization server, and must be one of
// them.
func TestCreateCredentialOffer_GrantAuthorizationServer(t *testing.T) {
	as1, as2 := "https://as1.example.com", "https://as2.example.com"
	cases := []struct {
		name    string
		servers []string
		grantAS string
		wantErr string // "" means accepted
	}{
		{name: "no servers, grant names one", servers: nil, grantAS: as1, wantErr: "must not be set"},
		{name: "one server, grant names it", servers: []string{as1}, grantAS: as1, wantErr: "must not be set"},
		{name: "two servers, grant names one", servers: []string{as1, as2}, grantAS: as2},
		{name: "two servers, grant names another", servers: []string{as1, as2}, grantAS: "https://other.example.com", wantErr: "not one of"},
		{name: "two servers, grant names none", servers: []string{as1, as2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig(t)
			for _, s := range tc.servers {
				cfg.AuthorizationServers = append(cfg.AuthorizationServers, mustAS(t, s))
			}
			iss := newTestIssuer(t, cfg, validDependencies(t))
			for grant, grants := range map[string]*oid4vci.Grants{
				"authorization_code":  {AuthorizationCode: &oid4vci.GrantAuthorizationCode{AuthorizationServer: tc.grantAS}},
				"pre-authorized_code": {PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc123", AuthorizationServer: tc.grantAS}},
			} {
				_, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
					CredentialConfigurationIDs: []string{"IdentityCredential"}, Grants: grants,
				})
				switch {
				case tc.wantErr == "" && err != nil:
					t.Errorf("%s: CreateCredentialOffer: %v", grant, err)
				case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
					t.Errorf("%s: error = %v, want one containing %q", grant, err, tc.wantErr)
				}
			}
		})
	}
}

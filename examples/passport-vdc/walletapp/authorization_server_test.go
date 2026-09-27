package walletapp

import (
	"testing"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

func TestAuthorizationServer(t *testing.T) {
	const issuer = "https://issuer.example.com"
	as := func(raw string) fapi.URL {
		u, err := fapi.ParseIssuerURL(raw)
		if err != nil {
			t.Fatalf("ParseIssuerURL(%q): %v", raw, err)
		}
		return u
	}
	offer := func(named string) oid4vci.CredentialOffer {
		o := oid4vci.CredentialOffer{CredentialIssuer: issuer}
		if named != "" {
			o.Grants = &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{AuthorizationServer: named}}
		}
		return o
	}
	two := []fapi.URL{as("https://as1.example.com"), as("https://as2.example.com")}

	for _, tc := range []struct {
		name    string
		offer   oid4vci.CredentialOffer
		servers []fapi.URL
		want    string // "" means an error
	}{
		{"none listed: the issuer itself", offer(""), nil, issuer},
		{"one listed", offer(""), []fapi.URL{as("https://as1.example.com")}, "https://as1.example.com"},
		{"several, offer names one", offer("https://as2.example.com"), two, "https://as2.example.com"},
		{"several, offer names none", offer(""), two, ""},
		{"several, offer names an unlisted one", offer("https://attacker.example.com"), two, ""},
		{"one listed, offer names another", offer("https://attacker.example.com"), two[:1], ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authorizationServer(tc.offer, oid4vci.Metadata{AuthorizationServers: tc.servers})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("authorizationServer = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("authorizationServer = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func TestPlanAuthorization(t *testing.T) {
	const issuer = "https://issuer.example.com"
	as := func(raw string) fapi.URL {
		u, err := fapi.ParseIssuerURL(raw)
		if err != nil {
			t.Fatalf("ParseIssuerURL(%q): %v", raw, err)
		}
		return u
	}
	metadata := func(servers ...fapi.URL) oid4vci.Metadata {
		return oid4vci.Metadata{
			CredentialIssuer:     as(issuer),
			AuthorizationServers: servers,
			CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfigurationMetadata{
				"pid_sdjwt": {Format: "dc+sd-jwt", Scope: "pid"},
				"pid_mdoc":  {Format: "mso_mdoc", Scope: "pid"}, // same scope: requested once
				"mdl":       {Format: "mso_mdoc", Scope: "mdl"},
				"noscope":   {Format: "dc+sd-jwt"},
			},
		}
	}
	offer := func(named string, ids ...string) oid4vci.CredentialOffer {
		return oid4vci.CredentialOffer{
			CredentialIssuer: issuer, CredentialConfigurationIDs: ids,
			Grants: &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: "st", AuthorizationServer: named}},
		}
	}
	two := []fapi.URL{as("https://as1.example.com"), as("https://as2.example.com")}

	got, err := wallet.PlanAuthorization(offer("", "pid_sdjwt", "pid_mdoc", "mdl"), metadata())
	if err != nil {
		t.Fatalf("PlanAuthorization: %v", err)
	}
	if want := (wallet.AuthorizationPlan{AuthorizationServer: issuer, Scopes: []string{"pid", "mdl"}, IssuerState: "st"}); !reflect.DeepEqual(got, want) {
		t.Errorf("plan = %+v, want %+v", got, want)
	}

	for name, tc := range map[string]struct {
		offer oid4vci.CredentialOffer
		meta  oid4vci.Metadata
		want  string // authorization server; "" means an error
	}{
		"one listed":                           {offer("", "mdl"), metadata(two[0]), "https://as1.example.com"},
		"several, offer names one":             {offer("https://as2.example.com", "mdl"), metadata(two...), "https://as2.example.com"},
		"several, offer names none":            {offer("", "mdl"), metadata(two...), ""},
		"several, offer names an unlisted one": {offer("https://attacker.example.com", "mdl"), metadata(two...), ""},
		"one listed, offer names another":      {offer("https://attacker.example.com", "mdl"), metadata(two[0]), ""},
		"none listed, offer names another":     {offer("https://attacker.example.com", "mdl"), metadata(), ""},
		"unknown configuration":                {offer("", "nope"), metadata(), ""},
		"configuration without a scope":        {offer("", "noscope"), metadata(), ""},
		"no configurations":                    {offer(""), metadata(), ""},
		"pre-authorized only": {oid4vci.CredentialOffer{
			CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"mdl"},
			Grants: &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "code"}},
		}, metadata(), ""},
		"wallet-initiated (no grants)": {oid4vci.CredentialOffer{CredentialIssuer: issuer, CredentialConfigurationIDs: []string{"mdl"}}, metadata(), issuer},
		"metadata for another issuer":  {oid4vci.CredentialOffer{CredentialIssuer: "https://other.example.com", CredentialConfigurationIDs: []string{"mdl"}}, metadata(), ""},
	} {
		t.Run(name, func(t *testing.T) {
			plan, err := wallet.PlanAuthorization(tc.offer, tc.meta)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("plan = %+v, want an error", plan)
				}
				return
			}
			if err != nil || plan.AuthorizationServer != tc.want {
				t.Fatalf("plan = %+v, %v; want authorization server %q", plan, err, tc.want)
			}
		})
	}
}

func TestAuthorizationServerMetadata_ClientEndpoints(t *testing.T) {
	m := wallet.AuthorizationServerMetadata{
		Issuer: "https://as.example.com", AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint: "https://as.example.com/token", PushedAuthorizationRequestEndpoint: "https://as.example.com/par",
	}
	issuer, endpoints, err := m.ClientEndpoints()
	if err != nil {
		t.Fatalf("ClientEndpoints: %v", err)
	}
	if issuer.String() != m.Issuer || endpoints.Authorization.String() != m.AuthorizationEndpoint ||
		endpoints.Token.String() != m.TokenEndpoint || endpoints.PushedAuthorizationRequest.String() != m.PushedAuthorizationRequestEndpoint {
		t.Errorf("ClientEndpoints = %v, %+v", issuer, endpoints)
	}

	loopback := wallet.AuthorizationServerMetadata{
		Issuer: "http://127.0.0.1:8080", AuthorizationEndpoint: "http://127.0.0.1:8080/authorize",
		TokenEndpoint: "http://127.0.0.1:8080/token", PushedAuthorizationRequestEndpoint: "http://127.0.0.1:8080/par",
	}
	if _, _, err := loopback.ClientEndpoints(); err == nil {
		t.Error("loopback http accepted without fapi.AllowLoopbackHTTP")
	}
	if _, _, err := loopback.ClientEndpoints(fapi.AllowLoopbackHTTP()); err != nil {
		t.Errorf("loopback http with fapi.AllowLoopbackHTTP: %v", err)
	}
	missing := m
	missing.PushedAuthorizationRequestEndpoint = ""
	if _, _, err := missing.ClientEndpoints(); err == nil || !strings.Contains(err.Error(), "pushed_authorization_request_endpoint") {
		t.Errorf("missing PAR endpoint: error = %v", err)
	}
}

func TestParseAuthorizationRequestLink(t *testing.T) {
	got, err := wallet.ParseAuthorizationRequestLink("openid4vp://?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fverifier.example%2Fro%2F1")
	if err != nil {
		t.Fatalf("ParseAuthorizationRequestLink: %v", err)
	}
	if want := (wallet.AuthorizationRequestLink{ClientID: "x509_hash:abc", RequestURI: "https://verifier.example/ro/1", RequestURIMethod: wallet.RequestURIMethodGet}); got != want {
		t.Errorf("link = %+v, want %+v", got, want)
	}
	if got, err := wallet.ParseAuthorizationRequestLink("https://wallet.example/present?client_id=c&request_uri=https%3A%2F%2Fv.example%2Fr&request_uri_method=post"); err != nil || got.RequestURIMethod != wallet.RequestURIMethodPost {
		t.Errorf("https link with request_uri_method=post: %+v, %v", got, err)
	}
	for name, link := range map[string]string{
		"no client_id":         "openid4vp://?request_uri=https%3A%2F%2Fv.example%2Fr",
		"no request_uri":       "openid4vp://?client_id=c",
		"request by value":     "openid4vp://?client_id=c&request=eyJ.eyJ.sig",
		"relative request_uri": "openid4vp://?client_id=c&request_uri=%2Fr",
		"unknown method":       "openid4vp://?client_id=c&request_uri=https%3A%2F%2Fv.example%2Fr&request_uri_method=put",
	} {
		if got, err := wallet.ParseAuthorizationRequestLink(link); err == nil {
			t.Errorf("%s: accepted as %+v", name, got)
		}
	}
}

// TestPreviewPresentation_MatchesWhatIsPresented checks the preview
// names exactly the claims PresentCredentials discloses — here the first
// satisfiable claim_sets option, not every claim the query lists.
func TestPreviewPresentation_MatchesWhatIsPresented(t *testing.T) {
	ca, caKey := testcert.CA(t, "preview test CA")
	leaf, leafKey := testcert.Leaf(t, "preview test issuer", ca, caKey)
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holderJWK, err := jwk.Marshal(&holder.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).Unix()
	credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{
		VCT: "urn:eudi:pid:1", Exp: &exp, CNF: map[string]any{"jwk": holderJWK},
		Additional: map[string]any{
			"given_name": sdjwtvc.SD("Alice"), "family_name": sdjwtvc.SD("Doe"), "birthdate": sdjwtvc.SD("2000-01-01"),
		},
	}, sdjwtvc.IssueOptions{IssuerCertificate: leaf})
	if err != nil {
		t.Fatalf("sdjwtvc.Issue: %v", err)
	}
	held := []wallet.HeldCredential{{Format: sdjwtvc.CredentialFormat, Credential: credential, HolderKey: holder, HolderKeyAlg: jose.ES256}}

	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:eudi:pid:1"}})
	if err != nil {
		t.Fatal(err)
	}
	claim := func(id, name string) dcql.ClaimsQuery {
		return dcql.ClaimsQuery{ID: id, Path: dcql.Path{dcql.PathKey(name)}}
	}
	query := dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "pid", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims:    []dcql.ClaimsQuery{claim("g", "given_name"), claim("f", "family_name"), claim("b", "birthdate")},
		ClaimSets: [][]string{{"g"}, {"f", "b"}},
	}}}

	preview, err := wallet.PreviewPresentation(context.Background(), query, held, nil)
	if err != nil {
		t.Fatalf("PreviewPresentation: %v", err)
	}
	if len(preview) != 1 || preview[0].QueryID != "pid" || len(preview[0].Claims) != 1 || preview[0].Claims[0][0].Key() != "given_name" {
		t.Fatalf("preview = %+v, want the pid credential with given_name only", preview)
	}

	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: query, Credentials: held, Audience: "x509_hash:abc", Nonce: "n",
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	pres, err := sdjwtvc.Parse(vpToken["pid"][0])
	if err != nil {
		t.Fatalf("parse presentation: %v", err)
	}
	var disclosed []string
	for _, d := range pres.Disclosures {
		disclosed = append(disclosed, d.Name)
	}
	if !reflect.DeepEqual(disclosed, []string{"given_name"}) {
		t.Errorf("PresentCredentials disclosed %v, the preview said [given_name]", disclosed)
	}
}

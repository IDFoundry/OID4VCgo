package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// sharedASAuthorizeCode runs the authorization code flow at srv for a
// request naming resources, with tenant's consent step signing in its
// own user-42 and granting what tenant.iss.AuthorizationResources
// decides, or denying the request when it refuses. It returns the
// DPoP-bound access token and its key, or the authorization error the
// client was redirected with.
func sharedASAuthorizeCode(t *testing.T, srv *server.Server, clientKey *ecdsa.PrivateKey, now time.Time, tenant sharedASTenant, resources ...string) (string, *ecdsa.PrivateKey, string) {
	t.Helper()
	ctx := context.Background()
	params := pushedAuthorizationParameters(buildClientAssertion(t, clientKey, now), "offer")
	for i := range params {
		if params[i].Name == "scope" {
			params[i].Value = "diploma"
		}
	}
	for _, r := range resources {
		params = append(params, server.FormParameter{Name: "resource", Value: r})
	}
	pushed, err := srv.PushAuthorizationRequest(ctx, server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: params}})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	action, err := srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: pushed.RequestURI.String(), ClientID: testASClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization = %T", action)
	}
	result := server.Deny("the request names another resource")
	if granted, err := tenant.iss.AuthorizationResources(interaction.Interaction.Resources); err == nil {
		subjectID, _ := server.NewSubjectID("user-42")
		subject, _ := server.NewAuthenticatedSubject(subjectID)
		authCtx, _ := server.NewAuthenticationContext(now, "urn:example:login", nil)
		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: interaction.Interaction.Scope, Resources: granted})
	} else if !errors.Is(err, issuer.ErrResourceNotThisIssuer) {
		t.Fatalf("AuthorizationResources: %v", err)
	}
	done, err := srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{Handle: interaction.Handle, Result: result})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	redirect, ok := done.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T", done)
	}
	destination := redirect.Destination().URL()
	query := destination.Query()
	if query.Get("code") == "" {
		return "", nil, query.Get("error")
	}
	dpopKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token, err := srv.ExchangeAuthorizationCode(ctx, server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: []server.FormParameter{
			{Name: "grant_type", Value: "authorization_code"},
			{Name: "code", Value: query.Get("code")},
			{Name: "redirect_uri", Value: string(testASRedirectURI)},
			{Name: "code_verifier", Value: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
			{Name: "client_assertion", Value: buildClientAssertion(t, clientKey, now)},
			{Name: "client_assertion_type", Value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		}},
		DPoPProofs: []string{sharedASDPoP(t, dpopKey, http.MethodPost, testASIssuer+"/token", "")},
	})
	if err != nil {
		t.Fatalf("ExchangeAuthorizationCode: %v", err)
	}
	return token.AccessToken.Reveal(), dpopKey, ""
}

// TestSharedAuthorizationServer_AuthorizationCodeConsentGrantsOnlyItsIssuer:
// on an Authorization Server serving tenants A and B, a Wallet whose
// request for tenant A's offer names tenant B as its resource is
// denied at tenant A's consent step, rather than given a token tenant
// B takes for its own user-42; one naming tenant A, alone or beside
// tenant B, gets a token for tenant A only.
func TestSharedAuthorizationServer_AuthorizationCodeConsentGrantsOnlyItsIssuer(t *testing.T) {
	var asCfg server.Config
	var asDeps server.Dependencies
	srv, clientKey, now := newTestAuthorizationServer(t, nil, func(cfg *server.Config, deps *server.Dependencies, client *storage.RegisteredClientConfig) {
		cfg.Resources = []string{sharedASTenantA, sharedASTenantB}
		client.AllowedScopes = []string{"diploma"}
		asCfg, asDeps = *cfg, *deps
	})
	tenantA := sharedASNewTenant(t, sharedASTenantA, asCfg, asDeps, sharedASTenantA, nil, sharedASUsersA)
	tenantB := sharedASNewTenant(t, sharedASTenantB, asCfg, asDeps, sharedASTenantB, nil, sharedASUsersB)

	for name, resources := range map[string][]string{"tenant B": {sharedASTenantB}, "none": nil} {
		if token, _, authErr := sharedASAuthorizeCode(t, srv, clientKey, now, tenantA, resources...); token != "" || authErr != "access_denied" {
			t.Errorf("a request naming %s: token %v, error %q; want access_denied", name, token != "", authErr)
		}
	}

	for name, resources := range map[string][]string{"tenant A": {sharedASTenantA}, "both": {sharedASTenantB, sharedASTenantA}} {
		token, dpopKey, authErr := sharedASAuthorizeCode(t, srv, clientKey, now, tenantA, resources...)
		if token == "" {
			t.Fatalf("a request naming %s was refused: %s", name, authErr)
		}
		if aud := sharedASAudience(t, token); aud != sharedASTenantA {
			t.Errorf("a request naming %s: aud = %v, want %s", name, aud, sharedASTenantA)
		}
		holderKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if status, resp := sharedASCredentialRequest(t, tenantB, token, dpopKey, holderKey); status != http.StatusUnauthorized || resp["error"] != "invalid_token" {
			t.Errorf("a request naming %s: tenant B answered %d %v, want 401 invalid_token", name, status, resp)
		}
		status, resp := sharedASCredentialRequest(t, tenantA, token, dpopKey, holderKey)
		if status != http.StatusOK || sharedASClaims(t, resp)["holder_name"] != sharedASUsersA["user-42"] {
			t.Errorf("a request naming %s: tenant A answered %d %v", name, status, resp)
		}
	}
}

// AuthorizationResources grants exactly Config.Issuer when the request
// names it; a request naming no resource only when a token addressed to
// the Authorization Server is accepted here.
func TestAuthorizationResources(t *testing.T) {
	const as = "https://as.example.com"
	newIssuer := func(servers, accepted []fapi.URL) *issuer.Issuer {
		cfg := validConfig(t)
		cfg.AuthorizationServers, cfg.AcceptedAccessTokenAudiences = servers, accepted
		return newTestIssuer(t, cfg, validDependencies(t))
	}
	own := newIssuer(nil, nil)
	shared := newIssuer([]fapi.URL{mustAS(t, as)}, nil)
	sole := newIssuer([]fapi.URL{mustAS(t, as)}, []fapi.URL{mustAS(t, as)})

	for name, c := range map[string]struct {
		iss       *issuer.Issuer
		requested []string
		want      []string
	}{
		"this issuer":             {shared, []string{testIssuer}, []string{testIssuer}},
		"this issuer and another": {shared, []string{"https://other.example.com", testIssuer}, []string{testIssuer}},
		"none, its own AS":        {own, nil, nil},
		"none, accepted AS":       {sole, nil, nil},
	} {
		got, err := c.iss.AuthorizationResources(c.requested)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: AuthorizationResources = %v, %v; want %v", name, got, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		iss       *issuer.Issuer
		requested []string
	}{
		"another":           {own, []string{"https://other.example.com"}},
		"a near miss":       {own, []string{testIssuer + "/"}},
		"none, a shared AS": {shared, nil},
	} {
		if got, err := c.iss.AuthorizationResources(c.requested); !errors.Is(err, issuer.ErrResourceNotThisIssuer) || got != nil {
			t.Errorf("%s: AuthorizationResources = %v, %v; want ErrResourceNotThisIssuer", name, got, err)
		}
	}
}

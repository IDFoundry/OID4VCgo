package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// otherResource is another Credential Issuer the Authorization Server
// accepts as a resource in these tests (Config.extraResources).
const otherResource = "https://other-issuer.example.com"

// TestConsent_GrantsOnlyTheCredentialIssuer: with the Authorization
// Server also accepting another resource, an authorization request
// naming the Credential Issuer and the other gets a token for the
// Credential Issuer alone, and one naming only the other is denied at
// the consent step (issuer.Issuer.AuthorizationResources).
func TestConsent_GrantsOnlyTheCredentialIssuer(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.extraResources = []string{otherResource}
	client, cfg, attesterKey, clientKey := setupFullFlowTestWithConfig(t, cfg, "resource-test-client", "resource-test-subject")
	now := time.Now()

	accessToken := performAuthFlowThroughToken(t, client, cfg, attesterKey, clientKey, now, cfg.Issuer, otherResource)
	if aud := accessTokenAudience(t, accessToken); aud != cfg.Issuer {
		t.Errorf("access token aud = %v, want %s alone", aud, cfg.Issuer)
	}

	redirect, _ := authorizeToCallback(t, client, cfg, attesterKey, clientKey, now, otherResource)
	if q := redirect.Query(); q.Get("code") != "" || q.Get("error") != "access_denied" {
		t.Errorf("a request naming only another resource was answered with %s, want error=access_denied", redirect)
	}
}

// TestPreAuthorizedCode_RefusesAnotherResource: a pre-authorized Token
// Request naming any resource but the Credential Issuer is refused with
// invalid_target, leaving the code redeemable; one naming the
// Credential Issuer gets its token.
func TestPreAuthorizedCode_RefusesAnotherResource(t *testing.T) {
	e := startOffersTestServer(t, nil)
	offer, _ := e.offer(t, `{"grant":"pre-authorized_code","credential_configuration_ids":["`+e.cfg.CredentialConfigurationID+`"]}`)
	code := offer.Grants.PreAuthorizedCode.PreAuthorizedCode
	for name, resources := range map[string][]string{
		"another":                           {otherResource},
		"the Credential Issuer and another": {e.cfg.Issuer, otherResource},
		"a near miss":                       {e.cfg.Issuer + "/"},
	} {
		status, body := e.do(t, e.preAuthorizedTokenRequest(t, code, url.Values{"resource": resources}, true))
		if status != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Errorf("a Token Request naming %s: %d %v, want 400 invalid_target", name, status, body)
		}
	}
	status, token := e.do(t, e.preAuthorizedTokenRequest(t, code, url.Values{"resource": {e.cfg.Issuer}}, true))
	if status != http.StatusOK {
		t.Fatalf("a Token Request naming the Credential Issuer: %d %v, want 200", status, token)
	}
	accessToken, _ := token["access_token"].(string)
	if aud := accessTokenAudience(t, accessToken); aud != e.cfg.Issuer {
		t.Errorf("access token aud = %v, want %s", aud, e.cfg.Issuer)
	}
}

// accessTokenAudience is a JWT access token's "aud".
func accessTokenAudience(t *testing.T, accessToken string) any {
	t.Helper()
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token %q isn't a JWT", accessToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims["aud"]
}

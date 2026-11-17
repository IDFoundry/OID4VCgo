package issuer_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

const otherAudience = "https://as.example.com"

// requestWithAudience is requestSDJWTWithProof with the access token's
// audience set to audience.
func requestWithAudience(t *testing.T, f credentialEndpointFixture, audience []string) error {
	t.Helper()
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{
		ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}, Audience: audience,
	}, issuer.CredentialRequest{
		CredentialConfigurationID: testSDJWTConfigID,
		Proofs:                    map[string][]string{oid4vci.ProofTypeJWT: {buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))}},
		SDJWTClaims:               testSDJWTClaims(),
	})
	return err
}

// assertInvalidToken checks err is 401 invalid_token, written with a
// WWW-Authenticate challenge for each scheme.
func assertInvalidToken(t *testing.T, err error) {
	t.Helper()
	assertIssuerError(t, err, issuer.ErrorInvalidToken)
	var ierr *issuer.Error
	if !errors.As(err, &ierr) || ierr.HTTPStatus() != http.StatusUnauthorized {
		t.Fatalf("error = %v, want HTTP 401", err)
	}
	w := httptest.NewRecorder()
	ierr.WriteJSON(w)
	if got := w.Header().Values("WWW-Authenticate"); len(got) != 2 || got[0] != `DPoP error="invalid_token"` || got[1] != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
}

// A token whose audience names the Credential Issuer is accepted, as is
// one whose verifier reported no audience (nil); one naming only
// another audience, or none, is refused as invalid_token.
func TestAccessTokenAudience_RequestCredential(t *testing.T) {
	for name, audience := range map[string][]string{
		"unknown":           nil,
		"this issuer":       {testIssuer},
		"several, this one": {otherAudience, testIssuer},
	} {
		// A fixture each: its c_nonce is used once.
		if err := requestWithAudience(t, newCredentialEndpointFixture(t), audience); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, audience := range map[string][]string{
		"another":  {otherAudience},
		"none":     {},
		"a prefix": {testIssuer + "/tenant"},
	} {
		t.Run(name, func(t *testing.T) {
			assertInvalidToken(t, requestWithAudience(t, newCredentialEndpointFixture(t), audience))
		})
	}
}

// Config.AcceptedAccessTokenAudiences admits a token addressed to the
// Authorization Server it lists, which must be one of
// Config.AuthorizationServers: a co-tenant Credential Issuer's identifier
// is refused.
func TestAccessTokenAudience_AcceptedAudiences(t *testing.T) {
	f := newCredentialEndpointFixture(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.AuthorizationServers = []fapi.URL{mustAS(t, otherAudience)}
		cfg.AcceptedAccessTokenAudiences = []fapi.URL{mustAS(t, otherAudience)}
	})
	if err := requestWithAudience(t, f, []string{otherAudience}); err != nil {
		t.Fatalf("a token addressed to the accepted audience: %v", err)
	}
	assertInvalidToken(t, requestWithAudience(t, f, []string{"https://elsewhere.example.com"}))

	cfg := validConfig(t)
	cfg.AcceptedAccessTokenAudiences = []fapi.URL{{}}
	_, err := issuer.New(cfg, validDependencies(t))
	if err == nil {
		t.Fatal("New accepted an unset accepted_access_token_audiences entry")
	}

	for name, servers := range map[string][]fapi.URL{
		"no authorization_servers":     nil,
		"another authorization server": {mustAS(t, "https://as2.example.com")},
	} {
		cfg := validConfig(t)
		cfg.AuthorizationServers = servers
		cfg.AcceptedAccessTokenAudiences = []fapi.URL{mustAS(t, "https://tenant-b.example.com")}
		if _, err := issuer.New(cfg, validDependencies(t)); err == nil || !strings.Contains(err.Error(), "isn't one of authorization_servers") {
			t.Errorf("%s: New = %v, want an accepted audience outside authorization_servers refused", name, err)
		}
	}
}

// The Deferred Credential and Notification Endpoints refuse a token
// issued for another audience before looking its transaction or
// notification_id up: the transaction stays for a token of this issuer.
func TestAccessTokenAudience_DeferredAndNotification(t *testing.T) {
	ctx := context.Background()
	f := newDeferralFixture(t)
	txID := f.deferIssued(t, deferralAuth, issuer.CredentialRequest{CredentialConfigurationID: testSDJWTConfigID})
	other := deferralAuth
	other.Audience = []string{otherAudience}

	_, err := f.iss.RequestDeferredCredential(ctx, other, issuer.DeferredCredentialRequest{TransactionID: txID})
	assertInvalidToken(t, err)
	err = f.iss.RequestNotification(ctx, other, issuer.NotificationRequest{NotificationID: "n", Event: oid4vci.NotificationEventCredentialAccepted})
	assertInvalidToken(t, err)

	own := deferralAuth
	own.Audience = []string{testIssuer}
	res, err := f.iss.RequestDeferredCredential(ctx, own, issuer.DeferredCredentialRequest{TransactionID: txID})
	if err != nil || len(res.Credentials) != 1 {
		t.Fatalf("poll with this issuer's token = %+v, %v", res, err)
	}
}

// Under AssuranceProduction an AuthorizedRequest without an Audience is
// refused, as a plain error, rather than skipping the audience check.
func TestAccessTokenAudience_RequiredUnderProduction(t *testing.T) {
	cfg, deps := preAuthorizedCodeProductionConfig(t)
	deps.Notifications = assuredNotificationStore{newFakeNotificationStore(), issuer.StoreCapabilities{Durable: true}}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	auth := issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("client-a")}
	var ierr *issuer.Error
	if _, err := iss.IssueNotificationID(ctx, auth); err == nil || errors.As(err, &ierr) || !strings.Contains(err.Error(), "audience is required") {
		t.Errorf("IssueNotificationID without an Audience = %v, want a plain error", err)
	}
	err = iss.RequestNotification(ctx, auth, issuer.NotificationRequest{NotificationID: "n", Event: oid4vci.NotificationEventCredentialAccepted})
	if err == nil || errors.As(err, &ierr) {
		t.Errorf("RequestNotification without an Audience = %v, want a plain error", err)
	}
	auth.Audience = []string{cfg.Issuer.String()}
	if _, err := iss.IssueNotificationID(ctx, auth); err != nil {
		t.Errorf("IssueNotificationID with this issuer's audience: %v", err)
	}
}

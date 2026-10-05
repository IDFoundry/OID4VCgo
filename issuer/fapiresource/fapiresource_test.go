package fapiresource_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
)

// noTokens resolves no access token.
type noTokens struct{}

func (noTokens) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	return resource.ResolvedAccessToken{}, errors.New("unknown token")
}

func TestNewRequiresVerifier(t *testing.T) {
	if _, err := fapiresource.New(nil); err == nil {
		t.Error("New(nil) succeeded, want an error")
	}
}

// TestVerifyRefusesMissingToken checks a request without an access
// token fails, and that the failure is written as resource.WriteError
// writes it. The success path is covered end to end
// by cmd/conformance-issuer's full-flow tests.
func TestVerifyRefusesMissingToken(t *testing.T) {
	rv, err := resource.NewVerifier(resource.Config{
		Assurance: resource.AssuranceDevelopment, Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: time.Minute},
	}, resource.Dependencies{
		AccessTokens: noTokens{}, Replay: memstore.NewReplayStore(),
		Revocation: resource.NoRevocation{}, Clock: resource.SystemClock{},
	})
	if err != nil {
		t.Fatalf("resource.NewVerifier: %v", err)
	}
	v, err := fapiresource.New(rv)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	endpoint, _ := url.Parse("https://issuer.example.com/credential")
	_, err = v.Verify(httptest.NewRequest(http.MethodPost, "/credential", nil), endpoint)
	if err == nil {
		t.Fatal("Verify succeeded without an access token")
	}
	got, want := httptest.NewRecorder(), httptest.NewRecorder()
	v.WriteError(got, err)
	resource.WriteError(want, err)
	if got.Code != want.Code || got.Code < 400 || got.Body.String() != want.Body.String() {
		t.Errorf("WriteError = %d %q, want resource.WriteError's %d %q", got.Code, got.Body, want.Code, want.Body)
	}
}

// certBoundTokens resolves any token to one bound to cert (RFC 8705),
// naming clientID and carrying claims.
type certBoundTokens struct {
	cert     *x509.Certificate
	clientID string
	claims   map[string]json.RawMessage
}

func (c certBoundTokens) ResolveAccessToken(context.Context, resource.ResolveAccessTokenRequest) (resource.ResolvedAccessToken, error) {
	sum := sha256.Sum256(c.cert.Raw)
	return resource.ResolvedAccessToken{
		Subject: "holder-1", ClientID: c.clientID, Scopes: []string{"pid"}, Claims: c.claims,
		ExpiresAt: time.Now().Add(time.Hour), Key: "token-1",
		Thumbprint: base64.RawURLEncoding.EncodeToString(sum[:]), SenderConstrain: storage.SenderConstrainMTLS,
	}, nil
}

// TestVerifyMapsTheToken covers a verified token's mapping onto a
// Grant: its client_id (or NoClientIdentity without one), scopes and
// authorization_details — and a malformed authorization_details.
func TestVerifyMapsTheToken(t *testing.T) {
	ca, caKey := testcert.CA(t, "client CA")
	cert, _ := testcert.Leaf(t, "wallet", ca, caKey)
	endpoint, _ := url.Parse("https://issuer.example.com/credential")
	verify := func(tokens certBoundTokens) (issuer.Grant, error) {
		t.Helper()
		rv, err := resource.NewVerifier(resource.Config{
			Assurance: resource.AssuranceDevelopment, Limits: resource.Limits{MaxDPoPProofAge: time.Minute, MaxClockSkew: time.Minute},
		}, resource.Dependencies{
			AccessTokens: tokens, Replay: memstore.NewReplayStore(),
			Revocation: resource.NoRevocation{}, Clock: resource.SystemClock{},
		})
		if err != nil {
			t.Fatal(err)
		}
		v, err := fapiresource.New(rv)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/credential", nil)
		r.Header.Set("Authorization", "Bearer token-1")
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		return v.Verify(r, endpoint)
	}

	details := `[{"type":"openid_credential","credential_configuration_id":"pid"}]`
	grant, err := verify(certBoundTokens{cert: cert, clientID: "wallet-1", claims: map[string]json.RawMessage{"authorization_details": json.RawMessage(details)}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if grant.Subject != "holder-1" || grant.Authorized.Subject != "holder-1" || grant.Authorized.ClientIdentity != issuer.KnownClientID("wallet-1") ||
		len(grant.Authorized.Scopes) != 1 || len(grant.Authorized.AuthorizationDetails) != 1 ||
		grant.Authorized.AuthorizationDetails[0].CredentialConfigurationID != "pid" {
		t.Errorf("grant = %+v", grant)
	}

	grant, err = verify(certBoundTokens{cert: cert})
	if err != nil {
		t.Fatalf("Verify (no client_id): %v", err)
	}
	if _, ok := grant.Authorized.ClientIdentity.(issuer.NoClientIdentity); !ok {
		t.Errorf("ClientIdentity without a client_id = %#v, want NoClientIdentity", grant.Authorized.ClientIdentity)
	}

	if _, err := verify(certBoundTokens{cert: cert, clientID: "wallet-1", claims: map[string]json.RawMessage{"authorization_details": json.RawMessage(`{"not":"a list"}`)}}); err == nil {
		t.Error("a malformed authorization_details was accepted")
	}
}

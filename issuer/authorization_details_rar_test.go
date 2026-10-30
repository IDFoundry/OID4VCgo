package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// withCredentialAuthorizationDetails has the test Authorization Server
// take openid_credential authorization_details at PAR, as
// oid4vci.AuthorizationDetailRARDefinition declares them, from a client
// registered for the type.
func withCredentialAuthorizationDetails(t *testing.T) func(*server.Config, *server.Dependencies, *storage.RegisteredClientConfig) {
	t.Helper()
	registry, err := extension.NewRARRegistry(8<<10, 6, oid4vci.AuthorizationDetailRARDefinition(2, 4<<10))
	if err != nil {
		t.Fatalf("NewRARRegistry: %v", err)
	}
	return func(cfg *server.Config, deps *server.Dependencies, client *storage.RegisteredClientConfig) {
		cfg.RAR = registry
		deps.AuthorizationCodeRARPolicy = server.AllowRequestedAuthorizationDetails{}
		client.AuthorizationDetailsTypes = []string{oid4vci.AuthorizationDetailsTypeOpenIDCredential}
	}
}

// credentialASFlow is one authorization at a test Authorization Server
// taking openid_credential authorization_details.
type credentialASFlow struct {
	srv       *server.Server
	clientKey *ecdsa.PrivateKey
	now       time.Time
}

// pushCredentialAuthorizationDetails pushes an authorization request
// carrying details as its authorization_details, to a fresh test
// Authorization Server taking them.
func pushCredentialAuthorizationDetails(t *testing.T, details string) (credentialASFlow, server.PushAuthorizationResult, error) {
	t.Helper()
	srv, clientKey, now := newTestAuthorizationServer(t, nil, withCredentialAuthorizationDetails(t))
	params := append(pushedAuthorizationParameters(buildClientAssertion(t, clientKey, now), "state"),
		server.FormParameter{Name: "authorization_details", Value: details})
	result, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: params}})
	return credentialASFlow{srv: srv, clientKey: clientKey, now: now}, result, err
}

// A Wallet's pushed authorization request naming its own
// credential_identifiers is refused with invalid_authorization_details
// (OpenID4VCI 1.0 §6.2: they're the Authorization Server's to issue), so
// none it chose reaches a grant, a token or the Credential Endpoint's
// Prepare.
func TestAuthorizationServerRefusesClientCredentialIdentifiers(t *testing.T) {
	_, _, err := pushCredentialAuthorizationDetails(t,
		`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["victim-dataset"]}]`)
	requireInvalidAuthorizationDetails(t, "PushAuthorizationRequest", err)
}

// requireInvalidAuthorizationDetails fails t unless err is fapigo's
// invalid_authorization_details.
func requireInvalidAuthorizationDetails(t *testing.T, call string, err error) {
	t.Helper()
	var serr *server.Error
	if !errors.As(err, &serr) || serr.Code() != server.ErrorInvalidAuthorizationDetails {
		t.Fatalf("%s = %v, want invalid_authorization_details", call, err)
	}
}

// authorizeCredentialDetails pushes a request for one openid_credential
// object without credential_identifiers, and has consent grant it with
// mint as its identifiers (none for nil). It returns the flow and the
// authorization code issued.
func authorizeCredentialDetails(t *testing.T, mint []string) (credentialASFlow, string) {
	t.Helper()
	flow, result, err := pushCredentialAuthorizationDetails(t,
		`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential"}]`)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	ctx := context.Background()
	action, err := flow.srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: result.RequestURI.String(), ClientID: testASClientID})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		t.Fatalf("BeginAuthorization action = %T, want server.InteractionRequired", action)
	}
	requested, err := extension.RARGet(interaction.Interaction.AuthorizationDetails, oid4vci.AuthorizationDetailRARDefinition(2, 4<<10))
	if err != nil || len(requested) != 1 {
		t.Fatalf("requested authorization_details = %+v, %v", requested, err)
	}
	granted := requested[0].Fields
	granted.Type = oid4vci.AuthorizationDetailsTypeOpenIDCredential
	granted.CredentialIdentifiers = mint
	raw, err := json.Marshal(granted)
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := server.NewSubjectID("holder")
	if err != nil {
		t.Fatal(err)
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		t.Fatal(err)
	}
	authCtx, err := server.NewAuthenticationContext(flow.now, "urn:example:test", nil)
	if err != nil {
		t.Fatal(err)
	}
	done, err := flow.srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: interaction.Interaction.Scope, AuthorizationDetails: []json.RawMessage{raw},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization with identifiers %v: %v", mint, err)
	}
	redirect, ok := done.(server.AuthorizationRedirect)
	if !ok {
		t.Fatalf("CompleteAuthorization = %T, want an AuthorizationRedirect", done)
	}
	destination := redirect.Destination().URL()
	code := destination.Query().Get("code")
	if code == "" {
		t.Fatalf("CompleteAuthorization redirected to %s, without a code", redirect.Destination().String())
	}
	return flow, code
}

// exchange redeems code at the flow's token endpoint, asking for
// details as its authorization_details (none for "").
func (f credentialASFlow) exchange(t *testing.T, code, details string) (server.TokenResult, error) {
	t.Helper()
	params := []server.FormParameter{
		{Name: "grant_type", Value: "authorization_code"},
		{Name: "code", Value: code},
		{Name: "redirect_uri", Value: string(testASRedirectURI)},
		// RFC 7636 Appendix B's verifier for pushedAuthorizationParameters's challenge.
		{Name: "code_verifier", Value: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		{Name: "client_assertion", Value: buildClientAssertion(t, f.clientKey, f.now)},
		{Name: "client_assertion_type", Value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
	}
	if details != "" {
		params = append(params, server.FormParameter{Name: "authorization_details", Value: details})
	}
	return f.srv.ExchangeAuthorizationCode(context.Background(), server.AuthorizationCodeExchangeRequest{
		HTTP: server.FormRequest{Parameters: params}, DPoPProofs: []string{f.tokenDPoPProof(t)},
	})
}

// tokenDPoPProof builds an RFC 9449 §4.2 DPoP proof for a token request
// at the flow's Authorization Server, with a fresh key.
func (f credentialASFlow) tokenDPoPProof(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{"jti": rand.Text(), "htm": "POST", "htu": testASIssuer + "/token", "iat": f.now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt", "jwk": pub}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

// Without credential_identifiers, the request is pushed, and the
// Authorization Server's consent may grant the object with identifiers
// it mints — and only then.
func TestAuthorizationServerGrantsMintedCredentialIdentifiers(t *testing.T) {
	authorizeCredentialDetails(t, []string{"minted-1"})
}

// A token request narrowing its grant (S-31) may not add
// credential_identifiers to a grant that holds none: the code exchange
// is refused with invalid_authorization_details. Exchanging it for the
// grant as it is still works.
func TestAuthorizationServerRefusesTokenRequestCredentialIdentifiers(t *testing.T) {
	flow, code := authorizeCredentialDetails(t, nil)
	_, err := flow.exchange(t, code,
		`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["victim-dataset"]}]`)
	requireInvalidAuthorizationDetails(t, "ExchangeAuthorizationCode adding credential_identifiers", err)

	flow, code = authorizeCredentialDetails(t, nil)
	if _, err := flow.exchange(t, code, `[{"type":"openid_credential","credential_configuration_id":"IdentityCredential"}]`); err != nil {
		t.Fatalf("ExchangeAuthorizationCode for the grant as it is: %v", err)
	}
}

// A token request may keep some of the identifiers its grant holds, or
// drop them, but not name one the grant doesn't hold.
func TestAuthorizationServerNarrowsGrantedCredentialIdentifiers(t *testing.T) {
	for name, tc := range map[string]struct {
		details string
		ok      bool
	}{
		"kept in part":  {`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["minted-2"]}]`, true},
		"dropped":       {`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential"}]`, true},
		"none narrowed": {"", true},
		"another added": {`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["minted-1","victim-dataset"]}]`, false},
	} {
		t.Run(name, func(t *testing.T) {
			flow, code := authorizeCredentialDetails(t, []string{"minted-1", "minted-2"})
			_, err := flow.exchange(t, code, tc.details)
			if tc.ok {
				if err != nil {
					t.Fatalf("ExchangeAuthorizationCode: %v", err)
				}
				return
			}
			requireInvalidAuthorizationDetails(t, "ExchangeAuthorizationCode", err)
		})
	}
}

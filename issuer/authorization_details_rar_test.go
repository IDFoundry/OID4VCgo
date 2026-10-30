package issuer_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo"
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

// pushCredentialAuthorizationDetails pushes an authorization request
// carrying details as its authorization_details, to a fresh test
// Authorization Server taking them.
func pushCredentialAuthorizationDetails(t *testing.T, details string) (*server.Server, time.Time, server.PushAuthorizationResult, error) {
	t.Helper()
	srv, clientKey, now := newTestAuthorizationServer(t, nil, withCredentialAuthorizationDetails(t))
	params := append(pushedAuthorizationParameters(buildClientAssertion(t, clientKey, now), "state"),
		server.FormParameter{Name: "authorization_details", Value: details})
	result, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{HTTP: server.FormRequest{Parameters: params}})
	return srv, now, result, err
}

// A Wallet's pushed authorization request naming its own
// credential_identifiers is refused with invalid_authorization_details
// (OpenID4VCI 1.0 §6.2: they're the Authorization Server's to issue), so
// none it chose reaches a grant, a token or the Credential Endpoint's
// Prepare.
func TestAuthorizationServerRefusesClientCredentialIdentifiers(t *testing.T) {
	_, _, _, err := pushCredentialAuthorizationDetails(t,
		`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["victim-dataset"]}]`)
	var serr *server.Error
	if !errors.As(err, &serr) || serr.Code() != server.ErrorInvalidAuthorizationDetails {
		t.Fatalf("PushAuthorizationRequest = %v, want invalid_authorization_details", err)
	}
}

// Without credential_identifiers, the request is pushed, and the
// Authorization Server's consent may grant the object with identifiers
// it mints — and only then.
func TestAuthorizationServerGrantsMintedCredentialIdentifiers(t *testing.T) {
	srv, now, result, err := pushCredentialAuthorizationDetails(t,
		`[{"type":"openid_credential","credential_configuration_id":"IdentityCredential"}]`)
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	ctx := context.Background()
	action, err := srv.BeginAuthorization(ctx, server.BeginAuthorizationRequest{RequestURI: result.RequestURI.String(), ClientID: testASClientID})
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
	granted.CredentialIdentifiers = []string{"minted-1"}
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
	authCtx, err := server.NewAuthenticationContext(now, "urn:example:test", nil)
	if err != nil {
		t.Fatal(err)
	}
	done, err := srv.CompleteAuthorization(ctx, server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{
			Scope: interaction.Interaction.Scope, AuthorizationDetails: []json.RawMessage{raw},
		}),
	})
	if err != nil {
		t.Fatalf("CompleteAuthorization with minted identifiers: %v", err)
	}
	if _, ok := done.(server.AuthorizationRedirect); !ok {
		t.Fatalf("CompleteAuthorization = %T, want an AuthorizationRedirect", done)
	}
}

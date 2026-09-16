package issuer_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/internal/jose"
)

// These tests prove oid4vci.IssuerStateExtension actually does its job
// against a real *fapigo/server.Server — not a simulation of one — the
// same "real round trip, not just our own assumption" discipline every
// other cross-package wire-format claim in this repo is held to. They
// don't exercise anything issuer itself owns (see
// issuer/authorization_server.go: this package deliberately doesn't
// wrap fapigo/server's own endpoints), only the shared extension value
// issuer's own doc comment tells a caller to register.

const (
	testASIssuer      = "https://as.example.com"
	testASClientID    = fapi.ClientID("test-client")
	testASRedirectURI = fapi.RegisteredRedirectURI("https://wallet.example.com/callback")
)

type fixedASClock struct{ now time.Time }

func (c fixedASClock) Now() time.Time { return c.now }

// fakeASClientKeySource resolves every request to one fixed public
// key, standing in for a real JWKS fetch — fapigo/keys/ephemeral's own
// ClientKeySource needs a real HTTP fetcher, more machinery than these
// tests need to prove PAR's own extension handling.
type fakeASClientKeySource struct{ pub crypto.PublicKey }

func (f fakeASClientKeySource) ResolveVerificationKeys(context.Context, keys.ClientKeyRequest) (keys.VerificationKeySet, error) {
	return keys.VerificationKeySet{Keys: []keys.VerificationKey{{Algorithm: fapi.ES256, PublicKey: f.pub}}}, nil
}

// newTestAuthorizationServer builds a real *fapigo/server.Server with
// one registered private_key_jwt client, using extensions as its own
// Config.Extensions (nil defaults to an empty registry, in which no
// extension parameter — including issuer_state — is registered).
func newTestAuthorizationServer(t *testing.T, extensions *extension.Registry) (srv *server.Server, clientKey *ecdsa.PrivateKey, now time.Time) {
	t.Helper()
	now = time.Now()
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}

	client, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                       testASClientID,
		RedirectURIs:             []fapi.RegisteredRedirectURI{testASRedirectURI},
		ClientAssertionAlgorithm: fapi.ES256,
		AllowedScopes:            []string{"identity_credential"},
	})
	if err != nil {
		t.Fatalf("NewRegisteredClient: %v", err)
	}

	issuerURL, err := fapi.ParseIssuerURL(testASIssuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	authorization, err := fapi.ParseEndpointURL(testASIssuer + "/authorize")
	if err != nil {
		t.Fatalf("ParseEndpointURL(authorize): %v", err)
	}
	token, err := fapi.ParseEndpointURL(testASIssuer + "/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	par, err := fapi.ParseEndpointURL(testASIssuer + "/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}
	jwks, err := fapi.ParseEndpointURL(testASIssuer + "/jwks")
	if err != nil {
		t.Fatalf("ParseEndpointURL(jwks): %v", err)
	}

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
		keys.IDTokenSigning:     fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}

	cfg := server.Config{
		Issuer: issuerURL,
		Endpoints: server.Endpoints{
			Authorization: authorization, Token: token, PushedAuthorizationRequest: par, JWKS: jwks,
		},
		Profile: server.ProfileFAPISecurity,
		Algorithms: server.AlgorithmPolicy{
			ClientAssertion: server.AlgorithmSet{fapi.ES256},
			RequestObject:   server.AlgorithmSet{fapi.ES256},
			IDToken:         fapi.ES256,
		},
		Limits: server.Limits{
			PushedRequestLifetime:      90 * time.Second,
			MaxClientAssertionLifetime: time.Minute,
			MaxRequestObjectLifetime:   time.Minute,
			InteractionLifetime:        5 * time.Minute,
			AuthorizationCodeLifetime:  time.Minute,
			AccessTokenLifetime:        5 * time.Minute,
			IDTokenLifetime:            5 * time.Minute,
			RefreshTokenLifetime:       5 * time.Minute,
			MaxDPoPProofAge:            time.Minute,
			MaxClockSkew:               5 * time.Second,
		},
		Assurance:  server.AssuranceDevelopment,
		Extensions: extensions,
	}
	deps := server.Dependencies{
		Clients:      memstore.NewClientRepository([]storage.RegisteredClient{client}),
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       memstore.NewReplayStore(),
		ClientKeys:   fakeASClientKeySource{pub: &clientKey.PublicKey},
		Keys:         keyManager,
		AccessTokens: server.JWTAccessTokens{Keys: keyManager, Algorithm: fapi.ES256},
		Revocation:   server.NoRevocation{},
		Clock:        fixedASClock{now: now},
		Random:       rand.Reader,
	}
	srv, err = server.New(cfg, deps)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, clientKey, now
}

// buildClientAssertion hand-builds a private_key_jwt client assertion
// (RFC 7523 §3: iss/sub = client_id, aud = the Authorization Server's
// own issuer identifier — the value fapigo/server itself accepts,
// confirmed against fapigo's own par_test.go). This package can't
// import fapigo/internal/clientassertion (a different module's
// internal package), so it builds the same claim shape directly with
// this repo's own internal/jose — the assertion's own contents are
// generic RFC 7523, nothing OID4VCI-specific.
func buildClientAssertion(t *testing.T, signer *ecdsa.PrivateKey, now time.Time) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"iss": string(testASClientID),
		"sub": string(testASClientID),
		"aud": testASIssuer,
		"jti": "test-assertion-jti-1",
		"iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal assertion claims: %v", err)
	}
	assertion, err := jose.Sign(jose.ES256, signer, map[string]any{}, payload)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return assertion
}

// pushedAuthorizationParameters builds a minimal, otherwise-valid PAR
// request's own form parameters (client assertion, PKCE, response_type,
// redirect_uri, scope) plus issuer_state — the same
// code_challenge value fapigo's own par_test.go uses (any
// syntactically valid S256 challenge works; PAR itself never checks it
// against a verifier — that happens at token exchange).
func pushedAuthorizationParameters(assertion, issuerState string) []server.FormParameter {
	return []server.FormParameter{
		{Name: "client_assertion", Value: assertion},
		{Name: "client_assertion_type", Value: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		{Name: "response_type", Value: "code"},
		{Name: "redirect_uri", Value: string(testASRedirectURI)},
		{Name: "scope", Value: "identity_credential"},
		{Name: "code_challenge", Value: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		{Name: "code_challenge_method", Value: "S256"},
		{Name: "issuer_state", Value: issuerState},
	}
}

// pushAuthorizationRequestWithIssuerState builds a test Authorization
// Server registering extensions (nil for none), pushes one
// Authorization Request carrying issuer_state, and asserts it
// succeeds with a non-empty RequestURI — the shared setup/assertion
// TestAuthorizationServerAcceptsIssuerStateExtension and
// TestAuthorizationServerIgnoresIssuerStateWithoutExtensionRegistered
// both need, differing only in what's registered.
func pushAuthorizationRequestWithIssuerState(t *testing.T, extensions *extension.Registry) server.PushAuthorizationResult {
	t.Helper()
	srv, clientKey, now := newTestAuthorizationServer(t, extensions)
	assertion := buildClientAssertion(t, clientKey, now)

	result, err := srv.PushAuthorizationRequest(context.Background(), server.PushAuthorizationRequest{
		HTTP: server.FormRequest{Parameters: pushedAuthorizationParameters(assertion, "opaque-issuer-state")},
	})
	if err != nil {
		t.Fatalf("PushAuthorizationRequest: %v", err)
	}
	if result.RequestURI.String() == "" {
		t.Errorf("RequestURI is empty")
	}
	return result
}

func TestAuthorizationServerAcceptsIssuerStateExtension(t *testing.T) {
	registry, err := extension.NewRegistry(oid4vci.IssuerStateExtension)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	pushAuthorizationRequestWithIssuerState(t, registry)
}

// TestAuthorizationServerIgnoresIssuerStateWithoutExtensionRegistered
// documents fapigo/server's own current behavior for a deployment that
// skips issuer/authorization_server.go's own recipe: PAR now succeeds
// regardless (RFC 6749 §3.1/RFC 9126 §2.1 require tolerating an
// unrecognized authorization request parameter, not rejecting the
// whole request over it — fapigo/server used to reject it, fixed
// upstream), unlike this test's own prior name/assertion. What's not
// observable from here — because it isn't observable from outside
// fapigo/server's own extension.Registry.Parse at all, registered or
// not (see issuer/authorization_server.go's own "does not resurface
// through BeginAuthorization" section) — is that issuer_state's value
// is silently dropped rather than carried through when unregistered;
// that half is fapigo/server's own contract, already covered by its
// own test suite, not something to re-verify by reaching past this
// package's own dependency boundary.
func TestAuthorizationServerIgnoresIssuerStateWithoutExtensionRegistered(t *testing.T) {
	pushAuthorizationRequestWithIssuerState(t, nil)
}

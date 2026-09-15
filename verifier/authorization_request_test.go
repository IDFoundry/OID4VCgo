package verifier_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/verifier"
)

func testQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"https://credentials.example.com/identity_credential"}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{
		Credentials: []dcql.CredentialQuery{{
			ID: "identity_credential", Format: "dc+sd-jwt", Meta: meta,
			Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}}},
		}},
	}
}

// requestObjectPayload is the subset of Request Object claims this
// test asserts on directly.
type requestObjectPayload struct {
	Iss            string     `json:"iss"`
	Aud            string     `json:"aud"`
	ResponseType   string     `json:"response_type"`
	ResponseMode   string     `json:"response_mode"`
	ClientID       string     `json:"client_id"`
	ResponseURI    string     `json:"response_uri"`
	Nonce          string     `json:"nonce"`
	State          string     `json:"state"`
	DCQLQuery      dcql.Query `json:"dcql_query"`
	ClientMetadata struct {
		JWKS struct {
			Keys []struct {
				Kty string `json:"kty"`
				Crv string `json:"crv"`
				X   string `json:"x"`
				Y   string `json:"y"`
				Kid string `json:"kid"`
				Use string `json:"use"`
				Alg string `json:"alg"`
			} `json:"keys"`
		} `json:"jwks"`
		EncValuesSupported []string `json:"encrypted_response_enc_values_supported"`
	} `json:"client_metadata"`
}

// TestBuildAuthorizationRequest drives a real round trip: build a
// signed Request Object, then parse and verify it via internal/jose's
// own production Verify path (mirroring
// issuer/authorization_server_test.go's "real round trip against
// production code on both sides" discipline) — proving the JWS this
// package produces is exactly what a Wallet's own JOSE verification
// would accept.
func TestBuildAuthorizationRequest(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	query := testQuery(t)
	result, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query, State: "state-1"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	if result.ClientID != v.ClientID() {
		t.Errorf("ClientID = %q, want %q", result.ClientID, v.ClientID())
	}
	if result.Nonce == "" {
		t.Errorf("Nonce is empty")
	}
	if result.ResponseDecryptionKey == nil {
		t.Fatalf("ResponseDecryptionKey is nil")
	}

	header, payload, err := jose.Verify(cfg.SigningAlg, deps.Signer.Public(), result.RequestObject)
	if err != nil {
		t.Fatalf("jose.Verify: %v", err)
	}
	if header["typ"] != "oauth-authz-req+jwt" {
		t.Errorf(`header["typ"] = %v, want "oauth-authz-req+jwt"`, header["typ"])
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf(`header["x5c"] = %v, want a one-element array`, header["x5c"])
	}
	wantCert := base64.StdEncoding.EncodeToString(cfg.ClientCertificate.Raw)
	if x5c[0] != wantCert {
		t.Errorf("x5c[0] = %v, want the client certificate's own DER", x5c[0])
	}

	var claims requestObjectPayload
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if claims.ResponseType != "vp_token" {
		t.Errorf("response_type = %q, want vp_token", claims.ResponseType)
	}
	if claims.ResponseMode != "direct_post.jwt" {
		t.Errorf("response_mode = %q, want direct_post.jwt", claims.ResponseMode)
	}
	if claims.ClientID != v.ClientID() {
		t.Errorf("client_id = %q, want %q", claims.ClientID, v.ClientID())
	}
	if claims.Aud != "https://self-issued.me/v2" {
		t.Errorf("aud = %q, want https://self-issued.me/v2", claims.Aud)
	}
	if claims.ResponseURI != cfg.ResponseURI.String() {
		t.Errorf("response_uri = %q, want %q", claims.ResponseURI, cfg.ResponseURI.String())
	}
	if claims.Nonce != result.Nonce {
		t.Errorf("nonce = %q, want %q", claims.Nonce, result.Nonce)
	}
	if claims.State != "state-1" {
		t.Errorf("state = %q, want state-1", claims.State)
	}
	if err := claims.DCQLQuery.Validate(); err != nil {
		t.Errorf("dcql_query round-tripped invalid: %v", err)
	}
	if len(claims.DCQLQuery.Credentials) != 1 || claims.DCQLQuery.Credentials[0].ID != "identity_credential" {
		t.Errorf("dcql_query round-tripped wrong: %+v", claims.DCQLQuery)
	}

	if len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Fatalf("client_metadata.jwks.keys has %d entries, want 1", len(claims.ClientMetadata.JWKS.Keys))
	}
	key := claims.ClientMetadata.JWKS.Keys[0]
	if key.Kty != "EC" || key.Crv != "P-256" || key.X == "" || key.Y == "" {
		t.Errorf("jwks.keys[0] = %+v, want a well-formed P-256 EC JWK", key)
	}
	if key.Kid == "" {
		t.Errorf("jwks.keys[0].kid is empty")
	}
	if key.Use != "enc" {
		t.Errorf("jwks.keys[0].use = %q, want enc", key.Use)
	}
	if key.Alg != "ECDH-ES" {
		t.Errorf("jwks.keys[0].alg = %q, want ECDH-ES", key.Alg)
	}
	if len(claims.ClientMetadata.EncValuesSupported) != 2 {
		t.Errorf("encrypted_response_enc_values_supported = %v, want 2 entries", claims.ClientMetadata.EncValuesSupported)
	}
}

func TestBuildAuthorizationRequestRejectsInvalidQuery(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: dcql.Query{}}); err == nil {
		t.Fatalf("BuildAuthorizationRequest = nil error, want error")
	}
}

func TestBuildAuthorizationRequestOmitsStateWhenEmpty(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	_, payload, err := jose.Verify(cfg.SigningAlg, deps.Signer.Public(), result.RequestObject)
	if err != nil {
		t.Fatalf("jose.Verify: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if _, present := raw["state"]; present {
		t.Errorf(`payload carries "state" when BuildAuthorizationRequestRequest.State was empty`)
	}
}

// TestBuildAuthorizationRequestFreshPerCall confirms nonce and the
// response-encryption key are freshly generated on every call, per
// HAIP §5's own "fresh ephemeral encryption key per Authorization
// Request" MUST.
func TestBuildAuthorizationRequestFreshPerCall(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest (first): %v", err)
	}
	second, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest (second): %v", err)
	}
	if first.Nonce == second.Nonce {
		t.Errorf("nonce repeated across calls: %q", first.Nonce)
	}
	if first.ResponseDecryptionKey.Equal(second.ResponseDecryptionKey) {
		t.Errorf("response decryption key repeated across calls")
	}
}

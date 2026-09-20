package verifier_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/verifier"
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

// requestObjectPayload is the subset of Request Object claims both
// TestBuildAuthorizationRequest and TestBuildDCAPIAuthorizationRequest
// assert on directly — ResponseURI is only ever set by the redirect
// flow, ExpectedOrigins only ever set by the DC API flow.
type requestObjectPayload struct {
	Iss             string                      `json:"iss"`
	Aud             string                      `json:"aud"`
	ResponseType    string                      `json:"response_type"`
	ResponseMode    string                      `json:"response_mode"`
	ClientID        string                      `json:"client_id"`
	ResponseURI     string                      `json:"response_uri"`
	ExpectedOrigins []string                    `json:"expected_origins"`
	Nonce           string                      `json:"nonce"`
	State           string                      `json:"state"`
	DCQLQuery       dcql.Query                  `json:"dcql_query"`
	ClientMetadata  requestObjectClientMetadata `json:"client_metadata"`
}

// requestObjectClientMetadata mirrors requestObjectPayload's own
// "client_metadata" member — split out from an inline anonymous struct
// purely for readability, the field/tag shape is unchanged.
type requestObjectClientMetadata struct {
	JWKS               requestObjectJWKS `json:"jwks"`
	EncValuesSupported []string          `json:"encrypted_response_enc_values_supported"`
}

type requestObjectJWKS struct {
	Keys []requestObjectJWK `json:"keys"`
}

type requestObjectJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
}

// verifyAndParseRequestObject verifies requestObject via internal/jose's
// own production Verify path (mirroring
// issuer/authorization_server_test.go's "real round trip against
// production code on both sides" discipline) — proving the JWS
// BuildAuthorizationRequest/BuildDCAPIAuthorizationRequest produce is
// exactly what a Wallet's own JOSE verification would accept — checks
// the header's own "typ"/"x5c" (identical for both flows, since both
// sign via the shared signRequestObject), and unmarshals the payload
// into requestObjectPayload.
func verifyAndParseRequestObject(t *testing.T, cfg verifier.Config, deps verifier.Dependencies, requestObject string) requestObjectPayload {
	t.Helper()
	header, payload, err := jose.Verify(cfg.SigningAlg, deps.Signer.Public(), requestObject)
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
	return claims
}

// TestBuildAuthorizationRequest drives a real round trip: build a
// signed Request Object and verify its own claims.
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
	checkBuildAuthorizationRequestResult(t, v, result)

	claims := verifyAndParseRequestObject(t, cfg, deps, result.RequestObject)
	checkRequestObjectClaims(t, v, cfg, claims, result)
	checkRequestObjectClientMetadataJWKS(t, claims)
}

// checkBuildAuthorizationRequestResult, checkRequestObjectClaims, and
// checkRequestObjectClientMetadataJWKS are TestBuildAuthorizationRequest's
// own assertion chain, split into top-level helpers purely to keep
// that function under the linter's own cognitive complexity ceiling.
func checkBuildAuthorizationRequestResult(t *testing.T, v *verifier.Verifier, result verifier.BuildAuthorizationRequestResult) {
	t.Helper()
	if result.ClientID != v.ClientID() {
		t.Errorf("ClientID = %q, want %q", result.ClientID, v.ClientID())
	}
	if result.Nonce == "" {
		t.Errorf("Nonce is empty")
	}
	if result.ResponseDecryptionKey == nil {
		t.Fatalf("ResponseDecryptionKey is nil")
	}
}

func checkRequestObjectClaims(t *testing.T, v *verifier.Verifier, cfg verifier.Config, claims requestObjectPayload, result verifier.BuildAuthorizationRequestResult) {
	t.Helper()
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
}

func checkRequestObjectClientMetadataJWKS(t *testing.T, claims requestObjectPayload) {
	t.Helper()
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

// TestBuildDCAPIAuthorizationRequest drives the same kind of real
// round trip TestBuildAuthorizationRequest does, checking exactly what
// differs for the DC API flow (Appendix A.3.2.1): "response_mode" is
// "dc_api.jwt" rather than "direct_post.jwt", "expected_origins" is
// present rather than "response_uri", and "response_uri" itself is
// absent entirely. Coverage for the mechanics both flows share
// (nonce/response-encryption-key freshness, state omission when
// empty, header shape) lives on TestBuildAuthorizationRequest's own
// side — signRequestObject/buildResponseEncryptionMetadata/randomToken
// are the same code paths regardless of which Build*Request method
// calls them, so there's nothing flow-specific left to re-prove here.
func TestBuildDCAPIAuthorizationRequest(t *testing.T) {
	cfg, deps, v := newTestVerifierWithConfig(t)

	query := testQuery(t)
	result, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{"https://verifier.example.com"}, State: "state-1",
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}
	if result.ClientID != v.ClientID() {
		t.Errorf("ClientID = %q, want %q", result.ClientID, v.ClientID())
	}
	if result.ResponseDecryptionKey == nil {
		t.Fatalf("ResponseDecryptionKey is nil")
	}

	claims := verifyAndParseRequestObject(t, cfg, deps, result.RequestObject)
	if claims.ResponseMode != "dc_api.jwt" {
		t.Errorf("response_mode = %q, want dc_api.jwt", claims.ResponseMode)
	}
	if len(claims.ExpectedOrigins) != 1 || claims.ExpectedOrigins[0] != "https://verifier.example.com" {
		t.Errorf("expected_origins = %v, want [https://verifier.example.com]", claims.ExpectedOrigins)
	}
	if claims.ResponseURI != "" {
		t.Errorf("response_uri = %q, want empty (not a DC API parameter)", claims.ResponseURI)
	}
	if claims.ClientID != v.ClientID() {
		t.Errorf("client_id = %q, want %q", claims.ClientID, v.ClientID())
	}
	if claims.Nonce != result.Nonce {
		t.Errorf("nonce = %q, want %q", claims.Nonce, result.Nonce)
	}
	if len(claims.ClientMetadata.JWKS.Keys) != 1 {
		t.Errorf("client_metadata.jwks.keys has %d entries, want 1", len(claims.ClientMetadata.JWKS.Keys))
	}
}

func TestBuildDCAPIAuthorizationRequestRejectsInvalidQuery(t *testing.T) {
	v := newTestVerifier(t)
	req := verifier.BuildDCAPIAuthorizationRequestRequest{Query: dcql.Query{}, ExpectedOrigins: []string{"https://verifier.example.com"}}
	if _, err := v.BuildDCAPIAuthorizationRequest(req); err == nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest = nil error, want error")
	}
}

func TestBuildDCAPIAuthorizationRequestRejectsMissingExpectedOrigins(t *testing.T) {
	v := newTestVerifier(t)
	req := verifier.BuildDCAPIAuthorizationRequestRequest{Query: testQuery(t)}
	if _, err := v.BuildDCAPIAuthorizationRequest(req); err == nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest = nil error, want error")
	}
}

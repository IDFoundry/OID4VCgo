package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// clientAttestationTypHeader/clientAttestationPoPTypHeader are the
// required JOSE "typ" header values draft-ietf-oauth-attestation-based-
// client-auth-07 §5.1/§5.2 define — confirmed against FAPIgo's own
// (unexported) internal/clientattestation.TypHeader/PoPTypHeader, so
// hardcoded here rather than imported.
const (
	clientAttestationTypHeader    = "oauth-client-attestation+jwt"
	clientAttestationPoPTypHeader = "oauth-client-attestation-pop+jwt"
	dpopProofTypHeader            = "dpop+jwt"
	credentialProofTypHeader      = "openid4vci-proof+jwt"
)

// buildClientAttestationJWT builds a Client Attestation JWT (draft-07
// §5.1): signed by the attester's own key, naming clientID as its
// subject and clientInstanceKey (the client's own key, not the
// attester's) as its cnf.jwk confirmation key — confirmed against
// FAPIgo's own (unexported) internal/clientattestation.attestationClaims.
func buildClientAttestationJWT(attesterKey *ecdsa.PrivateKey, attesterKid, attesterIssuer, clientID string, clientInstanceKey *ecdsa.PublicKey, now time.Time) (string, error) {
	instanceJWK, err := jwk.Marshal(clientInstanceKey)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": attesterIssuer, "sub": clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": instanceJWK},
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, attesterKey, map[string]any{"typ": clientAttestationTypHeader, "kid": attesterKid}, payload)
}

// buildClientAttestationPoPJWT builds a Client Attestation PoP JWT
// (draft-07 §5.2): signed by the Client Instance Key the paired
// Attestation names, proving possession of it for this one request.
// audience is the Authorization Server's own issuer identifier (not a
// specific endpoint URL — draft-07 grants this JWT no endpoint-URL
// carve-out, confirmed against FAPIgo's own PoPVerifyPolicy.ExpectedAudience
// doc comment).
func buildClientAttestationPoPJWT(clientInstanceKey *ecdsa.PrivateKey, clientID, audience, jti string, now time.Time) (string, error) {
	payload, err := json.Marshal(map[string]any{
		"iss": clientID, "aud": audience, "jti": jti, "iat": now.Unix(),
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, clientInstanceKey, map[string]any{"typ": clientAttestationPoPTypHeader}, payload)
}

// buildDPoPProof builds an RFC 9449 §4.2 DPoP proof — a local
// equivalent of wallet.GenerateDPoPProof (that method needs a fully
// constructed *wallet.Wallet, more setup than this one-off test
// warrants). ath is the presented access token's own base64url(SHA-256(...))
// digest (§4.3) — required whenever this proof accompanies a
// DPoP-scheme Authorization header (the Credential Endpoint call),
// empty for PAR/token where no access token exists yet.
func buildDPoPProof(key *ecdsa.PrivateKey, htm, htu, jti, ath string, now time.Time) (string, error) {
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return "", err
	}
	body := map[string]any{"jti": jti, "htm": htm, "htu": htu, "iat": now.Unix()}
	if ath != "" {
		body["ath"] = ath
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, key, map[string]any{"typ": dpopProofTypHeader, "jwk": pub}, payload)
}

// buildCredentialProofJWT builds a jwt-type key proof (OID4VCI 1.0
// Appendix F.1) binding holderKey to this Credential Request.
func buildCredentialProofJWT(holderKey *ecdsa.PrivateKey, clientID, audience, nonce string, now time.Time) (string, error) {
	pub, err := jwk.Marshal(&holderKey.PublicKey)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"iss": clientID, "aud": audience, "iat": now.Unix(), "nonce": nonce,
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(jose.ES256, holderKey, map[string]any{"typ": credentialProofTypHeader, "jwk": pub}, payload)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// startTestIssuerServer sets cfg.Issuer from a fresh TLS listener
// address, builds this binary's own real newServerMux from *cfg, and
// starts serving — shared setup for every full-flow-style test in
// this file.
func startTestIssuerServer(t *testing.T, cfg *Config) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	cfg.Issuer = "https://" + ts.Listener.Addr().String()
	mux, err := newServerMux(*cfg)
	if err != nil {
		t.Fatalf("newServerMux: %v", err)
	}
	ts.Config.Handler = mux
	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

// clientAttestationHeaders builds the OAuth-Client-Attestation/-PoP
// header pair (draft-07 §4) for one request as cc, signed by
// attesterKey/attesterKid and proving possession of clientInstanceKey
// — audience is always the Authorization Server's own issuer
// identifier (issuerURL), never a specific endpoint URL (see
// buildClientAttestationPoPJWT's own doc comment), so this same pair
// works for both PAR and token requests.
func clientAttestationHeaders(t *testing.T, attesterKey *ecdsa.PrivateKey, attesterKid string, cc ConfigClient, clientInstanceKey *ecdsa.PrivateKey, issuerURL string, now time.Time) http.Header {
	t.Helper()
	attJWT, err := buildClientAttestationJWT(attesterKey, attesterKid, cc.ExpectedAttesterIssuer, cc.ID, &clientInstanceKey.PublicKey, now)
	if err != nil {
		t.Fatalf("buildClientAttestationJWT: %v", err)
	}
	popJWT, err := buildClientAttestationPoPJWT(clientInstanceKey, cc.ID, issuerURL, randomHex(t, 16), now)
	if err != nil {
		t.Fatalf("buildClientAttestationPoPJWT: %v", err)
	}
	h := http.Header{}
	h.Set("OAuth-Client-Attestation", attJWT)
	h.Set("OAuth-Client-Attestation-PoP", popJWT)
	return h
}

// performPAR drives one PAR request as cc — PKCE, a DPoP proof, and
// a Client Attestation + PoP JWT pair, all real — and returns the
// parsed JSON response (via doJSON, which already fails the test on a
// non-2xx status).
func performPAR(t *testing.T, client *http.Client, issuerURL, scope, codeChallenge string, cc ConfigClient, attesterKey *ecdsa.PrivateKey, attesterKid string, clientInstanceKey *ecdsa.PrivateKey, now time.Time) map[string]any {
	t.Helper()
	parURL := issuerURL + "/par"
	parDPoP, err := buildDPoPProof(clientInstanceKey, http.MethodPost, parURL, randomHex(t, 16), "", now)
	if err != nil {
		t.Fatalf("buildDPoPProof (par): %v", err)
	}
	parForm := url.Values{
		"response_type": {"code"}, "client_id": {cc.ID},
		"redirect_uri": {cc.RedirectURIs[0]}, "scope": {scope},
		"code_challenge": {codeChallenge}, "code_challenge_method": {"S256"},
	}
	parReq, err := http.NewRequest(http.MethodPost, parURL, strings.NewReader(parForm.Encode()))
	if err != nil {
		t.Fatalf("new par request: %v", err)
	}
	parReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	parReq.Header.Set("DPoP", parDPoP)
	for k, v := range clientAttestationHeaders(t, attesterKey, attesterKid, cc, clientInstanceKey, issuerURL, now) {
		parReq.Header[k] = v
	}
	return doJSON(t, client, parReq)
}

// pkceChallenge generates a fresh PKCE code_verifier/code_challenge
// pair (S256).
func pkceChallenge(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = randomHex(t, 32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestFullFlow_ParAuthorizeTokenNonceCredential drives
// cmd/conformance-issuer's entire stack — PAR, the consent-form
// authorize/decision round trip, the token endpoint (Client
// Attestation + PoP JWT authentication, DPoP sender-constraining), the
// Nonce Endpoint, and finally the Credential Endpoint — end to end
// against a real newServerMux instance. This is the flow
// README.md's own "Status" section previously flagged as unexercised;
// building it surfaced a real bug (par.go/token.go never forwarded the
// OAuth-Client-Attestation/-PoP headers to fapigo/server at all — fixed
// alongside this test).
// performAuthFlowThroughNonce drives PAR → GET /authorize → POST
// /authorize/decision → POST /token → POST /nonce for cfg's own
// registered client (attesterKey/clientKey identify it, matching
// performPAR's own parameter shape), returning the access token and
// c_nonce a POST /credential request needs next. Factored out of
// TestFullFlow_ParAuthorizeTokenNonceCredential so
// TestFullFlow_BatchIssuanceReturnsOneCredentialPerProof doesn't
// duplicate this same ~80-line sequence just to reach a different
// credential-request shape.
func performAuthFlowThroughNonce(t *testing.T, client *http.Client, cfg Config, attesterKey, clientKey *ecdsa.PrivateKey, now time.Time) (accessToken, cNonce string) {
	t.Helper()

	// PKCE
	verifier, challenge := pkceChallenge(t)

	// --- PAR ---
	parResp := performPAR(t, client, cfg.Issuer, cfg.Scope, challenge, cfg.Client, attesterKey, "attester-1", clientKey, now)
	requestURI, _ := parResp["request_uri"].(string)
	if requestURI == "" {
		t.Fatalf("par response has no request_uri: %+v", parResp)
	}

	// --- GET /authorize, POST /authorize/decision ---
	authorizeURL := cfg.Issuer + "/authorize?" + url.Values{
		"client_id": {cfg.Client.ID}, "request_uri": {requestURI},
	}.Encode()
	redirectURL := driveConsentToCallback(t, client, cfg.Issuer, authorizeURL, cfg.DefaultSubject, cfg.Scope)
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect location has no code: %s (error=%s)", redirectURL, redirectURL.Query().Get("error"))
	}

	// --- POST /token ---
	tokenURL := cfg.Issuer + "/token"
	tokenDPoP, err := buildDPoPProof(clientKey, http.MethodPost, tokenURL, randomHex(t, 16), "", now)
	if err != nil {
		t.Fatalf("buildDPoPProof (token): %v", err)
	}
	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {cfg.Client.RedirectURIs[0]}, "code_verifier": {verifier},
		"client_id": {cfg.Client.ID},
	}
	tokenReq, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("new token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("DPoP", tokenDPoP)
	for k, v := range clientAttestationHeaders(t, attesterKey, "attester-1", cfg.Client, clientKey, cfg.Issuer, now) {
		tokenReq.Header[k] = v
	}
	tokenResp := doJSON(t, client, tokenReq)
	accessToken, _ = tokenResp["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("token response has no access_token: %+v", tokenResp)
	}

	// --- POST /nonce ---
	nonceReq, err := http.NewRequest(http.MethodPost, cfg.Issuer+"/nonce", http.NoBody)
	if err != nil {
		t.Fatalf("new nonce request: %v", err)
	}
	nonceResp := doJSON(t, client, nonceReq)
	cNonce, _ = nonceResp["c_nonce"].(string)
	if cNonce == "" {
		t.Fatalf("nonce response has no c_nonce: %+v", nonceResp)
	}
	return accessToken, cNonce
}

// driveConsentToCallback drives the headless consent step against
// issuer's own consent UI — GET authorizeURL, then POST
// /authorize/decision approving as subject for scope — and returns the
// resulting redirect URL (the "code"/"state"/"iss" callback a real
// browser session would land on). Shared by performAuthFlowThroughNonce
// (this file's own raw-HTTP wallet simulation) and
// TestFullFlow_RealClientDrivesAttestationAuth (a real fapigo/client
// wallet): driving an actual browser has no fapigo/client equivalent
// either way, so both reuse this one sequence rather than each
// hand-rolling their own copy.
func driveConsentToCallback(t *testing.T, httpClient *http.Client, issuer, authorizeURL, subject, scope string) *url.URL {
	t.Helper()
	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL, nil)
	if err != nil {
		t.Fatalf("new authorize request: %v", err)
	}
	authorizeResp, err := httpClient.Do(authorizeReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_, _ = io.Copy(io.Discard, authorizeResp.Body)
	_ = authorizeResp.Body.Close()
	handle := authorizeResp.Header.Get("X-Interaction-Handle")
	if handle == "" {
		t.Fatalf("GET /authorize: missing X-Interaction-Handle (status %d)", authorizeResp.StatusCode)
	}

	decisionClient := &http.Client{
		Transport:     httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	decisionForm := url.Values{"handle": {handle}, "subject": {subject}, "decision": {"approve"}, "scope": {scope}}
	decisionReq, err := http.NewRequest(http.MethodPost, issuer+"/authorize/decision", strings.NewReader(decisionForm.Encode()))
	if err != nil {
		t.Fatalf("new decision request: %v", err)
	}
	decisionReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	decisionResp, err := decisionClient.Do(decisionReq)
	if err != nil {
		t.Fatalf("POST /authorize/decision: %v", err)
	}
	decisionBody, _ := io.ReadAll(decisionResp.Body)
	_ = decisionResp.Body.Close()
	location := decisionResp.Header.Get("Location")
	if location == "" {
		t.Fatalf("POST /authorize/decision: no redirect Location (status %d, body %s)", decisionResp.StatusCode, decisionBody)
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect location %q: %v", location, err)
	}
	return redirectURL
}

// setupFullFlowTest builds the plumbing every full-flow test in this
// file needs before it can drive PAR: an http.Client trusting this
// test's own throwaway TLS listener, a fresh attester/client-instance
// key pair, a registered client (clientID/defaultSubject) with a
// matching attester JWKS, and a running startTestIssuerServer
// instance. Each test still generates its own holder key(s) — how
// many it needs (1 vs N for a batch) is the one thing that actually
// varies between callers.
func setupFullFlowTest(t *testing.T, clientID, defaultSubject string) (client *http.Client, cfg Config, attesterKey, clientKey *ecdsa.PrivateKey) {
	t.Helper()
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener

	var err error
	attesterKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	clientKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-1")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}

	cfg = baseTestConfig(t)
	cfg.Client.ID = clientID
	cfg.Client.RedirectURIs = []string{"https://client.example.com/callback"}
	cfg.Client.ExpectedAttesterIssuer = "https://attester.example.com"
	cfg.Client.AttesterJWKS = attesterJWKS
	cfg.DefaultSubject = defaultSubject

	startTestIssuerServer(t, &cfg)
	return client, cfg, attesterKey, clientKey
}

func TestFullFlow_ParAuthorizeTokenNonceCredential(t *testing.T) {
	now := time.Now()
	client, cfg, attesterKey, clientKey := setupFullFlowTest(t, "smoke-test-client", "smoke-test-subject")
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}

	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)

	// --- POST /credential ---
	proofJWT, err := buildCredentialProofJWT(holderKey, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT: %v", err)
	}
	credentialResp := postCredentialRequest(t, client, cfg, clientKey, accessToken, now, map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT}},
	})
	credentials, _ := credentialResp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credential response has %d credentials, want 1: %+v", len(credentials), credentialResp)
	}
	payload := decodeIssuedSDJWTPayload(t, credentials[0])
	if _, ok := payload["exp"]; !ok {
		t.Error("issued credential has no exp claim")
	}
}

// buildCredentialRequest builds a POST /credential *http.Request
// against cfg's own Credential Endpoint, with a fresh DPoP proof
// (RFC 9449 §4.2's own "ath" binding it to accessToken) and
// Authorization header — the shared HTTP-request-building primitive
// every full-flow test's own final step needs, regardless of body
// content type (plain JSON, or an encrypted JWE compact
// serialization for §10's own encrypted requests).
func buildCredentialRequest(t *testing.T, cfg Config, clientKey *ecdsa.PrivateKey, accessToken, contentType string, body []byte, now time.Time) *http.Request {
	t.Helper()
	credentialURL := cfg.Issuer + "/credential"
	athSum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(athSum[:])
	credentialDPoP, err := buildDPoPProof(clientKey, http.MethodPost, credentialURL, randomHex(t, 16), ath, now)
	if err != nil {
		t.Fatalf("buildDPoPProof (credential): %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, credentialURL, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new credential request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "DPoP "+accessToken)
	req.Header.Set("DPoP", credentialDPoP)
	return req
}

// postCredentialRequest POSTs body (already carrying
// credential_configuration_id/credential_identifier and proofs) as
// plain JSON and decodes the (also plain-JSON) response — the shape
// every full-flow test used before §10 encryption support existed,
// still used by every test that doesn't exercise encryption.
func postCredentialRequest(t *testing.T, client *http.Client, cfg Config, clientKey *ecdsa.PrivateKey, accessToken string, now time.Time, body map[string]any) map[string]any {
	t.Helper()
	credentialBody, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal credential request: %v", err)
	}
	req := buildCredentialRequest(t, cfg, clientKey, accessToken, "application/json", credentialBody, now)
	return doJSON(t, client, req)
}

// decodeIssuedSDJWTPayload decodes one credentials[i] response entry
// (an any wrapping {"credential": "<sd-jwt>~..."}) into its issuer
// JWT's own claims — shared by every full-flow test that inspects an
// issued credential's own payload, whether from a single-credential or
// batch response.
func decodeIssuedSDJWTPayload(t *testing.T, entry any) map[string]any {
	t.Helper()
	credentialEntry, _ := entry.(map[string]any)
	issuedSDJWT, _ := credentialEntry["credential"].(string)
	issuerJWT, _, _ := strings.Cut(issuedSDJWT, "~")
	_, rawPayload, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return payload
}

// TestFullFlow_BatchIssuanceReturnsOneCredentialPerProof proves this
// binary's own real HTTP path — not just issuer.RequestCredential's
// already-tested internals — actually issues a distinct Credential per
// proof when a Credential Request's own "proofs" array holds more than
// one: OID4VCI §3.3.2's own batch issuance shape, now wired in via
// wiring.go's conformanceBatchSize (see its own doc comment). Sends 2
// jwt proofs bound to 2 different holder keys and asserts exactly 2
// credentials come back, in the same order, each cryptographically
// bound (via its own "cnf.jwk" claim) to its own proof's key — not to
// the other one, and not both to the same key.
func TestFullFlow_BatchIssuanceReturnsOneCredentialPerProof(t *testing.T) {
	now := time.Now()
	client, cfg, attesterKey, clientKey := setupFullFlowTest(t, "batch-test-client", "batch-test-subject")
	holderKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key 1: %v", err)
	}
	holderKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key 2: %v", err)
	}

	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)

	// --- POST /credential, 2 proofs in one request ---
	proofJWT1, err := buildCredentialProofJWT(holderKey1, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT (1): %v", err)
	}
	proofJWT2, err := buildCredentialProofJWT(holderKey2, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT (2): %v", err)
	}
	credentialResp := postCredentialRequest(t, client, cfg, clientKey, accessToken, now, map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT1, proofJWT2}},
	})
	credentials, _ := credentialResp["credentials"].([]any)
	if len(credentials) != 2 {
		t.Fatalf("credential response has %d credentials, want 2: %+v", len(credentials), credentialResp)
	}

	holderJWK1, err := jwk.Marshal(&holderKey1.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal (1): %v", err)
	}
	holderJWK2, err := jwk.Marshal(&holderKey2.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal (2): %v", err)
	}
	wantCNFX := []string{holderJWK1.X, holderJWK2.X}
	if wantCNFX[0] == wantCNFX[1] {
		t.Fatal("test bug: both holder keys have the same x — regenerate")
	}
	for i, entry := range credentials {
		payload := decodeIssuedSDJWTPayload(t, entry)
		cnf, _ := payload["cnf"].(map[string]any)
		jwkVal, _ := cnf["jwk"].(map[string]any)
		gotX, _ := jwkVal["x"].(string)
		if gotX != wantCNFX[i] {
			t.Errorf("credential %d: cnf.jwk.x = %q, want %q (proof %d's own holder key)", i, gotX, wantCNFX[i], i)
		}
	}
}

// TestFullFlow_EncryptedCredentialRequestAndResponse proves this
// binary's own real HTTP path genuinely supports OID4VCI §10 in both
// directions, not just issuer/encryption.go's own already-tested
// internals: encrypts a Credential Request as a JWE addressed to this
// issuer's own published request-decryption key (found via
// cfg.credentialRequestDecryptionKey(), the exact key
// wiring.go's own credentialRequestDecryptionKeyID publishes), asks
// for an encrypted Response via a fresh "Wallet" key in
// credential_response_encryption, and decrypts the issuer's own
// response with that same key — a full encrypt→issue→encrypt→decrypt
// round trip through the real binary, not a mock of either side.
// setupEncryptedCredentialRequestTest drives setupFullFlowTest +
// performAuthFlowThroughNonce + a single jwt-type proof for every
// full-flow test in this file that POSTs an *encrypted* Credential
// Request — the shared plumbing every one of them needs before it can
// build its own plaintext body (they differ only in exactly what that
// body contains, and what outer "enc" it gets encrypted with).
func setupEncryptedCredentialRequestTest(t *testing.T, clientID, defaultSubject string) (client *http.Client, cfg Config, clientKey, requestDecryptionKey *ecdsa.PrivateKey, accessToken, proofJWT string, now time.Time) {
	t.Helper()
	now = time.Now()
	var attesterKey *ecdsa.PrivateKey
	client, cfg, attesterKey, clientKey = setupFullFlowTest(t, clientID, defaultSubject)
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	requestDecryptionKey, err = cfg.credentialRequestDecryptionKey()
	if err != nil {
		t.Fatalf("credentialRequestDecryptionKey: %v", err)
	}
	var cNonce string
	accessToken, cNonce = performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)
	proofJWT, err = buildCredentialProofJWT(holderKey, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT: %v", err)
	}
	return client, cfg, clientKey, requestDecryptionKey, accessToken, proofJWT, now
}

// buildWalletResponseEncryptionKey generates a fresh ephemeral P-256
// "Wallet" key for credential_response_encryption, returning both its
// own private key (needed to decrypt a real response back) and its
// wire JWK. bogusAlg, when non-empty, is embedded as the JWK's own
// "alg" member — reproducing the OIDF suite's own literal
// "UNSUPPORTED_ALG" probe for a Wallet-declared alg this issuer can't
// honor.
func buildWalletResponseEncryptionKey(t *testing.T, bogusAlg string) (walletKey *ecdsa.PrivateKey, walletJWK json.RawMessage) {
	t.Helper()
	walletKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate wallet response-encryption key: %v", err)
	}
	pubJWK, err := jwk.Marshal(&walletKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	if bogusAlg == "" {
		raw, err := json.Marshal(pubJWK)
		if err != nil {
			t.Fatalf("marshal wallet jwk: %v", err)
		}
		return walletKey, raw
	}
	raw, err := json.Marshal(struct {
		jwk.JWK
		Alg string `json:"alg"`
	}{JWK: pubJWK, Alg: bogusAlg})
	if err != nil {
		t.Fatalf("marshal wallet jwk with alg: %v", err)
	}
	return walletKey, raw
}

// encryptAndPostCredentialRequest marshals plaintextBody, encrypts it
// to requestDecryptionKey's own public half with outerEnc (the JWE
// "enc" the *outer* Credential Request encryption itself uses), and
// POSTs it — the one request-building sequence every encrypted-request
// test in this file shares, regardless of what's actually under test
// inside plaintextBody or outerEnc.
func encryptAndPostCredentialRequest(t *testing.T, client *http.Client, cfg Config, clientKey, requestDecryptionKey *ecdsa.PrivateKey, accessToken string, outerEnc jwe.Enc, plaintextBody map[string]any, now time.Time) *http.Response {
	t.Helper()
	body, err := json.Marshal(plaintextBody)
	if err != nil {
		t.Fatalf("marshal plaintext credential request: %v", err)
	}
	encryptedBody, err := jwe.Encrypt(&requestDecryptionKey.PublicKey, outerEnc, body, jwe.EncryptOptions{KeyID: credentialRequestDecryptionKeyID})
	if err != nil {
		t.Fatalf("jwe.Encrypt (request): %v", err)
	}
	req := buildCredentialRequest(t, cfg, clientKey, accessToken, "application/jwt", []byte(encryptedBody), now)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /credential: %v", err)
	}
	return resp
}

func TestFullFlow_EncryptedCredentialRequestAndResponse(t *testing.T) {
	client, cfg, clientKey, requestDecryptionKey, accessToken, proofJWT, now := setupEncryptedCredentialRequestTest(t, "encryption-test-client", "encryption-test-subject")
	walletKey, walletJWK := buildWalletResponseEncryptionKey(t, "")

	resp := encryptAndPostCredentialRequest(t, client, cfg, clientKey, requestDecryptionKey, accessToken, jwe.A128GCM, map[string]any{
		"credential_configuration_id":    cfg.CredentialConfigurationID,
		"proofs":                         map[string][]string{"jwt": {proofJWT}},
		"credential_response_encryption": map[string]any{"jwk": walletJWK, "enc": "A128GCM"},
	}, now)
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /credential: status %d: %s", resp.StatusCode, respBody)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("Content-Type = %q, want application/jwt", ct)
	}

	decrypted, err := jwe.Decrypt(walletKey, string(respBody))
	if err != nil {
		t.Fatalf("jwe.Decrypt (response): %v", err)
	}
	var credentialResp map[string]any
	if err := json.Unmarshal(decrypted, &credentialResp); err != nil {
		t.Fatalf("unmarshal decrypted response: %v", err)
	}
	credentials, _ := credentialResp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credential response has %d credentials, want 1: %+v", len(credentials), credentialResp)
	}
	payload := decodeIssuedSDJWTPayload(t, credentials[0])
	if _, ok := payload["exp"]; !ok {
		t.Error("issued credential has no exp claim")
	}
}

// TestFullFlow_CredentialRequestRejectsUnsupportedEncAlgorithm mirrors
// the OIDF suite's own fail-unsupported-encryption-algorithm module
// locally: encrypts a well-formed Credential Request with A192GCM —
// an enc value internal/jwe genuinely implements, but this binary's
// own wiring.go deliberately never advertises or accepts (see
// credentialEncValuesSupported's own doc comment) — and asserts the
// binary rejects it outright rather than silently accepting an
// algorithm it never offered.
func TestFullFlow_CredentialRequestRejectsUnsupportedEncAlgorithm(t *testing.T) {
	client, cfg, clientKey, requestDecryptionKey, accessToken, proofJWT, now := setupEncryptedCredentialRequestTest(t, "encryption-fail-test-client", "encryption-fail-test-subject")

	resp := encryptAndPostCredentialRequest(t, client, cfg, clientKey, requestDecryptionKey, accessToken, jwe.A192GCM, map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT}},
	}, now)
	defer func() { _ = resp.Body.Close() }()
	assertCredentialErrorCode(t, resp, "invalid_encryption_parameters")
}

// assertCredentialErrorCode reads resp's own JSON error body (§8.3.1.2's
// {"error": "...", "error_description": "..."} shape, written by
// issuer.Error.WriteJSON) and asserts its "error" member equals
// wantCode — every negative full-flow test in this file's own final
// assertion, since a non-200 status alone doesn't prove the *right*
// rejection reason was returned. Confirmed live this distinction is
// real, not pedantic: the OIDF suite's own
// fail-unsupported-encryption-algorithm module specifically checks for
// "invalid_encryption_parameters" and fails the module if it gets a
// different (even if still correctly-4xx) error code back.
func assertCredentialErrorCode(t *testing.T, resp *http.Response, wantCode string) {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status = 200, want rejection: %s", body)
	}
	var wire struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal error body: %v (status %d, body %s)", err, resp.StatusCode, body)
	}
	if wire.Error != wantCode {
		t.Fatalf("error = %q, want %q (status %d, body %s)", wire.Error, wantCode, resp.StatusCode, body)
	}
}

// TestFullFlow_CredentialResponseEncryptionRejectsUnsupportedEncAlgorithm
// covers the sibling half of the OIDF suite's own
// fail-unsupported-encryption-algorithm module: the *outer* Credential
// Request encryption is entirely valid (ECDH-ES/A128GCM), but the
// Wallet's own "credential_response_encryption.enc" (what it asks the
// issuer to encrypt the Response back with) names an enc value this
// issuer never advertised or accepts. issuer.EncryptResponseBody
// already validates this (issuer/encryption.go), but nothing in this
// binary's own test suite exercised that specific path through the
// real HTTP handler until now.
func TestFullFlow_CredentialResponseEncryptionRejectsUnsupportedEncAlgorithm(t *testing.T) {
	client, cfg, clientKey, requestDecryptionKey, accessToken, proofJWT, now := setupEncryptedCredentialRequestTest(t, "response-encryption-fail-test-client", "response-encryption-fail-test-subject")
	_, walletJWK := buildWalletResponseEncryptionKey(t, "")

	resp := encryptAndPostCredentialRequest(t, client, cfg, clientKey, requestDecryptionKey, accessToken, jwe.A128GCM, map[string]any{
		"credential_configuration_id":    cfg.CredentialConfigurationID,
		"proofs":                         map[string][]string{"jwt": {proofJWT}},
		"credential_response_encryption": map[string]any{"jwk": walletJWK, "enc": "A192GCM"},
	}, now)
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (a plain JSON error, not an encrypted body)", ct)
	}
	assertCredentialErrorCode(t, resp, "invalid_encryption_parameters")
}

// TestFullFlow_CredentialResponseEncryptionRejectsMismatchedJWKAlg
// reproduces exactly what a live run against the real OIDF suite's own
// fail-unsupported-encryption-algorithm module actually sends — caught
// only by driving it live, not by any test that existed before this:
// the outer Credential Request encryption and
// credential_response_encryption.enc both stay entirely valid
// (ECDH-ES/A128GCM), but the Wallet's own
// credential_response_encryption.jwk itself declares an "alg" this
// issuer doesn't implement (the suite's own literal probe value,
// "UNSUPPORTED_ALG"). Before the corresponding
// issuer/encryption.go fix, EncryptResponseBody never inspected the
// JWK's own "alg" member at all and encrypted the response anyway
// (with its own ECDH-ES, silently ignoring the mismatch) — a real
// finding, not a suite-satisfying formality.
func TestFullFlow_CredentialResponseEncryptionRejectsMismatchedJWKAlg(t *testing.T) {
	client, cfg, clientKey, requestDecryptionKey, accessToken, proofJWT, now := setupEncryptedCredentialRequestTest(t, "response-encryption-alg-fail-test-client", "response-encryption-alg-fail-test-subject")
	_, walletJWKWithBogusAlg := buildWalletResponseEncryptionKey(t, "UNSUPPORTED_ALG")

	resp := encryptAndPostCredentialRequest(t, client, cfg, clientKey, requestDecryptionKey, accessToken, jwe.A128GCM, map[string]any{
		"credential_configuration_id":    cfg.CredentialConfigurationID,
		"proofs":                         map[string][]string{"jwt": {proofJWT}},
		"credential_response_encryption": map[string]any{"jwk": walletJWKWithBogusAlg, "enc": "A128GCM"},
	}, now)
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (a plain JSON error, not an encrypted body)", ct)
	}
	assertCredentialErrorCode(t, resp, "invalid_encryption_parameters")
}

// TestFullFlow_Client2CanAuthenticatePAR proves Config.Client2 is a
// real, independently-registered second client, not just a config
// field that gets parsed and ignored — the OIDF conformance suite's
// own oid4vci-1_0-issuer-haip-test-plan requires a second client even
// for its happy-flow module (see README's own "Status"), which this
// binary couldn't previously register at all. Drives PAR — the
// earliest point ClientAuthMethodAttestation is actually checked —
// as client2, with client1 also registered alongside it, confirming
// client2's own attestation is accepted and client1's registration
// doesn't interfere.
func TestFullFlow_Client2CanAuthenticatePAR(t *testing.T) {
	now := time.Now()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener

	attester2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester2 key: %v", err)
	}
	client2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client2 instance key: %v", err)
	}
	attester2JWKS, err := conformancecert.JWKSet(&attester2Key.PublicKey, "attester-2")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}

	cfg := baseTestConfig(t)
	client2 := ConfigClient{
		ID:                     "smoke-test-client-2",
		RedirectURIs:           []string{"https://client2.example.com/callback"},
		ExpectedAttesterIssuer: "https://attester2.example.com",
		AttesterJWKS:           attester2JWKS,
	}
	cfg.Client2 = &client2

	startTestIssuerServer(t, &cfg)
	_, challenge := pkceChallenge(t)

	parResp := performPAR(t, client, cfg.Issuer, cfg.Scope, challenge, client2, attester2Key, "attester-2", client2Key, now)
	if requestURI, _ := parResp["request_uri"].(string); requestURI == "" {
		t.Fatalf("par response has no request_uri: %+v", parResp)
	}
}

func doJSON(t *testing.T, client *http.Client, req *http.Request) map[string]any {
	t.Helper()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("%s %s: unmarshal body: %v (status %d, body %s)", req.Method, req.URL, err, resp.StatusCode, raw)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.Fatalf("%s %s: status %d: %+v", req.Method, req.URL, resp.StatusCode, body)
	}
	return body
}

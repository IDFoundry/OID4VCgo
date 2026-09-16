package main

import (
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

	// --- GET /authorize ---
	authorizeURL := cfg.Issuer + "/authorize?" + url.Values{
		"client_id": {cfg.Client.ID}, "request_uri": {requestURI},
	}.Encode()
	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL, nil)
	if err != nil {
		t.Fatalf("new authorize request: %v", err)
	}
	authorizeResp, err := client.Do(authorizeReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	_, _ = io.Copy(io.Discard, authorizeResp.Body)
	_ = authorizeResp.Body.Close()
	handle := authorizeResp.Header.Get("X-Interaction-Handle")
	if handle == "" {
		t.Fatalf("GET /authorize: missing X-Interaction-Handle (status %d)", authorizeResp.StatusCode)
	}

	// --- POST /authorize/decision ---
	decisionClient := &http.Client{
		Transport:     client.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	decisionForm := url.Values{"handle": {handle}, "subject": {cfg.DefaultSubject}, "decision": {"approve"}, "scope": {cfg.Scope}}
	decisionReq, err := http.NewRequest(http.MethodPost, cfg.Issuer+"/authorize/decision", strings.NewReader(decisionForm.Encode()))
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
	code := redirectURL.Query().Get("code")
	if code == "" {
		t.Fatalf("redirect location has no code: %s (error=%s)", location, redirectURL.Query().Get("error"))
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

func TestFullFlow_ParAuthorizeTokenNonceCredential(t *testing.T) {
	now := time.Now()
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}

	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-1")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}

	cfg := baseTestConfig(t)
	cfg.Client.ID = "smoke-test-client"
	cfg.Client.RedirectURIs = []string{"https://client.example.com/callback"}
	cfg.Client.ExpectedAttesterIssuer = "https://attester.example.com"
	cfg.Client.AttesterJWKS = attesterJWKS
	cfg.DefaultSubject = "smoke-test-subject"

	startTestIssuerServer(t, &cfg)

	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)

	// --- POST /credential ---
	credentialURL := cfg.Issuer + "/credential"
	athSum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(athSum[:])
	credentialDPoP, err := buildDPoPProof(clientKey, http.MethodPost, credentialURL, randomHex(t, 16), ath, now)
	if err != nil {
		t.Fatalf("buildDPoPProof (credential): %v", err)
	}
	proofJWT, err := buildCredentialProofJWT(holderKey, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT: %v", err)
	}
	credentialBody, err := json.Marshal(map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT}},
	})
	if err != nil {
		t.Fatalf("marshal credential request: %v", err)
	}
	credentialReq, err := http.NewRequest(http.MethodPost, credentialURL, strings.NewReader(string(credentialBody)))
	if err != nil {
		t.Fatalf("new credential request: %v", err)
	}
	credentialReq.Header.Set("Content-Type", "application/json")
	credentialReq.Header.Set("Authorization", "DPoP "+accessToken)
	credentialReq.Header.Set("DPoP", credentialDPoP)
	credentialResp := doJSON(t, client, credentialReq)
	credentials, _ := credentialResp["credentials"].([]any)
	if len(credentials) != 1 {
		t.Fatalf("credential response has %d credentials, want 1: %+v", len(credentials), credentialResp)
	}
	credentialEntry, _ := credentials[0].(map[string]any)
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
	if _, ok := payload["exp"]; !ok {
		t.Error("issued credential has no exp claim")
	}
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
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, talks to this test's own throwaway TLS listener

	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client instance key: %v", err)
	}
	holderKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key 1: %v", err)
	}
	holderKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key 2: %v", err)
	}

	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-1")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}

	cfg := baseTestConfig(t)
	cfg.Client.ID = "batch-test-client"
	cfg.Client.RedirectURIs = []string{"https://client.example.com/callback"}
	cfg.Client.ExpectedAttesterIssuer = "https://attester.example.com"
	cfg.Client.AttesterJWKS = attesterJWKS
	cfg.DefaultSubject = "batch-test-subject"

	startTestIssuerServer(t, &cfg)

	accessToken, cNonce := performAuthFlowThroughNonce(t, client, cfg, attesterKey, clientKey, now)

	// --- POST /credential, 2 proofs in one request ---
	credentialURL := cfg.Issuer + "/credential"
	athSum := sha256.Sum256([]byte(accessToken))
	ath := base64.RawURLEncoding.EncodeToString(athSum[:])
	credentialDPoP, err := buildDPoPProof(clientKey, http.MethodPost, credentialURL, randomHex(t, 16), ath, now)
	if err != nil {
		t.Fatalf("buildDPoPProof (credential): %v", err)
	}
	proofJWT1, err := buildCredentialProofJWT(holderKey1, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT (1): %v", err)
	}
	proofJWT2, err := buildCredentialProofJWT(holderKey2, cfg.Client.ID, cfg.Issuer, cNonce, now)
	if err != nil {
		t.Fatalf("buildCredentialProofJWT (2): %v", err)
	}
	credentialBody, err := json.Marshal(map[string]any{
		"credential_configuration_id": cfg.CredentialConfigurationID,
		"proofs":                      map[string][]string{"jwt": {proofJWT1, proofJWT2}},
	})
	if err != nil {
		t.Fatalf("marshal credential request: %v", err)
	}
	credentialReq, err := http.NewRequest(http.MethodPost, credentialURL, strings.NewReader(string(credentialBody)))
	if err != nil {
		t.Fatalf("new credential request: %v", err)
	}
	credentialReq.Header.Set("Content-Type", "application/json")
	credentialReq.Header.Set("Authorization", "DPoP "+accessToken)
	credentialReq.Header.Set("DPoP", credentialDPoP)
	credentialResp := doJSON(t, client, credentialReq)
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
	for i, entry := range credentials {
		credentialEntry, _ := entry.(map[string]any)
		issuedSDJWT, _ := credentialEntry["credential"].(string)
		issuerJWT, _, _ := strings.Cut(issuedSDJWT, "~")
		_, rawPayload, err := jose.DecodeUnverified(issuerJWT)
		if err != nil {
			t.Fatalf("credential %d: DecodeUnverified: %v", i, err)
		}
		var payload struct {
			CNF struct {
				JWK struct {
					X string `json:"x"`
				} `json:"jwk"`
			} `json:"cnf"`
		}
		if err := json.Unmarshal(rawPayload, &payload); err != nil {
			t.Fatalf("credential %d: unmarshal payload: %v", i, err)
		}
		if payload.CNF.JWK.X != wantCNFX[i] {
			t.Errorf("credential %d: cnf.jwk.x = %q, want %q (proof %d's own holder key)", i, payload.CNF.JWK.X, wantCNFX[i], i)
		}
	}
	if wantCNFX[0] == wantCNFX[1] {
		t.Fatal("test bug: both holder keys have the same x — regenerate")
	}
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

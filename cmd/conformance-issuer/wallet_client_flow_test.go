package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// noopIssuerKeySource is a keys.IssuerKeySource that's never actually
// called — fapigo/client.New requires one whenever the browser flow is
// configured (it might need to verify a JARM response or an ID token),
// but this test's own scope ("IdentityCredential") never triggers
// either, so a stub satisfying the dependency check is enough.
type noopIssuerKeySource struct{}

func (noopIssuerKeySource) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, fmt.Errorf("noopIssuerKeySource: unexpectedly called")
}

// staticAttestationSource is a fixed client.AttestationSource — this
// test's simulated wallet holds one pre-issued Client Attestation JWT
// for its whole run, exactly like a real wallet would between
// attestation refreshes (see client.AttestationSource's own doc
// comment: it's never minted per request, only the PoP is).
type staticAttestationSource string

func (s staticAttestationSource) CurrentAttestation(context.Context) (string, error) {
	return string(s), nil
}

// TestFullFlow_RealClientDrivesAttestationAuth is
// TestFullFlow_ParAuthorizeTokenNonceCredential's real-client
// counterpart: instead of this file's own hand-rolled
// buildClientAttestationJWT/PoP simulation driving raw net/http
// requests, a genuine fapigo/client.Client (storage.ClientAuthMethodAttestation)
// and oid4vcigo/wallet.Wallet drive PAR, the Authorization Code Flow,
// the Nonce Endpoint and the Credential Endpoint against this exact
// server wiring. This is the proof that FAPIgo's client-side
// Attestation-Based Client Authentication (FAPIgo PR #317) actually
// interoperates with this repo's own server-side verification, not
// just that each side's own unit tests pass in isolation.
//
// The one piece with no fapigo/client equivalent is the consent step
// itself (GET /authorize, POST /authorize/decision) — driving an
// actual browser is out of scope for any OAuth client library — so
// this reuses the same headless sequence performAuthFlowThroughNonce
// already drives by hand.
func TestFullFlow_RealClientDrivesAttestationAuth(t *testing.T) {
	now := time.Now()
	httpClient, cfg, attesterKey, _ := setupFullFlowTest(t, "real-wallet-client", "real-wallet-subject")
	ctx := context.Background()

	// --- Client Instance Key + Client Attestation JWT ---
	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAttestationPoPSigning: fapi.ES256,
		keys.DPoPProofSigning:            fapi.ES256,
	})
	if err != nil {
		t.Fatalf("ephemeral.NewKeyManager: %v", err)
	}
	instanceKeyInfo, err := km.PublicKey(ctx, keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		t.Fatalf("PublicKey(ClientAttestationPoPSigning): %v", err)
	}
	instancePub, ok := instanceKeyInfo.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("instance key PublicKey type = %T, want *ecdsa.PublicKey", instanceKeyInfo.PublicKey)
	}
	attestationJWT, err := buildClientAttestationJWT(attesterKey, "attester-1", cfg.Client.ExpectedAttesterIssuer, cfg.Client.ID, instancePub, now)
	if err != nil {
		t.Fatalf("buildClientAttestationJWT: %v", err)
	}

	// --- fapigo/client.Client, configured for Attestation-Based Client Authentication ---
	issuerURL, err := fapi.ParseIssuerURL(cfg.Issuer)
	if err != nil {
		t.Fatalf("ParseIssuerURL: %v", err)
	}
	authorizeURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/authorize")
	if err != nil {
		t.Fatalf("ParseEndpointURL(authorize): %v", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/token")
	if err != nil {
		t.Fatalf("ParseEndpointURL(token): %v", err)
	}
	parURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/par")
	if err != nil {
		t.Fatalf("ParseEndpointURL(par): %v", err)
	}

	clientCfg := client.Config{
		Issuer:      issuerURL,
		ClientID:    fapi.ClientID(cfg.Client.ID),
		RedirectURI: cfg.Client.RedirectURIs[0],
		Endpoints: client.Endpoints{
			Authorization:              authorizeURL,
			Token:                      tokenURL,
			PushedAuthorizationRequest: parURL,
		},
		Profile:          client.ProfileFAPISecurity,
		Assurance:        client.AssuranceDevelopment,
		ClientAuthMethod: storage.ClientAuthMethodAttestation,
		Algorithms: client.Algorithms{
			DPoP:                 fapi.ES256,
			IDToken:              fapi.ES256,
			ClientAttestationPoP: fapi.ES256,
		},
		Limits: client.Limits{
			SessionLifetime:      5 * time.Minute,
			MaxIDTokenLifetime:   5 * time.Minute,
			MaxClockSkew:         5 * time.Second,
			HTTPTimeout:          10 * time.Second,
			MaxHTTPResponseBytes: 1 << 16,
			MaxJOSECompactBytes:  16 * 1024,
		},
	}
	clientDeps := client.Dependencies{
		Sessions:    memstore.NewSessionStore(),
		Keys:        km,
		IssuerKeys:  noopIssuerKeySource{},
		HTTP:        httpClient,
		Clock:       client.SystemClock{},
		Random:      rand.Reader,
		Attestation: staticAttestationSource(attestationJWT),
	}
	c, err := client.New(clientCfg, clientDeps)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}

	// --- PAR, via BeginAuthorization: real Attestation + PoP headers ---
	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{cfg.Scope}})
	if err != nil {
		t.Fatalf("BeginAuthorization: %v", err)
	}

	// --- headless consent: GET /authorize, POST /authorize/decision ---
	// (mirrors performAuthFlowThroughNonce's own sequence — no
	// fapigo/client equivalent exists for driving an actual browser)
	authorizeReq, err := http.NewRequest(http.MethodGet, session.URL().String(), nil)
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

	// --- token endpoint, via CompleteAuthorization: real Attestation + PoP + DPoP ---
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: redirectURL.RawQuery})
	if err != nil {
		t.Fatalf("CompleteAuthorization: %v", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		t.Fatalf("CompleteAuthorization result = %T, want client.CompletionSuccess", result)
	}

	// --- Nonce + Credential Endpoint, via a real oid4vcigo/wallet.Wallet ---
	w, err := wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 16,
			RequestTimeout:   10 * time.Second,
			MaxRedirects:     2,
			// This test's own issuer runs on a loopback TLS listener
			// (startTestIssuerServer), not a real public host.
			AllowLoopbackHTTP: true,
		},
	}, wallet.Dependencies{
		HTTP:   httpClient,
		Clock:  wallet.ClockFunc(time.Now),
		Random: rand.Reader,
	})
	if err != nil {
		t.Fatalf("wallet.New: %v", err)
	}

	nonceEndpoint, err := fapi.ParseEndpointURL(cfg.Issuer + "/nonce")
	if err != nil {
		t.Fatalf("ParseEndpointURL(nonce): %v", err)
	}
	nonceResult, err := w.RequestNonce(ctx, nonceEndpoint)
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}

	holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate holder key: %v", err)
	}
	credentialEndpoint, err := fapi.ParseEndpointURL(cfg.Issuer + "/credential")
	if err != nil {
		t.Fatalf("ParseEndpointURL(credential): %v", err)
	}

	// (*client.Client).ProtectedResource returns a *client.ResourceClient,
	// which satisfies wallet.ProtectedResourceClient directly (identical
	// Do(ctx, *http.Request) (*http.Response, error) shape) — no adapter
	// needed, exactly per wallet/doc.go's own boundary.
	resource := c.ProtectedResource(success.Tokens)

	credResult, err := w.RequestCredential(ctx, resource, credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: cfg.CredentialConfigurationID,
		Keys:                      []crypto.Signer{holderKey},
		CredentialIssuer:          cfg.Issuer,
		Nonce:                     nonceResult.CNonce,
	})
	if err != nil {
		t.Fatalf("RequestCredential: %v", err)
	}
	if len(credResult.Credentials) != 1 {
		t.Fatalf("Credentials = %v, want exactly 1", credResult.Credentials)
	}
}

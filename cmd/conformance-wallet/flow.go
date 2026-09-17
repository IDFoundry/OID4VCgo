package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/wallet"
)

// encryptionEnc is the JWE content encryption algorithm this binary
// asks for (both request and response) — A128GCM is in every enc
// this repo's own internal/jwe package supports (A128GCM/A192GCM/
// A256GCM) and every suite-advertised enc_values_supported list
// confirmed live, so a fixed choice is enough; no runtime negotiation.
const encryptionEnc = jwe.A128GCM

// credentialIssuerEncryptionMetadata is the subset of Credential Issuer
// Metadata (openid-credential-issuer) this binary needs for the
// immediate+encrypted crossing — everything else about the document
// (credential_configurations_supported, endpoints, ...) this binary
// already knows from its own config/module.URL, matching wallet/doc.go's
// own "this package doesn't fetch or parse Issuer metadata itself"
// boundary (so this binary does it inline, not wallet).
type credentialIssuerEncryptionMetadata struct {
	CredentialRequestEncryption struct {
		JWKS struct {
			Keys []json.RawMessage `json:"keys"`
		} `json:"jwks"`
	} `json:"credential_request_encryption"`
}

// wellKnownMetadataURL builds a RFC 8414 §3.1-style well-known URL for
// issuerURL, a URL that may itself carry a path component (e.g. this
// binary's own module.URL, "https://host/test/a/<alias>"):
// "/.well-known/<suffix>" is inserted *before* that path, not appended
// after it — "https://host/.well-known/<suffix>/test/a/<alias>", the
// same insertion rule OID4VCI's own Credential Issuer Metadata
// discovery follows (§11.2.1) for an Issuer whose identifier carries a
// path.
func wellKnownMetadataURL(issuerURL, suffix string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("parse issuer URL: %w", err)
	}
	u.Path = "/.well-known/" + suffix + u.Path
	return u.String(), nil
}

// fetchCredentialRequestEncryptionJWK fetches module's own Credential
// Issuer Metadata and returns the first key of its own
// credential_request_encryption.jwks — the Issuer's own encryption
// public key a Wallet encrypts a Credential Request to (§10,
// RequestEncryption.RecipientJWK's own doc comment).
func fetchCredentialRequestEncryptionJWK(ctx context.Context, httpClient *http.Client, moduleURL string) (json.RawMessage, error) {
	// The trailing slash matters here too — the same "aud"/CredentialIssuer
	// trailing-slash convention this binary already found applies to the
	// metadata request path itself (confirmed live: without it, the
	// suite's own metadata handler rejects the request as "does not
	// match expected URL path").
	wellKnownURL, err := wellKnownMetadataURL(moduleURL+"/", "openid-credential-issuer")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential issuer metadata endpoint returned status %d", res.StatusCode)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var metadata credentialIssuerEncryptionMetadata
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode credential issuer metadata: %w", err)
	}
	if len(metadata.CredentialRequestEncryption.JWKS.Keys) == 0 {
		return nil, fmt.Errorf("credential issuer metadata publishes no credential_request_encryption.jwks.keys")
	}
	return metadata.CredentialRequestEncryption.JWKS.Keys[0], nil
}

// newWallet builds a wallet.Wallet for the Nonce/Credential/Notification
// Endpoint calls driveModule needs — httpClient is the same
// suite-trusting client used for everything else in this binary, so
// the Nonce Endpoint's own unauthenticated call reaches the same
// module instance the rest of the flow already established.
func newWallet(httpClient *http.Client) (*wallet.Wallet, error) {
	return wallet.New(wallet.Config{
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20,
			RequestTimeout:   20 * time.Second,
			MaxRedirects:     2,
			// The suite's module base URL resolves to a loopback
			// address by default (see main.go's own -suite flag).
			AllowLoopbackHTTP: true,
		},
	}, wallet.Dependencies{
		HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader,
	})
}

// noopIssuerKeySource is a keys.IssuerKeySource that's never actually
// called — fapigo/client.New requires one whenever the browser flow is
// configured, but this run's own scope (plain_oauth, no "openid"
// scope) never returns an ID token, matching the identical stub
// cmd/conformance-issuer's own wallet_client_flow_test.go already
// established for the same reason.
type noopIssuerKeySource struct{}

func (noopIssuerKeySource) ResolveIssuerKeys(context.Context, keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	return keys.IssuerKeySet{}, fmt.Errorf("noopIssuerKeySource: unexpectedly called")
}

// buildClient constructs a fapigo/client.Client for module — every
// endpoint this run needs lives at a fixed path under module.URL
// (par/authorize/token/nonce/challenge/credential/deferred_credential/
// notification, confirmed directly against the suite's own
// AbstractVCIWalletTest.handleClientRequestForPath), so this hardcodes
// them the same way wallet_client_flow_test.go already does against a
// real fapigo/server instance, rather than running full RFC 8414
// discovery for a shape that never varies.
func buildClient(run *walletRun, module suiteModule, httpClient *http.Client) (*client.Client, error) {
	// The trailing slash matters here too, for the same reason it does
	// for CredentialIssuer in driveModule: the suite's own issuer
	// identifier (what it compares a Client Attestation PoP's own
	// "aud" claim against) is published with one — confirmed live
	// ("ValidateClientAttestationProofJwtAudience: aud claim... did
	// not match the authorization server issuer" without it).
	issuer, err := fapi.ParseIssuerURL(module.URL + "/")
	if err != nil {
		return nil, fmt.Errorf("parse issuer URL: %w", err)
	}
	authorizeURL, err := fapi.ParseEndpointURL(module.URL + "/authorize")
	if err != nil {
		return nil, fmt.Errorf("parse authorize URL: %w", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(module.URL + "/token")
	if err != nil {
		return nil, fmt.Errorf("parse token URL: %w", err)
	}
	parURL, err := fapi.ParseEndpointURL(module.URL + "/par")
	if err != nil {
		return nil, fmt.Errorf("parse par URL: %w", err)
	}

	km, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.ClientAttestationPoPSigning: fapi.ES256,
		keys.DPoPProofSigning:            fapi.ES256,
	})
	if err != nil {
		return nil, fmt.Errorf("generate key manager: %w", err)
	}
	instanceKeyInfo, err := km.PublicKey(context.Background(), keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		return nil, fmt.Errorf("resolve client instance public key: %w", err)
	}

	now := time.Now()
	attestationJWT, err := mintClientAttestationJWT(run.attesterKey, run.attesterLeafPEM,
		"https://oid4vcigo-wallet-attester.example.com", run.clientID, instanceKeyInfo.PublicKey, now)
	if err != nil {
		return nil, fmt.Errorf("mint client attestation: %w", err)
	}
	attestation := attestationAndChallengeSource{
		staticAttestationSource: staticAttestationSource(attestationJWT),
		challengeSource:         challengeSource{httpClient: httpClient, endpoint: module.URL + clientAttestationChallengePath},
	}

	cfg := client.Config{
		Issuer:      issuer,
		ClientID:    fapi.ClientID(run.clientID),
		RedirectURI: run.redirectURI,
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
			MaxClockSkew:         15 * time.Second,
			HTTPTimeout:          20 * time.Second,
			MaxHTTPResponseBytes: 1 << 20,
			MaxJOSECompactBytes:  16 * 1024,
		},
	}
	deps := client.Dependencies{
		Sessions:    memstore.NewSessionStore(),
		Keys:        km,
		IssuerKeys:  noopIssuerKeySource{},
		HTTP:        httpClient,
		Clock:       client.SystemClock{},
		Random:      rand.Reader,
		Attestation: attestation,
	}
	return client.New(cfg, deps)
}

// followAuthorizationRedirect GETs authorizationURL with a client that
// never follows a redirect, and returns the resulting Location's raw
// query — the suite's own vci10wallet AS auto-issues an authorization
// code and redirects immediately (AbstractFAPI2SPFinalClientTest's
// authorizationEndpoint, confirmed by direct source reading: no
// interactive consent step exists for this test plan), so there is no
// actual browser or human to intercept — this driver plays that single
// GET itself, mirroring FAPIgo's own cmd/conformance-client
// (followAuthorizationRedirect) established for the identical
// no-consent shape.
func followAuthorizationRedirect(baseClient *http.Client, authorizationURL string) (string, error) {
	noRedirectClient := &http.Client{
		Transport:     baseClient.Transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequest(http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	res, err := noRedirectClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode < 300 || res.StatusCode >= 400 {
		return "", fmt.Errorf("authorization endpoint returned %d, want a redirect", res.StatusCode)
	}
	location := res.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("redirect response carries no Location header")
	}
	redirectURL, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("parse redirect location %q: %w", location, err)
	}
	return redirectURL.RawQuery, nil
}

// driveModule drives one module instance end to end: PAR (via
// BeginAuthorization) -> follow the redirect -> CompleteAuthorization
// -> ProtectedResource -> RequestNonce -> RequestCredential (numCreds
// holder keys — 1, or more for the batch module) -> RequestNotification
// when the Credential Response carries a notification_id. Returns
// nothing but an error: for the modules this binary drives, the
// suite's own graded verdict (fetched separately) is what actually
// matters, not this function's own success/failure — matching
// FAPIgo's own cmd/conformance-client runModule doc comment.
// maxDeferredPollAttempts/defaultDeferredPollInterval bound
// pollDeferredCredential's own retry loop — the suite's own emulated
// Issuer resolves a deferred transaction quickly (it's a fixture, not
// a real backend process), so this is generous relative to what a real
// deployment would need, not tuned tightly against it.
const (
	maxDeferredPollAttempts     = 10
	defaultDeferredPollInterval = 2 * time.Second
)

// pollDeferredCredential drives the Deferred Credential Endpoint
// (§9.1/§9.2) until first carries either issued credentials, or the
// suite's own emulated Issuer accepts a fresh transaction_id and
// interval): first is the still-pending CredentialRequest.
func pollDeferredCredential(ctx context.Context, w *wallet.Wallet, resource wallet.ProtectedResourceClient, module suiteModule, first wallet.CredentialResult) (wallet.CredentialResult, error) {
	deferredEndpoint, err := fapi.ParseEndpointURL(module.URL + "/deferred_credential")
	if err != nil {
		return wallet.CredentialResult{}, fmt.Errorf("parse deferred credential endpoint: %w", err)
	}

	result := first
	for attempt := 0; attempt < maxDeferredPollAttempts; attempt++ {
		interval := result.Interval
		if interval <= 0 {
			interval = defaultDeferredPollInterval
		}
		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return wallet.CredentialResult{}, ctx.Err()
		}

		result, err = w.RequestDeferredCredential(ctx, resource, deferredEndpoint, wallet.DeferredCredentialRequest{
			TransactionID: result.TransactionID,
		})
		if err != nil {
			return wallet.CredentialResult{}, err
		}
		if len(result.Credentials) > 0 {
			return result, nil
		}
		if result.TransactionID == "" {
			return wallet.CredentialResult{}, fmt.Errorf("deferred credential response carries neither credentials nor a transaction_id")
		}
	}
	return wallet.CredentialResult{}, fmt.Errorf("deferred credential still pending after %d attempts", maxDeferredPollAttempts)
}

func driveModule(ctx context.Context, run *walletRun, module suiteModule, httpClient *http.Client, numCreds int, encrypted bool) error {
	c, err := buildClient(run, module, httpClient)
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	session, err := c.BeginAuthorization(ctx, client.BeginAuthorizationRequest{Scope: []string{run.scope}})
	if err != nil {
		return fmt.Errorf("begin authorization: %w", err)
	}

	rawQuery, err := followAuthorizationRedirect(httpClient, session.URL().String())
	if err != nil {
		return fmt.Errorf("follow authorization redirect: %w", err)
	}

	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		return fmt.Errorf("complete authorization: %w", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		return fmt.Errorf("authorization was not completed successfully: %#v", result)
	}

	resource := c.ProtectedResource(success.Tokens)

	w, err := newWallet(httpClient)
	if err != nil {
		return fmt.Errorf("build wallet: %w", err)
	}

	nonceEndpoint, err := fapi.ParseEndpointURL(module.URL + "/nonce")
	if err != nil {
		return fmt.Errorf("parse nonce endpoint: %w", err)
	}
	nonceResult, err := w.RequestNonce(ctx, nonceEndpoint)
	if err != nil {
		return fmt.Errorf("request nonce: %w", err)
	}

	holderKeys := make([]crypto.Signer, numCreds)
	for i := range holderKeys {
		holderKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if genErr != nil {
			return fmt.Errorf("generate holder key: %w", genErr)
		}
		holderKeys[i] = holderKey
	}

	credentialEndpoint, err := fapi.ParseEndpointURL(module.URL + "/credential")
	if err != nil {
		return fmt.Errorf("parse credential endpoint: %w", err)
	}
	credRequest := wallet.CredentialRequest{
		CredentialConfigurationID: run.credentialConfigurationID,
		Keys:                      holderKeys,
		// The trailing slash matters: it must match the Credential
		// Issuer Identifier exactly as the suite's own metadata
		// publishes it (confirmed live: "credential_issuer":
		// ".../<alias>/" — with a trailing slash), since this becomes
		// the jwt-type proof's own "aud" claim.
		CredentialIssuer: module.URL + "/",
		Nonce:            nonceResult.CNonce,
	}
	if encrypted {
		recipientJWK, encErr := fetchCredentialRequestEncryptionJWK(ctx, httpClient, module.URL)
		if encErr != nil {
			return fmt.Errorf("fetch credential request encryption key: %w", encErr)
		}
		credRequest.RequestEncryption = &wallet.RequestEncryption{RecipientJWK: recipientJWK, Enc: encryptionEnc}
		credRequest.ResponseEncryption = &wallet.ResponseEncryption{Enc: encryptionEnc}
	}
	credResult, err := w.RequestCredential(ctx, resource, credentialEndpoint, credRequest)
	if err != nil {
		return fmt.Errorf("request credential: %w", err)
	}

	if credResult.TransactionID != "" {
		// §8.3's own "deferred at first response" case (VCICredentialIssuanceMode=deferred):
		// no credentials yet, just a transaction_id/interval — poll the
		// Deferred Credential Endpoint until the suite's own emulated
		// Issuer actually issues them.
		credResult, err = pollDeferredCredential(ctx, w, resource, module, credResult)
		if err != nil {
			return fmt.Errorf("poll deferred credential: %w", err)
		}
	}
	if len(credResult.Credentials) != numCreds {
		return fmt.Errorf("credential response carries %d credentials, want %d", len(credResult.Credentials), numCreds)
	}

	if credResult.NotificationID != "" {
		notificationEndpoint, err := fapi.ParseEndpointURL(module.URL + "/notification")
		if err != nil {
			return fmt.Errorf("parse notification endpoint: %w", err)
		}
		if err := w.RequestNotification(ctx, resource, notificationEndpoint, wallet.NotificationRequest{
			NotificationID: credResult.NotificationID,
			Event:          oid4vci.NotificationEventCredentialAccepted,
		}); err != nil {
			return fmt.Errorf("request notification: %w", err)
		}
	}

	return nil
}

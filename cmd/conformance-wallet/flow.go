package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
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
	"github.com/idfoundry/oid4vcigo/wallet"
)

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
func driveModule(ctx context.Context, run *walletRun, module suiteModule, httpClient *http.Client, numCreds int) error {
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
	credResult, err := w.RequestCredential(ctx, resource, credentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: run.credentialConfigurationID,
		Keys:                      holderKeys,
		// The trailing slash matters: it must match the Credential
		// Issuer Identifier exactly as the suite's own metadata
		// publishes it (confirmed live: "credential_issuer":
		// ".../<alias>/" — with a trailing slash), since this becomes
		// the jwt-type proof's own "aud" claim.
		CredentialIssuer: module.URL + "/",
		Nonce:            nonceResult.CNonce,
	})
	if err != nil {
		return fmt.Errorf("request credential: %w", err)
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

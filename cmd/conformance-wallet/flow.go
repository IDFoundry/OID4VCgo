package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// encryptionEnc is the JWE content encryption algorithm this binary
// asks for (both request and response) — A128GCM is in every enc
// this repo's own internal/jwe package supports (A128GCM/A192GCM/
// A256GCM) and every suite-advertised enc_values_supported list
// confirmed live, so a fixed choice is enough; no runtime negotiation.
const encryptionEnc = jwe.A128GCM

// credentialRequestEncryptionJWK fetches moduleURL's own Credential
// Issuer Metadata (via wallet.Wallet.FetchCredentialIssuerMetadata,
// promoted from this function's own earlier hand-rolled fetch+decode —
// see wallet/discovery.go) and returns the first key of its own
// credential_request_encryption.jwks — the Issuer's own encryption
// public key a Wallet encrypts a Credential Request to (§10,
// RequestEncryption.RecipientJWK's own doc comment).
func credentialRequestEncryptionJWK(ctx context.Context, w *wallet.Wallet, moduleURL string) (json.RawMessage, error) {
	// The trailing slash matters here too — the same "aud"/CredentialIssuer
	// trailing-slash convention this binary already found applies to the
	// metadata request path itself (confirmed live: without it, the
	// suite's own metadata handler rejects the request as "does not
	// match expected URL path").
	metadata, err := w.FetchCredentialIssuerMetadata(ctx, moduleURL+"/")
	if err != nil {
		return nil, err
	}
	if metadata.CredentialRequestEncryption == nil || len(metadata.CredentialRequestEncryption.JWKS.Keys) == 0 {
		return nil, fmt.Errorf("credential issuer metadata publishes no credential_request_encryption.jwks.keys")
	}
	return json.Marshal(metadata.CredentialRequestEncryption.JWKS.Keys[0])
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
func buildClient(ctx context.Context, run *walletRun, module conformancesuite.SuiteModule, testName string, httpClient *http.Client) (*client.Client, error) {
	// The trailing slash matters here too, for the same reason it does
	// for CredentialIssuer in driveModule: the suite's own issuer
	// identifier (what it compares a Client Attestation PoP's own
	// "aud" claim against) is published with one — confirmed live
	// ("ValidateClientAttestationProofJwtAudience: aud claim... did
	// not match the authorization server issuer" without it).
	expectedIssuer := module.URL + "/"
	issuer, err := fapi.ParseIssuerURL(expectedIssuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer URL: %w", err)
	}

	// Real RFC 8414 metadata discovery, not hardcoded endpoint paths:
	// fapi2-security-profile-final-client-test-discovery-issuer-mismatch
	// corrupts the suite's own "issuer" field and expects the client to
	// notice and stop — this is the OIDC Discovery §4.3 anti-spoofing
	// check that module exists to verify. For every other module this
	// binary drives, the fetched endpoint values are identical to what
	// was previously hardcoded here, so this adds a validation step
	// without changing behavior elsewhere. Promoted to
	// wallet.Wallet.FetchAuthorizationServerMetadata — see
	// wallet/discovery.go for why fapigo/client.Discover can't do this
	// (OIDC-only well-known convention, no RFC 8414 support).
	discoveryWallet, err := newWallet(httpClient)
	if err != nil {
		return nil, fmt.Errorf("build discovery wallet: %w", err)
	}
	metadata, err := discoveryWallet.FetchAuthorizationServerMetadata(ctx, module.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch authorization server metadata: %w", err)
	}
	if metadata.Issuer != expectedIssuer {
		return nil, fmt.Errorf("authorization server metadata issuer %q does not match expected issuer %q", metadata.Issuer, expectedIssuer)
	}
	authorizeURL, err := fapi.ParseEndpointURL(metadata.AuthorizationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse authorize URL: %w", err)
	}
	tokenURL, err := fapi.ParseEndpointURL(metadata.TokenEndpoint)
	if err != nil {
		return nil, fmt.Errorf("parse token URL: %w", err)
	}
	parURL, err := fapi.ParseEndpointURL(metadata.PushedAuthorizationRequestEndpoint)
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
	instanceKeyInfo, err := km.PublicKey(ctx, keys.ClientAttestationPoPSigning, fapi.ES256)
	if err != nil {
		return nil, fmt.Errorf("resolve client instance public key: %w", err)
	}

	now := time.Now()
	attestationJWT, err := mintClientAttestationJWT(run.attesterKey, run.attesterLeafPEM,
		"https://oid4vcgo-wallet-attester.example.com", run.clientID, instanceKeyInfo.PublicKey, now)
	if err != nil {
		return nil, fmt.Errorf("mint client attestation: %w", err)
	}
	// The HAIP plan's generic FAPI2SP client battery reuses
	// AbstractFAPI2SPFinalClientTest as-is — a class hierarchy with no
	// knowledge of draft-ietf-oauth-attestation-based-client-auth-07 §8
	// at all, confirmed by its own source carrying no "challenge"
	// handling (only unrelated PKCE "code_challenge" conditions). It
	// never wires up the /challenge endpoint the 4 VCIWallet* modules
	// all do, so a client that calls it there hits the suite's own
	// catch-all TestDispatcher — "Got unexpected HTTP call to
	// challenge" — confirmed live. §5.2's own "challenge" claim in the
	// PoP JWT is optional (only sent when a fresh challenge exists), so
	// the battery gets a plain, unchallenged attestation source.
	var attestation client.AttestationSource = staticAttestationSource(attestationJWT)
	if !strings.HasPrefix(testName, batteryModulePrefix) {
		attestation = attestationAndChallengeSource{
			staticAttestationSource: staticAttestationSource(attestationJWT),
			challengeSource:         challengeSource{httpClient: httpClient, endpoint: module.URL + clientAttestationChallengePath},
		}
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
		// HAIP always sends "iss" in the authorization response
		// (RFC 9207) — required unconditionally, not just for the
		// fapi2-security-profile-final-client-test-remove-authorization-response-iss
		// module that specifically checks it: a client that tolerates
		// an absent iss when the AS is known to always send one is
		// itself a downgrade risk.
		RequireAuthorizationResponseIss: true,
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
func pollDeferredCredential(ctx context.Context, w *wallet.Wallet, resource wallet.ProtectedResourceClient, module conformancesuite.SuiteModule, first wallet.CredentialResult) (wallet.CredentialResult, error) {
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

// issuerStateExtension is OID4VCI §5.1.3's own "issuer_state"
// authorization/PAR parameter — a Wallet echoes back whatever the
// Credential Offer's own grants.authorization_code.issuer_state
// carried, when present. No server-side registration is needed to
// send it (extension.Set is purely a client-side, self-describing
// encode — see FAPIgo PR #304's own "ignore unrecognized authorization
// request parameters" fix on the suite's own AS side), and since this
// binary always runs FAPI2AuthRequestMethod=unsigned, a bare string
// value here always goes out as a plain top-level PAR parameter
// (BeginAuthorizationRequest.Extensions' own doc comment).
var issuerStateExtension = extension.Definition[string]{
	Name:           "issuer_state",
	Cardinality:    extension.Single,
	AllowedSources: extension.SourcePlainParameter,
	MaxBytes:       2048,
}

// driveModule drives one module instance through the full flow this
// binary's own scope covers. offer is non-nil only for the
// issuer_initiated flow variant (already resolved by runModule, since
// it has to be captured before this module even reaches WAITING — see
// credentialoffer.go) — when set, its own issuer_state (if any) is
// echoed back on the PAR request (OID4VCI §5.1.3) and its own
// credential_configuration_ids[0] is used in place of
// run.credentialConfigurationID, matching what a spec-faithful wallet
// actually resolves the offer for.
func (r moduleRunner) driveModule(ctx context.Context, module conformancesuite.SuiteModule, testName string, numCreds int, encrypted bool, offer *oid4vci.CredentialOffer) error {
	run, httpClient := r.WalletRun, r.HTTPClient
	resource, err := r.authorizeAndGetProtectedResource(ctx, module, testName, offer)
	if err != nil {
		return err
	}

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

	credentialEndpoint, err := fapi.ParseEndpointURL(module.URL + "/credential")
	if err != nil {
		return fmt.Errorf("parse credential endpoint: %w", err)
	}
	credRequest, err := buildWalletCredentialRequest(ctx, w, run, module, numCreds, encrypted, nonceResult.CNonce, offer)
	if err != nil {
		return err
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

// authorizeAndGetProtectedResource is driveModule's own PAR ->
// authorize -> token half — split out purely to keep driveModule under
// the linter's own cognitive complexity ceiling. offer's own
// issuer_state (if any) is echoed back on the PAR request (OID4VCI
// §5.1.3), matching what a spec-faithful wallet does for the
// issuer_initiated flow variant.
func (r moduleRunner) authorizeAndGetProtectedResource(ctx context.Context, module conformancesuite.SuiteModule, testName string, offer *oid4vci.CredentialOffer) (wallet.ProtectedResourceClient, error) {
	run, httpClient := r.WalletRun, r.HTTPClient
	c, err := buildClient(ctx, run, module, testName, httpClient)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}

	beginReq := client.BeginAuthorizationRequest{Scope: []string{run.scope}}
	if offer != nil && offer.Grants != nil && offer.Grants.AuthorizationCode != nil {
		if issuerState := offer.Grants.AuthorizationCode.IssuerState; issuerState != "" {
			if err := extension.Set(&beginReq.Extensions, issuerStateExtension, issuerState); err != nil {
				return nil, fmt.Errorf("set issuer_state extension: %w", err)
			}
		}
	}
	session, err := c.BeginAuthorization(ctx, beginReq)
	if err != nil {
		return nil, fmt.Errorf("begin authorization: %w", err)
	}

	rawQuery, err := followAuthorizationRedirect(httpClient, session.URL().String())
	if err != nil {
		return nil, fmt.Errorf("follow authorization redirect: %w", err)
	}

	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery})
	if err != nil {
		return nil, fmt.Errorf("complete authorization: %w", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		return nil, fmt.Errorf("authorization was not completed successfully: %#v", result)
	}
	return c.ProtectedResource(success.Tokens), nil
}

// buildWalletCredentialRequest builds the CredentialRequest driveModule
// sends, including its run.proofType-specific proof material and
// optional §10 request/response encryption — split out purely to keep
// driveModule under the linter's own cognitive complexity ceiling.
func buildWalletCredentialRequest(ctx context.Context, w *wallet.Wallet, run *walletRun, module conformancesuite.SuiteModule, numCreds int, encrypted bool, cNonce string, offer *oid4vci.CredentialOffer) (wallet.CredentialRequest, error) {
	credentialConfigurationID := run.credentialConfigurationID
	if offer != nil && len(offer.CredentialConfigurationIDs) > 0 {
		credentialConfigurationID = offer.CredentialConfigurationIDs[0]
	}
	credRequest := wallet.CredentialRequest{
		CredentialConfigurationID: credentialConfigurationID,
		// The trailing slash matters: it must match the Credential
		// Issuer Identifier exactly as the suite's own metadata
		// publishes it (confirmed live: "credential_issuer":
		// ".../<alias>/" — with a trailing slash), since this becomes
		// the jwt-type proof's own "aud" claim. Unused for the
		// attestation proof type below, but harmless to leave set.
		CredentialIssuer: module.URL + "/",
		Nonce:            cNonce,
	}
	switch run.proofType {
	case proofStrategyAttestation:
		// HAIP §4.5.1 Key Attestation (Appendix D/F.3): one Key
		// Attestation JWT attests numCreds fresh keys and is submitted
		// as the standalone "attestation" proof — no per-credential jwt
		// proof needed, see buildKeyAttestationProof's own doc comment.
		attestedKeys, genErr := generateAttestedKeys(numCreds)
		if genErr != nil {
			return wallet.CredentialRequest{}, fmt.Errorf("generate attested keys: %w", genErr)
		}
		attestationJWT, err := buildKeyAttestationProof(w, run, attestedKeys, cNonce, false)
		if err != nil {
			return wallet.CredentialRequest{}, fmt.Errorf("build key attestation proof: %w", err)
		}
		credRequest.Attestation = attestationJWT

	case proofStrategyJWTKeyAttestation:
		// Appendix D.1's nested case: an ordinary jwt-type proof per
		// credential, each with the Key Attestation JWT embedded in its
		// own header (wallet.GenerateProofWithKeyAttestation). All
		// proofs share one attestation covering every attested key at
		// once, rather than each minting its own single-key one:
		// AbstractVCIWalletTest.java only ever validates the *last*
		// proof's own nested attestation against the *first* proof's
		// own key (VCIValidateCredentialRequestJwtProof overwrites
		// vci.key_attestation_jwt per proof, then
		// VCIValidateAttestedKeysInKeyAttestationFromJwtProof checks
		// only the first proof's own key against whatever that ends up
		// being) — confirmed live: a batch of per-key attestations
		// fails that check for numCreds>1, while one shared attestation
		// naming every key passes regardless of which proof's copy the
		// suite happens to validate.
		attestedKeys, genErr := generateAttestedKeys(numCreds)
		if genErr != nil {
			return wallet.CredentialRequest{}, fmt.Errorf("generate attested keys: %w", genErr)
		}
		attestationJWT, err := buildKeyAttestationProof(w, run, attestedKeys, cNonce, true)
		if err != nil {
			return wallet.CredentialRequest{}, fmt.Errorf("build key attestation proof: %w", err)
		}
		jwtProofs := make([]string, numCreds)
		for i, signer := range attestedKeys {
			proof, genErr := w.GenerateProofWithKeyAttestation(signer, module.URL+"/", cNonce, attestationJWT)
			if genErr != nil {
				return wallet.CredentialRequest{}, fmt.Errorf("generate jwt proof with key attestation %d: %w", i, genErr)
			}
			jwtProofs[i] = proof
		}
		credRequest.JWTProofs = jwtProofs

	default:
		holderKeys := make([]crypto.Signer, numCreds)
		for i := range holderKeys {
			holderKey, genErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if genErr != nil {
				return wallet.CredentialRequest{}, fmt.Errorf("generate holder key: %w", genErr)
			}
			holderKeys[i] = holderKey
		}
		credRequest.Keys = holderKeys
	}
	if encrypted {
		recipientJWK, encErr := credentialRequestEncryptionJWK(ctx, w, module.URL)
		if encErr != nil {
			return wallet.CredentialRequest{}, fmt.Errorf("fetch credential request encryption key: %w", encErr)
		}
		credRequest.RequestEncryption = &wallet.RequestEncryption{RecipientJWK: recipientJWK, Enc: encryptionEnc}
		credRequest.ResponseEncryption = &wallet.ResponseEncryption{Enc: encryptionEnc}
	}
	return credRequest, nil
}

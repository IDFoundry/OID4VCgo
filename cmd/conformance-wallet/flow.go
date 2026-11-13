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

// credentialRequestEncryptionJWK returns the first key of metadata's
// credential_request_encryption.jwks — the Issuer's own encryption
// public key a Wallet encrypts a Credential Request to (§10,
// RequestEncryption.RecipientJWK's own doc comment).
func credentialRequestEncryptionJWK(metadata oid4vci.Metadata) (json.RawMessage, error) {
	if metadata.CredentialRequestEncryption == nil || len(metadata.CredentialRequestEncryption.JWKS.Keys) == 0 {
		return nil, fmt.Errorf("credential issuer metadata publishes no credential_request_encryption.jwks.keys")
	}
	return json.Marshal(metadata.CredentialRequestEncryption.JWKS.Keys[0])
}

// newWallet builds a wallet.Wallet for the metadata, Nonce, Credential
// and Notification Endpoint calls driveModule needs — httpClient is the
// same client, pinning the suite's TLS certificate, used for everything
// else in this binary.
func newWallet(httpClient *http.Client) (*wallet.Wallet, error) {
	return wallet.New(wallet.Config{
		Assurance:       wallet.AssuranceDevelopment,
		ProofSigningAlg: jose.ES256,
		Fetch: fapihttp.Config{
			MaxResponseBytes: 1 << 20,
			RequestTimeout:   20 * time.Second,
			MaxRedirects:     2,
			// The suite runs locally: https://localhost:8443 by
			// default (main.go's -suite flag), and in CI its module
			// URLs use localhost.emobix.co.uk, a public name that
			// resolves to 127.0.0.1.
			AllowLoopbackHosts:   true,
			AllowedLoopbackHosts: []string{"localhost.emobix.co.uk"},
		},
	}, wallet.Dependencies{
		HTTP: httpClient, Clock: wallet.ClockFunc(time.Now), Random: rand.Reader,
	})
}

// buildClient constructs a fapigo/client.Client for the Authorization
// Server asIssuer names (the Credential Issuer Metadata's
// authorization_servers entry), from its RFC 8414 metadata: its
// endpoints, and its Attestation Challenge Endpoint when it publishes
// one.
func buildClient(ctx context.Context, run *walletRun, asIssuer string, httpClient *http.Client) (*client.Client, error) {
	issuer, err := fapi.ParseIssuerURL(asIssuer)
	if err != nil {
		return nil, fmt.Errorf("parse issuer URL: %w", err)
	}

	// Real RFC 8414 metadata discovery, not hardcoded endpoint paths:
	// fapi2-security-profile-final-client-test-discovery-issuer-mismatch
	// corrupts the suite's own "issuer" field and expects the client to
	// notice and stop — this is the OIDC Discovery §4.3 anti-spoofing
	// check that module exists to verify, now done by
	// wallet.Wallet.FetchAuthorizationServerMetadata itself (RFC 8414
	// §3.3), given the full issuer identifier — trailing "/" included;
	// it removes that "/" when forming the well-known URL (§3.1). See
	// wallet/discovery.go for why fapigo/client.Discover can't do this
	// (OIDC-only well-known convention, no RFC 8414 support).
	discoveryWallet, err := newWallet(httpClient)
	if err != nil {
		return nil, fmt.Errorf("build discovery wallet: %w", err)
	}
	metadata, err := discoveryWallet.FetchAuthorizationServerMetadata(ctx, asIssuer)
	if err != nil {
		return nil, fmt.Errorf("fetch authorization server metadata: %w", err)
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
	// draft-ietf-oauth-attestation-based-client-auth-07 §8: a Client
	// Attestation PoP carries a challenge from the Authorization
	// Server's Challenge Endpoint when its metadata publishes one
	// (challenge_endpoint), as the suite's does for
	// oid4vci-1_0-wallet-test-client-attestation-challenge alone.
	attestation := client.StaticAttestation(attestationJWT)
	if metadata.ChallengeEndpoint != "" {
		attestation = attestationAndChallengeSource{
			AttestationSource: attestation,
			challengeSource:   challengeSource{httpClient: httpClient, endpoint: metadata.ChallengeEndpoint},
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
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		// This run's scope is plain_oauth, never "openid": no ID token
		// to verify, so no Algorithms.IDToken and no IssuerKeys.
		OAuthOnly: true,
		Algorithms: client.Algorithms{
			DPoP:                 fapi.ES256,
			ClientAttestationPoP: fapi.ES256,
		},
		Limits: client.Limits{
			SessionLifetime:      5 * time.Minute,
			MaxClockSkew:         15 * time.Second,
			HTTPTimeout:          20 * time.Second,
			MaxHTTPResponseBytes: 1 << 20,
			MaxJOSECompactBytes:  16 * 1024,
		},
	}
	deps := client.Dependencies{
		Sessions:    memstore.NewSessionStore(),
		Keys:        km,
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
func pollDeferredCredential(ctx context.Context, w *wallet.Wallet, resource wallet.ProtectedResourceClient, deferredEndpoint fapi.URL, first wallet.CredentialResult) (wallet.CredentialResult, error) {
	var err error
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

// driveModule drives one module instance through the full flow this
// binary's own scope covers, reading every endpoint from the Credential
// Issuer's metadata and its Authorization Server's, as a wallet does:
// the Credential Issuer is the offer's credential_issuer, or for the
// wallet_initiated variant the module's own, known out of band. offer
// is non-nil only for the issuer_initiated flow variant (already
// resolved by runModule, since it has to be captured before this module
// even reaches WAITING — see credentialoffer.go) — when set, its own
// issuer_state (if any) is echoed back on the PAR request (OID4VCI
// §5.1.3) and its own credential_configuration_ids[0] is used in place
// of run.credentialConfigurationID, matching what a spec-faithful
// wallet actually resolves the offer for. Every credential issued is
// verified before the flow goes on to its notification
// (verifyCredentials).
func (r moduleRunner) driveModule(ctx context.Context, module conformancesuite.SuiteModule, numCreds int, encrypted bool, offer *oid4vci.CredentialOffer) error {
	run, httpClient := r.WalletRun, r.HTTPClient
	w, err := newWallet(httpClient)
	if err != nil {
		return fmt.Errorf("build wallet: %w", err)
	}
	// The trailing slash matters: the suite publishes its Credential
	// Issuer Identifier with one, and §12.2.2's well-known URL keeps
	// it.
	credentialIssuer := module.URL + "/"
	credentialConfigurationID := run.credentialConfigurationID
	if offer != nil {
		credentialIssuer = offer.CredentialIssuer
		if len(offer.CredentialConfigurationIDs) > 0 {
			credentialConfigurationID = offer.CredentialConfigurationIDs[0]
		}
	}
	metadata, err := w.FetchCredentialIssuerMetadata(ctx, credentialIssuer)
	if err != nil {
		return fmt.Errorf("fetch credential issuer metadata: %w", err)
	}
	configuration, ok := metadata.CredentialConfigurationsSupported[credentialConfigurationID]
	if !ok {
		return fmt.Errorf("credential issuer metadata has no credential configuration %q", credentialConfigurationID)
	}
	if metadata.NonceEndpoint == nil {
		return fmt.Errorf("credential issuer metadata publishes no nonce_endpoint")
	}

	resource, err := r.authorizeAndGetProtectedResource(ctx, metadata, offer)
	if err != nil {
		return err
	}

	nonceResult, err := w.RequestNonce(ctx, *metadata.NonceEndpoint)
	if err != nil {
		return fmt.Errorf("request nonce: %w", err)
	}

	credRequest, holders, err := buildWalletCredentialRequest(w, credentialRequestParams{
		Run: run, Metadata: metadata, CredentialConfigurationID: credentialConfigurationID,
		NumCreds: numCreds, Encrypted: encrypted, CNonce: nonceResult.CNonce,
	})
	if err != nil {
		return err
	}
	credResult, err := w.RequestCredential(ctx, resource, metadata.CredentialEndpoint, credRequest)
	if err != nil {
		return fmt.Errorf("request credential: %w", err)
	}

	if credResult.TransactionID != "" {
		// §8.3's own "deferred at first response" case (VCICredentialIssuanceMode=deferred):
		// no credentials yet, just a transaction_id/interval — poll the
		// Deferred Credential Endpoint until the suite's own emulated
		// Issuer actually issues them.
		if metadata.DeferredCredentialEndpoint == nil {
			return fmt.Errorf("the credential was deferred, but the credential issuer metadata publishes no deferred_credential_endpoint")
		}
		credResult, err = pollDeferredCredential(ctx, w, resource, *metadata.DeferredCredentialEndpoint, credResult)
		if err != nil {
			return fmt.Errorf("poll deferred credential: %w", err)
		}
	}
	if len(credResult.Credentials) != numCreds {
		return fmt.Errorf("credential response carries %d credentials, want %d", len(credResult.Credentials), numCreds)
	}
	if err := verifyCredentials(ctx, r.Trust, configuration, credResult.Credentials, holders); err != nil {
		return fmt.Errorf("verify issued credentials: %w", err)
	}

	if credResult.NotificationID != "" {
		if metadata.NotificationEndpoint == nil {
			return fmt.Errorf("the credential response carries a notification_id, but the credential issuer metadata publishes no notification_endpoint")
		}
		if err := w.RequestNotification(ctx, resource, *metadata.NotificationEndpoint, wallet.NotificationRequest{
			NotificationID: credResult.NotificationID,
			Event:          oid4vci.NotificationEventCredentialAccepted,
		}); err != nil {
			return fmt.Errorf("request notification: %w", err)
		}
	}

	return nil
}

// authorizeAndGetProtectedResource is driveModule's own PAR ->
// authorize -> token half, at the Authorization Server metadata's
// authorization_servers names (the offer's, when its grant picks one),
// or the Credential Issuer itself when it names none (§12.2.4), asking
// for the Credential Issuer as the resource (RFC 8707) — split out
// purely to keep driveModule under the linter's own cognitive
// complexity ceiling. offer's own issuer_state (if any) is echoed back
// on the PAR request (OID4VCI §5.1.3), matching what a spec-faithful
// wallet does for the issuer_initiated flow variant.
func (r moduleRunner) authorizeAndGetProtectedResource(ctx context.Context, metadata oid4vci.Metadata, offer *oid4vci.CredentialOffer) (wallet.ProtectedResourceClient, error) {
	run, httpClient := r.WalletRun, r.HTTPClient
	asIssuer := metadata.CredentialIssuer.String()
	if len(metadata.AuthorizationServers) > 0 {
		asIssuer = metadata.AuthorizationServers[0].String()
	}
	var grant *oid4vci.GrantAuthorizationCode
	if offer != nil && offer.Grants != nil {
		grant = offer.Grants.AuthorizationCode
	}
	if grant != nil && grant.AuthorizationServer != "" {
		asIssuer = grant.AuthorizationServer
	}
	c, err := buildClient(ctx, run, asIssuer, httpClient)
	if err != nil {
		return nil, fmt.Errorf("build client: %w", err)
	}

	beginReq := client.BeginAuthorizationRequest{Scope: []string{run.scope}, Resource: []string{metadata.CredentialIssuer.String()}}
	if grant != nil && grant.IssuerState != "" {
		if err := extension.Set(&beginReq.Extensions, oid4vci.IssuerStateExtension, grant.IssuerState); err != nil {
			return nil, fmt.Errorf("set issuer_state extension: %w", err)
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

	// This process both began the flow and receives its callback.
	result, err := c.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: rawQuery, Session: session.Handle()})
	if err != nil {
		return nil, fmt.Errorf("complete authorization: %w", err)
	}
	success, ok := result.(client.CompletionSuccess)
	if !ok {
		return nil, fmt.Errorf("authorization was not completed successfully: %#v", result)
	}
	return c.ProtectedResource(success.Tokens), nil
}

// credentialRequestParams bundles buildWalletCredentialRequest's own
// per-call inputs — split out from a flat parameter list purely to
// stay under the linter's own parameter-count ceiling.
type credentialRequestParams struct {
	Run                       *walletRun
	Metadata                  oid4vci.Metadata
	CredentialConfigurationID string
	NumCreds                  int
	Encrypted                 bool
	CNonce                    string
}

// buildWalletCredentialRequest builds the CredentialRequest driveModule
// sends, including its p.Run.proofType-specific proof material and
// optional §10 request/response encryption, and returns the public
// keys it proved possession of, which the credentials must be bound to
// — split out purely to keep driveModule under the linter's own
// cognitive complexity ceiling.
func buildWalletCredentialRequest(w *wallet.Wallet, p credentialRequestParams) (wallet.CredentialRequest, []crypto.PublicKey, error) {
	run, numCreds, cNonce := p.Run, p.NumCreds, p.CNonce
	credentialIssuer := p.Metadata.CredentialIssuer.String()
	credRequest := wallet.CredentialRequest{
		CredentialConfigurationID: p.CredentialConfigurationID,
		// The Credential Issuer Identifier exactly as its metadata
		// publishes it (with a trailing slash, for the suite), since
		// this becomes the jwt-type proof's own "aud" claim. Unused for
		// the attestation proof type below, but harmless to leave set.
		CredentialIssuer: credentialIssuer,
		Nonce:            cNonce,
	}
	var signers []crypto.Signer
	switch run.proofType {
	case proofStrategyAttestation:
		// HAIP §4.5.1 Key Attestation (Appendix D/F.3): one Key
		// Attestation JWT attests numCreds fresh keys and is submitted
		// as the standalone "attestation" proof — no per-credential jwt
		// proof needed, see buildKeyAttestationProof's own doc comment.
		attestedKeys, genErr := generateAttestedKeys(numCreds)
		if genErr != nil {
			return wallet.CredentialRequest{}, nil, fmt.Errorf("generate attested keys: %w", genErr)
		}
		attestationJWT, err := buildKeyAttestationProof(w, run, attestedKeys, cNonce, false)
		if err != nil {
			return wallet.CredentialRequest{}, nil, fmt.Errorf("build key attestation proof: %w", err)
		}
		credRequest.Attestation = attestationJWT
		signers = attestedKeys

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
		jwtProofs, attestedKeys, err := buildJWTKeyAttestationProofs(w, run, credentialIssuer, numCreds, cNonce)
		if err != nil {
			return wallet.CredentialRequest{}, nil, err
		}
		credRequest.JWTProofs = jwtProofs
		signers = attestedKeys

	default:
		holderKeys, err := generateHolderKeys(numCreds)
		if err != nil {
			return wallet.CredentialRequest{}, nil, err
		}
		credRequest.Keys = holderKeys
		signers = holderKeys
	}
	if p.Encrypted {
		recipientJWK, encErr := credentialRequestEncryptionJWK(p.Metadata)
		if encErr != nil {
			return wallet.CredentialRequest{}, nil, fmt.Errorf("credential request encryption key: %w", encErr)
		}
		credRequest.RequestEncryption = &wallet.RequestEncryption{RecipientJWK: recipientJWK, Enc: encryptionEnc}
		credRequest.ResponseEncryption = &wallet.ResponseEncryption{Enc: encryptionEnc}
	}
	holders := make([]crypto.PublicKey, len(signers))
	for i, signer := range signers {
		holders[i] = signer.Public()
	}
	return credRequest, holders, nil
}

// buildJWTKeyAttestationProofs builds one jwt-type proof per credential,
// each embedding the same Key Attestation JWT covering every attested
// key — see buildWalletCredentialRequest's proofStrategyJWTKeyAttestation
// case for why the attestation is shared rather than per-key — and
// returns the attested keys.
func buildJWTKeyAttestationProofs(w *wallet.Wallet, run *walletRun, credentialIssuer string, numCreds int, cNonce string) ([]string, []crypto.Signer, error) {
	attestedKeys, err := generateAttestedKeys(numCreds)
	if err != nil {
		return nil, nil, fmt.Errorf("generate attested keys: %w", err)
	}
	attestationJWT, err := buildKeyAttestationProof(w, run, attestedKeys, cNonce, true)
	if err != nil {
		return nil, nil, fmt.Errorf("build key attestation proof: %w", err)
	}
	jwtProofs := make([]string, numCreds)
	for i, signer := range attestedKeys {
		proof, err := w.GenerateProofWithKeyAttestation(signer, credentialIssuer, cNonce, attestationJWT)
		if err != nil {
			return nil, nil, fmt.Errorf("generate jwt proof with key attestation %d: %w", i, err)
		}
		jwtProofs[i] = proof
	}
	return jwtProofs, attestedKeys, nil
}

// generateHolderKeys generates n fresh P-256 holder keys for the
// default (plain jwt proof) strategy.
func generateHolderKeys(n int) ([]crypto.Signer, error) {
	holderKeys := make([]crypto.Signer, n)
	for i := range holderKeys {
		holderKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate holder key: %w", err)
		}
		holderKeys[i] = holderKey
	}
	return holderKeys, nil
}

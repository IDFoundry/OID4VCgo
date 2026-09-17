package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/issuer"
	oid4vcigostorage "github.com/idfoundry/oid4vcigo/storage"
)

const httpFetchTimeout = 10 * time.Second

// clientAttestationAlgorithm is the one algorithm this binary accepts
// a Client Attestation/PoP JWT signed with — ES256, HAIP 1.0 §7's own
// minimum, matching every other algorithm choice this binary and its
// Phase 1 siblings make.
const clientAttestationAlgorithm = fapi.ES256

// conformanceBatchSize is this binary's own advertised
// "batch_credential_issuance.batch_size" (§12.2.4) — issuer.Issuer
// already fully implements batch issuance (RequestCredential resolves
// and issues one Credential per proof in the proofs array); this
// binary just never opted in before. Not deployment-specific, so a
// fixed constant rather than a Config field, matching issProofAlgs's
// own "conformance-fixed choice, not configurable" shape just below.
const conformanceBatchSize = 5

// credentialRequestDecryptionKeyID is this binary's own fixed "kid"
// for Config.CredentialRequestDecryptionKeyPEM's own public half,
// published as Metadata's own "credential_request_encryption.jwks"
// entry — not deployment-specific, so a hardcoded constant rather
// than a Config field, matching conformanceBatchSize's own precedent.
const credentialRequestDecryptionKeyID = "credential-request-encryption-key-1" //nolint:gosec // G101 false positive: this is a public "kid" identifier published in Metadata, not a credential or secret

// credentialEncValuesSupported is this binary's own advertised §10
// "enc_values_supported" for both Credential Request decryption and
// Credential Response encryption — HAIP's own A128GCM/A256GCM
// convention (already used for verifier.Config.EncValuesSupported
// elsewhere in this repo), deliberately excluding jwe.A192GCM even
// though internal/jwe implements it: this is what makes "unsupported
// algorithm" a real, testable condition for this issuer rather than a
// vacuous one.
var credentialEncValuesSupported = []jwe.Enc{jwe.A128GCM, jwe.A256GCM}

// jwtProofCredentialConfiguration builds the jwk-binding/jwt-proof-type
// shape every CredentialConfiguration this binary advertises shares —
// Format and the format-specific metadata parameter (VCT or DocType)
// are the caller's own job to set afterward, the one thing that
// actually differs between the "dc+sd-jwt" and "mso_mdoc"
// configurations below.
func jwtProofCredentialConfiguration(scope string, proofSigningAlgs []string) issuer.CredentialConfiguration {
	return issuer.CredentialConfiguration{
		Scope:                                scope,
		CryptographicBindingMethodsSupported: []string{"jwk"},
		ProofTypesSupported: map[string]issuer.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: proofSigningAlgs},
		},
	}
}

// newServerMux builds the full wiring — a real fapigo/server.Server
// (FAPI 2.0 Security Profile Final, Wallet Attestation client
// authentication, DPoP) paired with a real oid4vcigo/issuer.Issuer via
// fapigo/resource.Verifier, per issuer/authorization_server.go's and
// issuer/resource_verifier.go's own integration recipes — plus the
// HTTP router tying both together. Factored out from main so a future
// smoke test can stand this up directly, matching
// cmd/conformance-verifier's own newServerMux-equivalent precedent
// (here, main itself, kept small) — see README's own "Status" section
// for how far this has actually been exercised.
func newServerMux(cfg Config) (*http.ServeMux, error) {
	issuerURL, err := cfg.issuerURL()
	if err != nil {
		return nil, fmt.Errorf("issuer url: %w", err)
	}
	parURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/par")
	if err != nil {
		return nil, err
	}
	authorizationURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/authorize")
	if err != nil {
		return nil, err
	}
	tokenURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/token")
	if err != nil {
		return nil, err
	}
	jwksURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/jwks")
	if err != nil {
		return nil, err
	}
	credentialURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/credential")
	if err != nil {
		return nil, err
	}
	nonceURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/nonce")
	if err != nil {
		return nil, err
	}

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
	})
	if err != nil {
		return nil, err
	}
	fetcher, err := fapihttp.New(&http.Client{Timeout: httpFetchTimeout}, fapihttp.Config{
		MaxResponseBytes: 1 << 20, RequestTimeout: httpFetchTimeout, MaxRedirects: 2,
	})
	if err != nil {
		return nil, err
	}
	// Registers the attester's own public key(s) — even under
	// ClientAuthMethodAttestation, fapigo/server resolves a Client
	// Attestation JWT's own verification key via this same
	// Dependencies.ClientKeys, keyed by client ID (confirmed against
	// server/client_auth_attestation.go's own resolveClientKey call) —
	// see Config.Client's own doc comment.
	clientKeySpecs := []ephemeral.ClientKeySpec{
		{ClientID: fapi.ClientID(cfg.Client.ID), JWKS: cfg.Client.AttesterJWKS},
	}
	allowedScopes := []string{cfg.Scope}
	if cfg.Mdoc != nil {
		allowedScopes = append(allowedScopes, cfg.Mdoc.Scope)
	}
	registeredClients := []storage.RegisteredClient{}
	for _, cc := range []*ConfigClient{&cfg.Client, cfg.Client2} {
		if cc == nil {
			continue
		}
		c, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                         fapi.ClientID(cc.ID),
			RedirectURIs:               registeredRedirectURIs(cc.RedirectURIs),
			ClientAuthMethod:           storage.ClientAuthMethodAttestation,
			ExpectedAttesterIssuer:     cc.ExpectedAttesterIssuer,
			ClientAttestationAlgorithm: clientAttestationAlgorithm,
			AllowedScopes:              allowedScopes,
		})
		if err != nil {
			return nil, fmt.Errorf("register client %s: %w", cc.ID, err)
		}
		registeredClients = append(registeredClients, c)
	}
	if cfg.Client2 != nil {
		clientKeySpecs = append(clientKeySpecs, ephemeral.ClientKeySpec{
			ClientID: fapi.ClientID(cfg.Client2.ID), JWKS: cfg.Client2.AttesterJWKS,
		})
	}
	clientKeys, err := ephemeral.NewClientKeySource(fetcher, clientKeySpecs)
	if err != nil {
		return nil, err
	}
	clientRepo := memstore.NewClientRepository(registeredClients)
	replayStore := memstore.NewReplayStore()

	accessTokens, err := server.NewJWTAccessTokens(keyManager, fapi.ES256)
	if err != nil {
		return nil, err
	}
	resourceAccessTokens, err := fapires.NewJWTAccessTokens(
		selfIssuerKeySource{keyManager: keyManager}, issuerURL, issuerURL.String(),
		fapi.ES256, srvLimits().AccessTokenLifetime, 8,
	)
	if err != nil {
		return nil, err
	}

	limits := srvLimits()
	algorithms := server.RecommendedAlgorithms()
	algorithms.ClientAttestation = server.AlgorithmSet{clientAttestationAlgorithm}
	algorithms.ClientAttestationPoP = server.AlgorithmSet{clientAttestationAlgorithm}

	srvCfg := server.Config{
		Issuer: issuerURL,
		Endpoints: server.Endpoints{
			Authorization: authorizationURL, Token: tokenURL,
			PushedAuthorizationRequest: parURL, JWKS: jwksURL,
		},
		Profile:                              server.ProfileFAPISecurity,
		Algorithms:                           algorithms,
		Limits:                               limits,
		Assurance:                            server.AssuranceDevelopment,
		OAuthOnly:                            true,
		AttestationBasedClientAuthentication: true,
	}
	srvDeps := server.Dependencies{
		Clients:      clientRepo,
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       replayStore,
		ClientKeys:   clientKeys,
		Keys:         keyManager,
		AccessTokens: accessTokens,
		Revocation:   memstore.NewRevocationStore(),
		Clock:        server.SystemClock{},
		Random:       rand.Reader,
	}
	srv, err := server.New(srvCfg, srvDeps)
	if err != nil {
		return nil, fmt.Errorf("server.New: %w", err)
	}

	resourceVerifier, err := fapires.NewVerifier(fapires.Config{
		Limits: fapires.Limits{MaxDPoPProofAge: limits.MaxDPoPProofAge, MaxClockSkew: limits.MaxClockSkew},
	}, fapires.Dependencies{
		AccessTokens: resourceAccessTokens, Replay: replayStore,
		Revocation: memstore.NewRevocationStore(), Clock: fapires.SystemClock{},
	})
	if err != nil {
		return nil, fmt.Errorf("resource.NewVerifier: %w", err)
	}

	issuerSigningKey, err := cfg.credentialIssuerSigningKey()
	if err != nil {
		return nil, fmt.Errorf("credential issuer signing key: %w", err)
	}
	issuerCertificate, err := cfg.credentialIssuerCertificate()
	if err != nil {
		return nil, fmt.Errorf("credential issuer certificate: %w", err)
	}
	requestDecryptionKey, err := cfg.credentialRequestDecryptionKey()
	if err != nil {
		return nil, fmt.Errorf("credential request decryption key: %w", err)
	}
	issProofAlgs := []string{"ES256"}
	sdjwtConfig := jwtProofCredentialConfiguration(cfg.Scope, issProofAlgs)
	sdjwtConfig.Format, sdjwtConfig.VCT = sdjwtvc.CredentialFormat, cfg.VCT
	credentialConfigs := map[string]issuer.CredentialConfiguration{
		cfg.CredentialConfigurationID: sdjwtConfig,
	}
	issDeps := issuer.Dependencies{
		Nonces: oid4vcigostorage.NewNonceStore(),
		Clock:  issuer.ClockFunc(time.Now),
		Random: rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{
			Signer: issuerSigningKey, Alg: jose.ES256,
			IssuerCertificate: issuerCertificate,
		},
	}
	if cfg.Mdoc != nil {
		// Same issuer identity as the "dc+sd-jwt" CredentialConfiguration
		// above (issuerSigningKey/issuerCertificate) — one Credential
		// Issuer publishing two formats, not a second throwaway key.
		mdocConfig := jwtProofCredentialConfiguration(cfg.Mdoc.Scope, issProofAlgs)
		mdocConfig.Format, mdocConfig.DocType = mdoc.CredentialFormat, cfg.Mdoc.DocType
		credentialConfigs[cfg.Mdoc.CredentialConfigurationID] = mdocConfig
		issDeps.MdocSigner = &issuer.MdocSigner{
			Signer: issuerSigningKey, Alg: cose.ES256,
			X5Chain: [][]byte{issuerCertificate.Raw},
		}
	}

	iss, err := issuer.New(issuer.Config{
		Issuer:                  issuerURL,
		Endpoints:               issuer.Endpoints{Credential: credentialURL, Nonce: nonceURL},
		Limits:                  issuer.Limits{NonceLifetime: limits.MaxDPoPProofAge},
		BatchCredentialIssuance: &issuer.BatchCredentialIssuance{BatchSize: conformanceBatchSize},
		RequestEncryption: &issuer.RequestEncryptionSupport{
			Keys:               []issuer.RequestDecryptionKey{{KeyID: credentialRequestDecryptionKeyID, PrivateKey: requestDecryptionKey}},
			EncValuesSupported: credentialEncValuesSupported,
		},
		ResponseEncryption: &issuer.ResponseEncryptionSupport{
			EncValuesSupported: credentialEncValuesSupported,
		},
		CredentialConfigurationsSupported: credentialConfigs,
	}, issDeps)
	if err != nil {
		return nil, fmt.Errorf("issuer.New: %w", err)
	}

	consent := newConsentHandler(srv, clientRepo, server.SystemClock{}, cfg.DefaultSubject)
	credentialURLValue := credentialURL.URL()
	return newRouter(srv, iss, resourceVerifier, consent, &credentialURLValue, cfg, issuerSigningKey, issuerCertificate), nil
}

// srvLimits are this binary's own FAPI 2.0 Limits — server.RecommendedLimits
// plus the Client Attestation-specific bounds
// AttestationBasedClientAuthentication needs, which that preset
// deliberately doesn't set (see its own doc comment on why: most
// callers never register an attestation-authenticated client).
func srvLimits() server.Limits {
	limits := server.RecommendedLimits()
	limits.MaxClientAttestationLifetime = 24 * time.Hour
	limits.MaxClientAttestationPoPAge = limits.MaxDPoPProofAge
	return limits
}

func registeredRedirectURIs(raw []string) []fapi.RegisteredRedirectURI {
	out := make([]fapi.RegisteredRedirectURI, len(raw))
	for i, u := range raw {
		out[i] = fapi.RegisteredRedirectURI(u)
	}
	return out
}

// selfIssuerKeySource resolves this same process's own access-token
// signing key directly from its in-memory keyManager — matches
// FAPIgo's own cmd/conformance-as/resource.go identically, including
// why: a loopback to this binary's own /jwks endpoint would hit its
// self-signed listener cert with a standard net/http.Client, which
// (unlike the OIDF suite's own outbound client) does not trust it.
type selfIssuerKeySource struct {
	keyManager *ephemeral.KeyManager
}

func (s selfIssuerKeySource) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	pub, err := s.keyManager.PublicKey(ctx, keys.AccessTokenSigning, req.Algorithm)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{
		{KeyID: pub.KeyID, Algorithm: req.Algorithm, PublicKey: pub.PublicKey},
	}}, nil
}

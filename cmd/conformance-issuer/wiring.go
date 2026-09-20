package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/issuer"
	oid4vcgostorage "github.com/idfoundry/oid4vcgo/storage"
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

// credentialZipValuesSupported is this binary's own advertised §10
// "zip_values_supported" — internal/jwe/issuer/encryption.go already
// fully implement RFC 7516's only registered "zip" value (raw
// DEFLATE), this binary just never turned it on: confirmed live via
// the OIDF conformance suite's own oid4vci-1_0-issuer-happy-flow
// module under the vci_credential_encryption=encrypted variant, which
// optionally adds "zip":"DEF" to its own credential_response_encryption
// request and expects it honored, not rejected with
// invalid_encryption_parameters.
var credentialZipValuesSupported = []jwe.Zip{jwe.DEF}

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
		ProofTypesSupported: map[string]oid4vci.ProofTypeConfiguration{
			oid4vci.ProofTypeJWT: {ProofSigningAlgValuesSupported: proofSigningAlgs},
		},
	}
}

// newServerMux builds the full wiring — a real fapigo/server.Server
// (FAPI 2.0 Security Profile Final, Wallet Attestation client
// authentication, DPoP) paired with a real oid4vcgo/issuer.Issuer via
// fapigo/resource.Verifier, per issuer/authorization_server.go's and
// issuer/resource_verifier.go's own integration recipes — plus the
// HTTP router tying both together. Factored out from main so a future
// smoke test can stand this up directly, matching
// cmd/conformance-verifier's own newServerMux-equivalent precedent
// (here, main itself, kept small) — see README's own "Status" section
// for how far this has actually been exercised.
func newServerMux(cfg Config) (*http.ServeMux, error) {
	endpoints, err := resolveIssuerEndpoints(cfg)
	if err != nil {
		return nil, err
	}
	issuerURL, parURL, authorizationURL, tokenURL, jwksURL, credentialURL, nonceURL :=
		endpoints.issuer, endpoints.par, endpoints.authorization, endpoints.token, endpoints.jwks, endpoints.credential, endpoints.nonce

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{
		keys.AccessTokenSigning: fapi.ES256,
	})
	if err != nil {
		return nil, err
	}
	clientRepo, clientKeys, err := buildClientRegistration(cfg)
	if err != nil {
		return nil, err
	}
	replayStore := memstore.NewReplayStore()
	// revocationStore is shared between srvDeps (which records a
	// revocation when the AS detects authorization-code reuse, RFC 6749
	// §4.1.2) and resourceVerifier (which checks it on every Credential
	// Endpoint call) — two independent stores would let the resource
	// verifier keep accepting an access token the AS just revoked,
	// exactly the gap the OIDF conformance suite's own
	// attempt-reuse-authorization-code-after-one-second module flags
	// (WARNING: "resource endpoint returned a different http status
	// than expected" after "Testing if access token was revoked after
	// authorization code reuse"). Mirrors FAPIgo's own
	// cmd/conformance-as/wiring.go, which wires the identical shared
	// store for the same reason.
	revocationStore := memstore.NewRevocationStore()

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

	// oid4vci.IssuerStateExtension registration is what OID4VCI 1.0
	// §4.1.1's own issuer_state authorization parameter needs to
	// survive PAR at all — without it, fapigo/server silently drops
	// issuer_state instead of rejecting it outright (see
	// issuer/authorization_server.go's own "Registering issuer_state"
	// doc comment), which the issuer_initiated flow variant's own
	// Credential Offer relies on the Wallet echoing back.
	extensions, err := extension.NewRegistry(oid4vci.IssuerStateExtension)
	if err != nil {
		return nil, fmt.Errorf("extension.NewRegistry: %w", err)
	}

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
		Extensions:                           extensions,
	}
	srvDeps := server.Dependencies{
		Clients:      clientRepo,
		Transactions: memstore.NewTransactionStore(),
		Grants:       memstore.NewGrantStore(),
		Replay:       replayStore,
		ClientKeys:   clientKeys,
		Keys:         keyManager,
		AccessTokens: accessTokens,
		Revocation:   revocationStore,
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
		Revocation: revocationStore, Clock: fapires.SystemClock{},
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
	issDeps := issuer.Dependencies{
		Nonces: oid4vcgostorage.NewNonceStore(),
		Clock:  issuer.ClockFunc(time.Now),
		Random: rand.Reader,
		SDJWTSigner: &issuer.SDJWTSigner{
			Signer: issuerSigningKey, Alg: jose.ES256,
			IssuerCertificate: issuerCertificate,
		},
	}
	attestationVerifier, err := addKeyAttestationProofType(cfg, &sdjwtConfig)
	if err != nil {
		return nil, err
	}
	issDeps.AttestationVerifier = attestationVerifier
	credentialConfigs := map[string]issuer.CredentialConfiguration{
		cfg.CredentialConfigurationID: sdjwtConfig,
	}
	if cfg.Mdoc != nil {
		mdocConfig := jwtProofCredentialConfiguration(cfg.Mdoc.Scope, issProofAlgs)
		mdocConfig.Format, mdocConfig.DocType = mdoc.CredentialFormat, cfg.Mdoc.DocType
		credentialConfigs[cfg.Mdoc.CredentialConfigurationID] = mdocConfig
		mdocSigner, err := buildMdocSigner(cfg, issuerSigningKey, issuerCertificate)
		if err != nil {
			return nil, err
		}
		issDeps.MdocSigner = mdocSigner
	}

	iss, err := issuer.New(issuer.Config{
		Assurance:               issuer.AssuranceDevelopment,
		Issuer:                  issuerURL,
		Endpoints:               issuer.Endpoints{Credential: credentialURL, Nonce: nonceURL},
		Limits:                  issuer.Limits{NonceLifetime: limits.MaxDPoPProofAge},
		BatchCredentialIssuance: &oid4vci.BatchCredentialIssuance{BatchSize: conformanceBatchSize},
		RequestEncryption: &issuer.RequestEncryptionSupport{
			Keys:               []issuer.RequestDecryptionKey{{KeyID: credentialRequestDecryptionKeyID, PrivateKey: requestDecryptionKey}},
			EncValuesSupported: credentialEncValuesSupported,
			ZipValuesSupported: credentialZipValuesSupported,
		},
		ResponseEncryption: &issuer.ResponseEncryptionSupport{
			EncValuesSupported: credentialEncValuesSupported,
			ZipValuesSupported: credentialZipValuesSupported,
		},
		CredentialConfigurationsSupported: credentialConfigs,
	}, issDeps)
	if err != nil {
		return nil, fmt.Errorf("issuer.New: %w", err)
	}

	consent := newConsentHandler(srv, clientRepo, server.SystemClock{}, cfg.DefaultSubject)
	credentialURLValue := credentialURL.URL()
	return newRouter(srv, iss, resourceVerifier, consent, &credentialURLValue, cfg, metadataSigningIdentity{Signer: issuerSigningKey, Cert: issuerCertificate})
}

// issuerEndpoints bundles every fapi.URL newServerMux's own router and
// server config need, parsed once up front by resolveIssuerEndpoints.
type issuerEndpoints struct {
	issuer, par, authorization, token, jwks, credential, nonce fapi.URL
}

// resolveIssuerEndpoints parses cfg.Issuer's own well-known sub-paths —
// extracted out of newServerMux purely to keep its own cognitive
// complexity down (this repeated parse-then-check-error shape was
// newServerMux's single largest contributor).
func resolveIssuerEndpoints(cfg Config) (issuerEndpoints, error) {
	issuerURL, err := cfg.issuerURL()
	if err != nil {
		return issuerEndpoints{}, fmt.Errorf("issuer url: %w", err)
	}
	parURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/par")
	if err != nil {
		return issuerEndpoints{}, err
	}
	authorizationURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/authorize")
	if err != nil {
		return issuerEndpoints{}, err
	}
	tokenURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/token")
	if err != nil {
		return issuerEndpoints{}, err
	}
	jwksURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/jwks")
	if err != nil {
		return issuerEndpoints{}, err
	}
	credentialURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/credential")
	if err != nil {
		return issuerEndpoints{}, err
	}
	nonceURL, err := fapi.ParseEndpointURL(cfg.Issuer + "/nonce")
	if err != nil {
		return issuerEndpoints{}, err
	}
	return issuerEndpoints{
		issuer: issuerURL, par: parURL, authorization: authorizationURL,
		token: tokenURL, jwks: jwksURL, credential: credentialURL, nonce: nonceURL,
	}, nil
}

// buildClientRegistration registers cfg.Client/Client2 (whichever are
// set) as HAIP-profiled, Client-Attestation-authenticated clients, and
// resolves both their own attester JWKS into one shared key source —
// extracted out of newServerMux purely to keep its own cognitive
// complexity down (the loop below, plus its own nested branches, was
// newServerMux's second-largest contributor).
func buildClientRegistration(cfg Config) (clientRepo *memstore.ClientRepository, clientKeys *ephemeral.ClientKeySource, err error) {
	fetcher, err := fapihttp.New(&http.Client{Timeout: httpFetchTimeout}, fapihttp.Config{
		MaxResponseBytes: 1 << 20, RequestTimeout: httpFetchTimeout, MaxRedirects: 2,
	})
	if err != nil {
		return nil, nil, err
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
		c, regErr := storage.NewRegisteredClient(storage.RegisteredClientConfig{
			ID:                         fapi.ClientID(cc.ID),
			RedirectURIs:               registeredRedirectURIs(cc.RedirectURIs),
			ClientAuthMethod:           storage.ClientAuthMethodAttestation,
			ExpectedAttesterIssuer:     cc.ExpectedAttesterIssuer,
			ClientAttestationAlgorithm: clientAttestationAlgorithm,
			AllowedScopes:              allowedScopes,
		})
		if regErr != nil {
			return nil, nil, fmt.Errorf("register client %s: %w", cc.ID, regErr)
		}
		registeredClients = append(registeredClients, c)
	}
	if cfg.Client2 != nil {
		clientKeySpecs = append(clientKeySpecs, ephemeral.ClientKeySpec{
			ClientID: fapi.ClientID(cfg.Client2.ID), JWKS: cfg.Client2.AttesterJWKS,
		})
	}
	clientKeys, err = ephemeral.NewClientKeySource(fetcher, clientKeySpecs)
	if err != nil {
		return nil, nil, err
	}
	return memstore.NewClientRepository(registeredClients), clientKeys, nil
}

// addKeyAttestationProofType mutates sdjwtConfig in place to
// additionally advertise the "attestation" proof type (OID4VCI
// Appendix F.3) when cfg.KeyAttestation is set — a Wallet may use
// either "jwt" or "attestation" for the same credential_configuration_id,
// and issuer.RequestCredential dispatches per-request on which proof
// type key the request's own "proofs" object contains, so this leaves
// every existing "jwt"-proof flow completely unaffected — and returns
// the AttestationVerifier issDeps needs, or nil when key attestation
// isn't configured. Extracted out of newServerMux purely to keep its
// own cognitive complexity down.
// buildMdocSigner picks the mdoc CredentialConfiguration's own signing
// identity: cfg.Mdoc's own dedicated ISO/IEC 18013-5 Annex B-compliant
// Document Signer identity (internal/conformancecert.GenerateMdocDocumentSigner)
// when configured, falling back to the shared "dc+sd-jwt" issuer
// identity otherwise — see conformanceconfig.MdocConfig's own doc
// comment on why a dedicated identity exists and why the fallback
// stays supported (cmd/conformance-issuer/mdoc_test.go's own minimal
// MdocConfig never sets the three new fields).
func buildMdocSigner(cfg Config, fallbackKey *ecdsa.PrivateKey, fallbackCert *x509.Certificate) (*issuer.MdocSigner, error) {
	key, cert, ok, err := cfg.mdocSignerKeyAndCert()
	if err != nil {
		return nil, fmt.Errorf("mdoc signer: %w", err)
	}
	if !ok {
		key, cert = fallbackKey, fallbackCert
	}
	return &issuer.MdocSigner{
		Signer: key, Alg: cose.ES256,
		X5Chain: [][]byte{cert.Raw},
	}, nil
}

func addKeyAttestationProofType(cfg Config, sdjwtConfig *issuer.CredentialConfiguration) (issuer.AttestationVerifier, error) {
	if cfg.KeyAttestation == nil {
		return nil, nil
	}
	sdjwtConfig.ProofTypesSupported[oid4vci.ProofTypeAttestation] = haip.RecommendedAttestationProofType()
	trustedKey, err := jwk.ParsePublicKey(cfg.KeyAttestation.TrustedJWK)
	if err != nil {
		return nil, fmt.Errorf("key attestation trusted jwk: %w", err)
	}
	return fixedKeyAttestationVerifier{pub: trustedKey, alg: jose.ES256}, nil
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

// fixedKeyAttestationVerifier trusts exactly one public key for every
// Key Attestation JWT, ignoring its own "iss"/"kid" — a conformance
// fixture's own trust policy (see issuer.AttestationVerifier's own
// doc comment: "entirely this issuer's own trust policy"), not
// something a real deployment would do.
type fixedKeyAttestationVerifier struct {
	pub crypto.PublicKey
	alg jose.Alg
}

func (v fixedKeyAttestationVerifier) ResolveAttestationKey(context.Context, attestation.KeyAttestation) (crypto.PublicKey, jose.Alg, error) {
	return v.pub, v.alg, nil
}

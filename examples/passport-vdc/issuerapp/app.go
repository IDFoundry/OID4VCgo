package issuerapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/issuer"
	oid4vcgostorage "github.com/idfoundry/oid4vcgo/storage"
)

// Credential configuration IDs and the scopes that request them.
const (
	MdocConfigurationID  = "passport_mdoc"
	SDJWTConfigurationID = "passport_sdjwt"
	MdocScope            = "passport_mdoc"
	SDJWTScope           = "passport_sdjwt"
)

// VCTPath is where this issuer serves its SD-JWT VC type metadata,
// relative to IssuerURL; the full URL is the credential's vct.
const VCTPath = "/vct/passport/1"

const attestationAlgorithm = fapi.ES256

// App is a running passport-vdc issuer.
type App struct {
	cfg              Config
	issuerURL        fapi.URL
	vct              string
	credentialURL    url.URL
	now              func() time.Time
	server           *server.Server
	issuer           *issuer.Issuer
	resourceVerifier *fapires.Verifier
	transactions     *transactions
	requestURIs      *ttlMap[string]             // PAR request_uri → transaction ID
	interactions     *ttlMap[pendingInteraction] // interaction handle → approval
	metadataSigner   *ecdsa.PrivateKey
	metadataCert     *x509.Certificate
	caCert           *x509.Certificate
	handler          http.Handler
}

// New wires an App from cfg. Signing keys are generated per process —
// restarting the issuer invalidates every credential it issued, which
// is fine for a demo.
func New(cfg Config) (*App, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	a := &App{cfg: cfg, now: time.Now}
	var err error
	if a.issuerURL, err = parseIssuerURL(cfg.IssuerURL); err != nil {
		return nil, err
	}
	a.vct = cfg.IssuerURL + VCTPath
	a.transactions = newTransactions(a.now, cfg.transactionLifetime())
	a.requestURIs = newTTLMap[string](a.now)
	a.interactions = newTTLMap[pendingInteraction](a.now)

	if err := a.buildAuthorizationServer(); err != nil {
		return nil, err
	}
	if err := a.buildIssuer(); err != nil {
		return nil, err
	}
	a.handler = a.routes()
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

func parseIssuerURL(raw string) (fapi.URL, error) {
	var opts []fapi.URLOption
	if strings.HasPrefix(raw, "http://") {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	u, err := fapi.ParseIssuerURL(raw, opts...)
	if err != nil {
		return fapi.URL{}, fmt.Errorf("issuerapp: issuer URL: %w", err)
	}
	return u, nil
}

func (a *App) endpoint(path string) (fapi.URL, error) {
	raw := a.cfg.IssuerURL + path
	var opts []fapi.URLOption
	if strings.HasPrefix(raw, "http://") {
		opts = append(opts, fapi.AllowLoopbackHTTP())
	}
	u, err := fapi.ParseEndpointURL(raw, opts...)
	if err != nil {
		return fapi.URL{}, fmt.Errorf("issuerapp: endpoint %s: %w", path, err)
	}
	return u, nil
}

func (a *App) buildAuthorizationServer() error {
	var par, authorize, token, jwks fapi.URL
	for path, dst := range map[string]*fapi.URL{"/par": &par, "/authorize": &authorize, "/token": &token, "/jwks": &jwks} {
		u, err := a.endpoint(path)
		if err != nil {
			return err
		}
		*dst = u
	}

	keyManager, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	if err != nil {
		return fmt.Errorf("issuerapp: key manager: %w", err)
	}
	clients, clientKeys, err := a.registerWallet()
	if err != nil {
		return err
	}
	accessTokens, err := server.NewJWTAccessTokens(keyManager, fapi.ES256)
	if err != nil {
		return fmt.Errorf("issuerapp: access tokens: %w", err)
	}
	// issuer_state must be registered to survive PAR at all; the value
	// is captured by this app's own PAR handler (see the package doc).
	extensions, err := extension.NewRegistry(oid4vci.IssuerStateExtension)
	if err != nil {
		return fmt.Errorf("issuerapp: extensions: %w", err)
	}

	limits := server.RecommendedLimits()
	limits.MaxClientAttestationLifetime = 24 * time.Hour
	limits.MaxClientAttestationPoPAge = limits.MaxDPoPProofAge
	algorithms := server.RecommendedAlgorithms()
	algorithms.ClientAttestation = server.AlgorithmSet{attestationAlgorithm}
	algorithms.ClientAttestationPoP = server.AlgorithmSet{attestationAlgorithm}

	replay := memstore.NewReplayStore()
	revocation := memstore.NewRevocationStore()
	a.server, err = server.New(server.Config{
		Issuer:                               a.issuerURL,
		Endpoints:                            server.Endpoints{Authorization: authorize, Token: token, PushedAuthorizationRequest: par, JWKS: jwks},
		Profile:                              server.ProfileFAPISecurity,
		Algorithms:                           algorithms,
		Limits:                               limits,
		Assurance:                            server.AssuranceDevelopment,
		OAuthOnly:                            true,
		AttestationBasedClientAuthentication: true,
		Extensions:                           extensions,
	}, server.Dependencies{
		Clients: clients, Transactions: memstore.NewTransactionStore(), Grants: memstore.NewGrantStore(),
		Replay: replay, ClientKeys: clientKeys, Keys: keyManager, AccessTokens: accessTokens,
		Revocation: revocation, Clock: server.SystemClock{}, Random: rand.Reader,
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
	})
	if err != nil {
		return fmt.Errorf("issuerapp: server.New: %w", err)
	}

	resourceTokens, err := fapires.NewJWTAccessTokens(selfIssuerKeys{keyManager}, a.issuerURL, a.issuerURL.String(), fapi.ES256, limits.AccessTokenLifetime, 8)
	if err != nil {
		return fmt.Errorf("issuerapp: resource access tokens: %w", err)
	}
	a.resourceVerifier, err = fapires.NewVerifier(fapires.Config{
		Limits: fapires.Limits{MaxDPoPProofAge: limits.MaxDPoPProofAge, MaxClockSkew: limits.MaxClockSkew},
	}, fapires.Dependencies{AccessTokens: resourceTokens, Replay: replay, Revocation: revocation, Clock: fapires.SystemClock{}})
	if err != nil {
		return fmt.Errorf("issuerapp: resource verifier: %w", err)
	}
	return nil
}

// registerWallet registers the demo Wallet as a Wallet-Attestation
// client whose attestations are verified against the configured Wallet
// Provider key.
func (a *App) registerWallet() (*memstore.ClientRepository, *ephemeral.ClientKeySource, error) {
	w := a.cfg.Wallet
	redirects := make([]fapi.RegisteredRedirectURI, len(w.RedirectURIs))
	for i, u := range w.RedirectURIs {
		redirects[i] = fapi.RegisteredRedirectURI(u)
	}
	c, err := storage.NewRegisteredClient(storage.RegisteredClientConfig{
		ID:                         fapi.ClientID(w.ClientID),
		RedirectURIs:               redirects,
		ClientAuthMethod:           storage.ClientAuthMethodAttestation,
		ExpectedAttesterIssuer:     w.ProviderIssuer,
		ClientAttestationAlgorithm: attestationAlgorithm,
		AllowedScopes:              []string{MdocScope, SDJWTScope},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: register wallet: %w", err)
	}
	// The provider key is inline, so nothing is ever fetched; the
	// fetcher only satisfies ClientKeySource's constructor.
	fetcher, err := fapihttp.New(&http.Client{Timeout: 10 * time.Second}, fapihttp.Config{
		MaxResponseBytes: 1 << 16, RequestTimeout: 10 * time.Second, MaxRedirects: 2,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: fetcher: %w", err)
	}
	clientKeys, err := ephemeral.NewClientKeySource(fetcher, []ephemeral.ClientKeySpec{{ClientID: fapi.ClientID(w.ClientID), JWKS: w.ProviderJWKS}})
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: wallet provider keys: %w", err)
	}
	return memstore.NewClientRepository([]storage.RegisteredClient{c}), clientKeys, nil
}

func (a *App) buildIssuer() error {
	credentialURL, err := a.endpoint("/credential")
	if err != nil {
		return err
	}
	nonceURL, err := a.endpoint("/nonce")
	if err != nil {
		return err
	}
	a.credentialURL = credentialURL.URL()

	signer, cert, caCert, err := newIssuerIdentity(a.now())
	if err != nil {
		return err
	}
	a.caCert = caCert
	attestationRoots, err := certPool(a.cfg.Wallet.ProviderCA)
	if err != nil {
		return err
	}
	// Key attestation is required: attestation is the only proof type.
	proofTypes := map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: haip.RecommendedAttestationProofType()}
	a.issuer, err = issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    a.issuerURL,
		Endpoints: issuer.Endpoints{Credential: credentialURL, Nonce: nonceURL},
		Limits:    issuer.Limits{NonceLifetime: 5 * time.Minute},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			MdocConfigurationID: {
				Format: mdoc.CredentialFormat, DocType: credential.DocType, Scope: MdocScope,
				CryptographicBindingMethodsSupported: []string{"cose_key"},
				ProofTypesSupported:                  proofTypes,
			},
			SDJWTConfigurationID: {
				Format: sdjwtvc.CredentialFormat, VCT: a.vct, Scope: SDJWTScope,
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported:                  proofTypes,
			},
		},
	}, issuer.Dependencies{
		Nonces:              oid4vcgostorage.NewNonceStore(),
		Clock:               issuer.ClockFunc(a.now),
		Random:              rand.Reader,
		AttestationVerifier: issuer.X5CAttestationVerifier{Roots: attestationRoots},
		SDJWTSigner: &issuer.SDJWTSigner{
			Signer: signer, Alg: oid4vci.ES256, IssuerCertificate: cert,
		},
		MdocSigner: &issuer.MdocSigner{
			Signer: signer, Alg: haip.RecommendedCOSEAlgorithm, X5Chain: [][]byte{cert.Raw},
		},
	})
	if err != nil {
		return fmt.Errorf("issuerapp: issuer.New: %w", err)
	}
	a.metadataSigner, a.metadataCert = signer, cert
	return nil
}

// newIssuerIdentity generates this process's demo CA and, under it, the
// document signer key and certificate carried as the SD-JWT's x5c and
// the mdoc's x5chain. A verifier trusts the CA (App.IssuerCACertificate).
// The signer is valid for two years so it outlives any credential the
// one-year validity cap allows.
func newIssuerIdentity(now time.Time) (signer *ecdsa.PrivateKey, signerCert, caCert *x509.Certificate, err error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issuerapp: CA key: %w", err)
	}
	caCert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo CA", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}, nil, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issuerapp: signer key: %w", err)
	}
	signerCert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo document signer", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, caCert, &signer.PublicKey, caKey)
	if err != nil {
		return nil, nil, nil, err
	}
	return signer, signerCert, caCert, nil
}

// certPool parses the PEM certificates in data into a pool.
func certPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("issuerapp: Wallet.ProviderCA holds no PEM certificate")
	}
	return pool, nil
}

// selfIssuerKeys resolves this process's own access-token signing key
// for the resource verifier directly from the key manager, rather than
// fetching this issuer's own /jwks over HTTP.
type selfIssuerKeys struct{ km *ephemeral.KeyManager }

func (s selfIssuerKeys) ResolveIssuerKeys(ctx context.Context, req keys.IssuerKeyRequest) (keys.IssuerKeySet, error) {
	pub, err := s.km.PublicKey(ctx, keys.AccessTokenSigning, req.Algorithm)
	if err != nil {
		return keys.IssuerKeySet{}, err
	}
	return keys.IssuerKeySet{Keys: []keys.IssuerKey{{KeyID: pub.KeyID, Algorithm: req.Algorithm, PublicKey: pub.PublicKey}}}, nil
}

// IssuerCertificate is this process's document signer certificate,
// carried in each credential's x5c / x5chain.
func (a *App) IssuerCertificate() *x509.Certificate { return a.metadataCert }

// IssuerCACertificate is the demo CA that issued IssuerCertificate —
// the trust anchor a verifier configures for this issuer.
func (a *App) IssuerCACertificate() *x509.Certificate { return a.caCert }

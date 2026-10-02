package issuerapp

import (
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
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/server/interactioncookie"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
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

// App is a running passport-vdc issuer.
type App struct {
	cfg              Config
	issuerURL        fapi.URL
	vct              string
	credentialURL    url.URL
	deferredURL      url.URL
	notificationURL  url.URL
	accessTokens     server.AccessTokenIssuer // the Authorization Server's
	preAuthCodes     issuer.PreAuthorizedCodeStore
	tokenLifetime    time.Duration  // the Authorization Server's access token lifetime
	reviews          *reviews       // deferred issuances awaiting a decision
	notifications    *notifications // what the wallets have reported
	now              func() time.Time
	server           *server.Server
	issuer           *issuer.Issuer
	resourceVerifier *fapires.Verifier
	transactions     *transactions
	consent          *interactioncookie.Cookie // the approval step's state, sealed in the browser
	metadataSigner   *ecdsa.PrivateKey
	metadataCert     *x509.Certificate
	providerRoots    *x509.CertPool    // the Wallet Provider CA: Wallet and Key Attestations
	documentSigner   *ecdsa.PrivateKey // signs credentials and the status list
	documentCert     *x509.Certificate
	caCert           *x509.Certificate
	statusList       *statusList
	statusListURI    string
	publisher        *statuslist.Publisher // serves the status list; set by statusPublisher
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
	a.transactions = newTransactions(a.now, cfg.transactionLifetime(), cfg.maxTransactions())
	a.statusListURI = cfg.IssuerURL + StatusListPath
	if a.statusList, err = a.loadStatusList(); err != nil {
		return nil, err
	}
	a.reviews = newReviews(a.now)
	a.preAuthCodes = oid4vcgostorage.NewPreAuthorizedCodeStore()
	a.notifications = &notifications{now: a.now}
	if a.providerRoots, err = certPool(cfg.Wallet.ProviderCA); err != nil {
		return nil, err
	}

	if err := a.buildAuthorizationServer(); err != nil {
		return nil, err
	}
	if err := a.buildIssuer(); err != nil {
		return nil, err
	}
	credentialHandler, err := a.credentialHandler()
	if err != nil {
		return nil, err
	}
	deferredHandler, notificationHandler, err := a.protectedHandlers()
	if err != nil {
		return nil, err
	}
	a.handler = a.routes(credentialHandler, deferredHandler, notificationHandler)
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
	a.accessTokens = accessTokens

	// HAIP's Authorization Server settings, including the issuer_state
	// extension the approval step reads the passport transaction from.
	cfg, err := haip.RecommendedAuthorizationServerConfig()
	if err != nil {
		return fmt.Errorf("issuerapp: %w", err)
	}
	cfg.Issuer = a.issuerURL
	cfg.Endpoints = server.Endpoints{Authorization: authorize, Token: token, PushedAuthorizationRequest: par, JWKS: jwks}
	cfg.Assurance = server.AssuranceDevelopment
	cfg.Limits.MaxClientAttestationLifetime = 24 * time.Hour
	a.tokenLifetime = cfg.Limits.AccessTokenLifetime
	// The approval step's state — the interaction handle and request —
	// travels sealed in the browser's cookie, under a key per process:
	// the server's own interactions don't outlive it either. Instances
	// sharing interactions would share a persistent key.
	consentKey := make([]byte, 32)
	if _, err := rand.Read(consentKey); err != nil {
		return fmt.Errorf("issuerapp: interaction cookie key: %w", err)
	}
	if a.consent, err = interactioncookie.New([][]byte{consentKey}, interactioncookie.Options{}); err != nil {
		return fmt.Errorf("issuerapp: interaction cookie: %w", err)
	}
	// The token endpoint also serves the pre-authorized code grant
	// (handleToken), so its metadata lists it.
	cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrantType}

	deps := server.Dependencies{
		Clients: clients, Transactions: memstore.NewTransactionStore(), Grants: memstore.NewGrantStore(),
		Replay: memstore.NewReplayStore(), ClientKeys: clientKeys, Keys: keyManager, AccessTokens: accessTokens,
		Revocation: memstore.NewRevocationStore(), Clock: server.SystemClock{}, Random: rand.Reader,
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		// Wallet Attestations are trusted by their x5c chain to the
		// Wallet Provider CA (HAIP 1.0 §4.4.1), not by registered keys,
		// from a certificate naming the wallet's registered Wallet
		// Provider — so a CA certifying several providers doesn't let
		// one attest for another's wallets.
		AttesterTrust: server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: a.providerRoots},
			IssuerBinding: server.AttesterIssuerInCertificate,
		},
	}
	if a.server, err = server.New(cfg, deps); err != nil {
		return fmt.Errorf("issuerapp: server.New: %w", err)
	}

	// The Credential Endpoint's access-token verifier, built from the
	// server's own config and stores: its signing keys (read locally,
	// not from this issuer's /jwks), and the revocation store it
	// revokes into, so a token the server revokes stops working there
	// too. Its DPoP proofs must carry a nonce this issuer handed out
	// (RFC 9449 §9), from a nonce store of its own.
	if a.resourceVerifier, err = serverresource.NewVerifier(cfg, deps, serverresource.Options{
		Nonces: memstore.NewNonceStore(), NonceLifetime: 5 * time.Minute,
	}); err != nil {
		return fmt.Errorf("issuerapp: resource verifier: %w", err)
	}
	return nil
}

// registerWallet registers the demo Wallet as a Wallet-Attestation
// client. Its attestations are verified by their x5c chain (see
// AttesterTrust in buildAuthorizationServer), so it registers no keys.
func (a *App) registerWallet() (*memstore.ClientRepository, *ephemeral.ClientKeySource, error) {
	w := a.cfg.Wallet
	redirects := make([]fapi.RegisteredRedirectURI, len(w.RedirectURIs))
	for i, u := range w.RedirectURIs {
		redirects[i] = fapi.RegisteredRedirectURI(u)
	}
	clientCfg := haip.RecommendedWalletClient(fapi.ClientID(w.ClientID), w.ProviderIssuer)
	clientCfg.RedirectURIs, clientCfg.AllowedScopes = redirects, []string{MdocScope, SDJWTScope}
	// The demo's wallets are native apps — the CLI wallet (a loopback
	// redirect), the iOS demo app (a private-use scheme) — and the web
	// wallet (https), which a native registration allows too (RFC 8252).
	clientCfg.ApplicationType = storage.ApplicationTypeNative
	c, err := storage.NewRegisteredClient(clientCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: register wallet: %w", err)
	}
	// No client keys are registered, so nothing is ever fetched.
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: client keys: %w", err)
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
	deferredURL, err := a.endpoint("/deferred_credential")
	if err != nil {
		return err
	}
	notificationURL, err := a.endpoint("/notification")
	if err != nil {
		return err
	}
	a.credentialURL, a.deferredURL, a.notificationURL = credentialURL.URL(), deferredURL.URL(), notificationURL.URL()

	id, err := a.identity()
	if err != nil {
		return err
	}
	a.caCert = id.caCert
	requestKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("issuerapp: request decryption key: %w", err)
	}
	encValues := []oid4vci.JWEEnc{oid4vci.A256GCM, oid4vci.A128GCM}
	// Key attestation is required: attestation is the only proof type.
	proofTypes := map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: haip.RecommendedAttestationProofType()}
	a.issuer, err = issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    a.issuerURL,
		Endpoints: issuer.Endpoints{
			Credential: credentialURL, Nonce: nonceURL, DeferredCredential: deferredURL, Notification: notificationURL,
		},
		Limits: issuer.Limits{
			NonceLifetime:                5 * time.Minute,
			DeferredIssuancePollInterval: deferredPollInterval, DeferredTransactionLifetime: reviewLifetime,
			AccessTokenLifetime: a.tokenLifetime, MaxTxCodeAttempts: maxCodeFailures,
		},
		// HAIP 1.0 §4.4.1: the pre-authorized code grant authenticates
		// the wallet by its Wallet Attestation, as PAR and the
		// authorization code grant do. The Authorization Server checks
		// it, and the DPoP proof, before the issuer redeems the code
		// (handlePreAuthorizedToken).
		PreAuthorizedCodeClientAuthentication: issuer.VerifiedPreAuthorizedCode{},
		// The credentials carry passport data, down to the face image,
		// so they never travel in cleartext beyond TLS — which in a
		// real deployment often ends at a proxy (OID4VCI 1.0 §10).
		// Response encryption requires request encryption too (§8.2),
		// so both are required.
		RequestEncryption: &issuer.RequestEncryptionSupport{
			Keys:               []issuer.RequestDecryptionKey{{KeyID: "passport-vdc-request-1", PrivateKey: requestKey}},
			EncValuesSupported: encValues,
			Required:           true,
		},
		ResponseEncryption: &issuer.ResponseEncryptionSupport{EncValuesSupported: encValues, Required: true},
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
		Nonces:               oid4vcgostorage.NewNonceStore(),
		DeferredTransactions: oid4vcgostorage.NewDeferredTransactionStore(),
		// The pre-authorized code grant (preauth.go): tokens signed with
		// the Authorization Server's keys, for a Wallet Attestation the
		// Authorization Server authenticates.
		PreAuthorizedCodes:  a.preAuthCodes,
		AccessTokens:        accessTokenAdapter{inner: a.accessTokens},
		Notifications:       oid4vcgostorage.NewNotificationStore(),
		NotificationHandler: a.notifications,
		Clock:               issuer.ClockFunc(a.now),
		Random:              rand.Reader,
		AttestationVerifier: issuer.X5CAttestationVerifier{Roots: a.providerRoots},
		SDJWTSigner: &issuer.SDJWTSigner{
			Signer: id.documentSigner, Alg: oid4vci.ES256, IssuerCertificate: id.documentSignerCert,
		},
		MdocSigner: &issuer.MdocSigner{
			Signer: id.documentSigner, Alg: haip.RecommendedCOSEAlgorithm, X5Chain: [][]byte{id.documentSignerCert.Raw},
		},
	})
	if err != nil {
		return fmt.Errorf("issuerapp: issuer.New: %w", err)
	}
	a.metadataSigner, a.metadataCert = id.metadataSigner, id.metadataSignerCert
	a.documentSigner, a.documentCert = id.documentSigner, id.documentSignerCert
	return nil
}

// documentChain is the document signer's certificate chain as signed
// tokens carry it: the signer's certificate, without the CA (the trust
// anchor a verifier already holds).
func (a *App) documentChain() []*x509.Certificate { return []*x509.Certificate{a.documentCert} }

// issuerIdentity is this process's demo CA and the two keys certified
// under it: the document signer (the SD-JWT's x5c, the mdoc's x5chain)
// and a separate key that signs the Credential Issuer Metadata. A
// verifier trusts the CA (App.IssuerCACertificate).
type issuerIdentity struct {
	caCert             *x509.Certificate
	documentSigner     *ecdsa.PrivateKey
	documentSignerCert *x509.Certificate
	metadataSigner     *ecdsa.PrivateKey
	metadataSignerCert *x509.Certificate
}

// newIssuerIdentity generates an issuerIdentity. The certificates are
// valid for two years so they outlive any credential the one-year
// validity cap allows; the CA key is discarded.
func newIssuerIdentity(now time.Time) (issuerIdentity, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuerIdentity{}, fmt.Errorf("issuerapp: CA key: %w", err)
	}
	var id issuerIdentity
	id.caCert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo CA", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}, nil, &caKey.PublicKey, caKey)
	if err != nil {
		return issuerIdentity{}, fmt.Errorf("issuerapp: %w", err)
	}
	if id.documentSigner, id.documentSignerCert, err = issueSigner(now, "passport-vdc demo document signer", id.caCert, caKey); err != nil {
		return issuerIdentity{}, err
	}
	if id.metadataSigner, id.metadataSignerCert, err = issueSigner(now, "passport-vdc demo metadata signer", id.caCert, caKey); err != nil {
		return issuerIdentity{}, err
	}
	return id, nil
}

// issueSigner generates a signing key and its certificate under ca.
func issueSigner(now time.Time, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: %s key: %w", name, err)
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: %w", err)
	}
	return key, cert, nil
}

// certPool parses the PEM certificates in data into a pool.
func certPool(data []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("issuerapp: Wallet.ProviderCA holds no PEM certificate")
	}
	return pool, nil
}

// IssuerCertificate is this process's document signer certificate,
// carried in each credential's x5c / x5chain.
func (a *App) IssuerCertificate() *x509.Certificate { return a.documentCert }

// IssuerCACertificate is the demo CA that issued IssuerCertificate —
// the trust anchor a verifier configures for this issuer.
func (a *App) IssuerCACertificate() *x509.Certificate { return a.caCert }

// identity is this issuer's CA and signers: kept in Config.StateDir
// when set, so credentials it issued still verify after a restart, and
// generated afresh otherwise.
func (a *App) identity() (issuerIdentity, error) {
	if a.cfg.StateDir == "" {
		return newIssuerIdentity(a.now())
	}
	return loadOrCreateIdentity(a.cfg.StateDir, a.now())
}

// loadStatusList is this issuer's status list: kept in Config.StateDir
// when set, so revocations and allocated indices survive a restart.
func (a *App) loadStatusList() (*statusList, error) {
	if a.cfg.StateDir == "" {
		return newStatusList(), nil
	}
	return loadStatusList(a.cfg.StateDir)
}

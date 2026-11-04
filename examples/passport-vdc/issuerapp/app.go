package issuerapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/statuslist"
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
	cfg               Config
	issuerURL         fapi.URL
	vct               string
	credentialURL     url.URL
	deferredURL       url.URL
	notificationURL   url.URL
	stores            stores
	tokenLifetime     time.Duration  // the Authorization Server's access token lifetime
	reviews           *reviews       // deferred issuances awaiting a decision
	progress          *progressBoard // each offer's progress, for its page
	notifications     *notifications // what the wallets have reported
	now               func() time.Time
	server            *server.Server
	resourceVerifier  *fapires.Verifier
	transactions      *transactions
	consent           *interactioncookie.Cookie    // the approval step's state, sealed in the browser
	providerAnchors   server.StaticAttesterAnchors // the Wallet Provider CA, bound to Wallet.ProviderIssuer
	endpoints         issuer.Endpoints
	requestKey        *ecdsa.PrivateKey // decrypts Credential Requests, whichever signer signs
	caCert            *x509.Certificate
	crlURL            string      // where the CA serves its CRL: IssuerURL + CRLPath
	crl               *democrl.CA // the CA's revocation list
	statusList        *statusList
	statusListURI     string
	mdocStatusListURI string
	handler           http.Handler

	// signerMu serializes document signer rotations, which replace id
	// and signing (RevokeDocumentSigner).
	signerMu sync.Mutex
	id       issuerIdentity
	// signing is the current document signer and what signs with it.
	signing atomic.Pointer[signing]
}

// signing is the document signer and everything built on it: the
// Issuer, signing credentials, the endpoints it serves, and the status
// list publishers, signing the Status List Tokens. Revoking the signer
// replaces it whole (RevokeDocumentSigner).
type signing struct {
	issuer *issuer.Issuer
	key    *ecdsa.PrivateKey // signs credentials and the status list
	cert   *x509.Certificate
	// credential, deferred, notification and metadata serve the
	// Credential, Deferred Credential and Notification Endpoints, and
	// the Credential Issuer Metadata (signed by the metadata signer).
	credential, deferred, notification, metadata http.Handler
	// jwtList and cwtList serve the status list (statusPublishers).
	jwtList, cwtList *statuslist.Publisher
}

// current is the signing in use now.
func (a *App) current() *signing { return a.signing.Load() }

// iss is the Issuer in use now.
func (a *App) iss() *issuer.Issuer { return a.current().issuer }

// New wires an App from cfg. Without Config.StateDir its CA and signing
// keys are generated per process — restarting the issuer invalidates
// every credential it issued, which is fine for a demo.
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
	a.transactions = newTransactions(a.now, cfg.transactionLifetime(), KeepForRefresh, cfg.maxTransactions())
	a.statusListURI = cfg.IssuerURL + StatusListPath
	a.mdocStatusListURI = cfg.IssuerURL + MdocStatusListPath
	if a.statusList, err = a.loadStatusList(); err != nil {
		return nil, err
	}
	a.reviews = newReviews(a.now)
	a.progress = newProgressBoard()
	a.stores = memoryStores()
	if cfg.Database != nil {
		if a.stores, err = databaseStores(context.Background(), cfg.Database, cfg.DatabaseSealer); err != nil {
			return nil, err
		}
	}
	a.notifications = &notifications{now: a.now}
	if a.providerAnchors, err = attesterAnchors(cfg.Wallet.ProviderCA, cfg.Wallet.ProviderIssuer); err != nil {
		return nil, err
	}

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
	var par, authorize, token, jwks, revoke fapi.URL
	for path, dst := range map[string]*fapi.URL{"/par": &par, "/authorize": &authorize, "/token": &token, "/jwks": &jwks, "/revoke": &revoke} {
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

	// HAIP's Authorization Server settings, including the issuer_state
	// extension the approval step reads the passport transaction from.
	cfg, err := haip.RecommendedAuthorizationServerConfig()
	if err != nil {
		return fmt.Errorf("issuerapp: %w", err)
	}
	cfg.Issuer = a.issuerURL
	cfg.Endpoints = server.Endpoints{Authorization: authorize, Token: token, PushedAuthorizationRequest: par, JWKS: jwks, Revocation: revoke}
	cfg.Assurance = server.AssuranceDevelopment
	cfg.Limits.MaxClientAttestationLifetime = 24 * time.Hour
	// A passport kept for refresh gives the wallet a refresh token
	// lasting as long as the passport is kept (OfferOptions.KeepForRefresh).
	cfg.Limits.RefreshTokenLifetime = KeepForRefresh
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
	// (handleToken), so its metadata lists it, with the
	// authorization_details its tokens may carry.
	cfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrantType}
	if cfg.RAR, err = credentialAuthorizationDetails(); err != nil {
		return fmt.Errorf("issuerapp: authorization details: %w", err)
	}

	deps := server.Dependencies{
		Clients: clients, Transactions: a.stores.transactions, Grants: a.stores.grants,
		Replay: a.stores.replay, ClientKeys: clientKeys, Keys: keyManager, AccessTokens: accessTokens,
		Revocation: a.stores.revocation, Clock: server.SystemClock{}, Random: rand.Reader,
		ClientCertificateTrust: server.NoPKIClientAuthentication{},
		// Wallet Attestations are trusted by their x5c chain to the
		// Wallet Provider CA (HAIP 1.0 §4.4.1), not by registered keys,
		// from a certificate naming the wallet's registered Wallet
		// Provider. Each anchor is bound to the providers it may vouch
		// for, so a CA on a shared trust list can't attest for another
		// provider's wallets. The demo's Wallet Provider publishes no
		// CRL, so its certificates' revocation isn't checked.
		AttesterTrust: server.X5CAttesterChain{
			Anchors:       a.providerAnchors,
			IssuerBinding: server.AttesterIssuerBoundToAnchor,
			Revocation:    server.NoClientCertificateRevocationCheck{},
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
		// The Credential Endpoint and the rest are under the issuer.
		ResourceURLs: []fapi.URL{cfg.Issuer},
		Nonces:       a.stores.dpopNonces, NonceLifetime: 5 * time.Minute,
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
	// offline_access asks for a refresh token, granted only for a
	// passport kept for refresh (handleDecision).
	clientCfg.RedirectURIs, clientCfg.AllowedScopes = redirects, []string{MdocScope, SDJWTScope, offlineAccessScope}
	// The demo's wallets are native apps — the CLI wallet (a loopback
	// redirect), the iOS demo app (a private-use scheme) — and the web
	// wallet (https), which a native registration allows too (RFC 8252).
	clientCfg.ApplicationType = storage.ApplicationTypeNative
	// A pre-authorized code's token carries openid_credential
	// authorization_details when the wallet asked for them
	// (credentialAuthorizationDetails).
	clientCfg.AuthorizationDetailsTypes = []string{oid4vci.AuthorizationDetailsTypeOpenIDCredential}
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
	a.endpoints = issuer.Endpoints{
		Credential: credentialURL, Nonce: nonceURL, DeferredCredential: deferredURL, Notification: notificationURL,
	}

	a.crlURL = a.cfg.IssuerURL + CRLPath
	if a.id, err = a.identity(); err != nil {
		return err
	}
	a.caCert = a.id.caCert
	crlState := ""
	if a.cfg.StateDir != "" {
		crlState = filepath.Join(a.cfg.StateDir, crlFile)
	}
	if a.crl, err = democrl.Open(crlState, a.id.caCert, a.id.caKey, a.now); err != nil {
		return fmt.Errorf("issuerapp: %w", err)
	}
	// Request encryption's key, kept across signer rotations: a wallet
	// may have read it from the metadata before one.
	if a.requestKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return fmt.Errorf("issuerapp: request decryption key: %w", err)
	}
	s, err := a.newSigning(a.id.documentSigner, a.id.documentSignerCert)
	if err != nil {
		return err
	}
	a.signing.Store(s)
	a.statusList.attribute(signerID(s.cert))
	return nil
}

// newSigning builds the Issuer and its endpoints and status list
// publishers on the document signer key, certified by cert.
func (a *App) newSigning(key *ecdsa.PrivateKey, cert *x509.Certificate) (*signing, error) {
	s := &signing{key: key, cert: cert}
	var err error
	encValues := []oid4vci.JWEEnc{oid4vci.A256GCM, oid4vci.A128GCM}
	// Key attestation is required, in jwt proofs' key_attestation
	// header (HAIP 1.0 §4.5.1), whose aud binds each proof to this
	// issuer. Not the attestation proof type, which names no audience:
	// another issuer could hand a wallet a c_nonce from this one and
	// redeem here the key attestation the wallet returns.
	proofTypes := map[string]oid4vci.ProofTypeConfiguration{
		oid4vci.ProofTypeJWT: haip.RecommendedJWTKeyAttestationProofType(),
	}
	s.issuer, err = issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		// HAIP 1.0: issuer.New refuses what HAIP doesn't allow (a
		// configuration without a scope, key binding without the Nonce
		// Endpoint, proofs without ES256, pre-authorized codes redeemed
		// without client authentication).
		Profile:   haip.IssuerProfile{},
		Issuer:    a.issuerURL,
		Endpoints: a.endpoints,
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
			Keys:               []issuer.RequestDecryptionKey{{KeyID: "passport-vdc-request-1", PrivateKey: a.requestKey}},
			EncValuesSupported: encValues,
			Required:           true,
		},
		ResponseEncryption: &issuer.ResponseEncryptionSupport{EncValuesSupported: encValues, Required: true},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			MdocConfigurationID: {
				Format: mdoc.CredentialFormat, DocType: credential.DocType, Scope: MdocScope,
				CryptographicBindingMethodsSupported: []string{"cose_key"},
				ProofTypesSupported:                  proofTypes,
				CredentialMetadata:                   credentialDisplay("Passport (mdoc)"),
			},
			SDJWTConfigurationID: {
				Format: sdjwtvc.CredentialFormat, VCT: a.vct, Scope: SDJWTScope,
				CryptographicBindingMethodsSupported: []string{"jwk"},
				ProofTypesSupported:                  proofTypes,
				CredentialMetadata:                   credentialDisplay("Passport (SD-JWT)"),
			},
		},
		// Display metadata (OID4VCI 1.0 §12.2.4), which wallets show.
		Display: []oid4vci.Display{{Name: "IDFoundry passport demo", Locale: "en"}},
		// Batches of copies, each bound to its own key, so a wallet can
		// present a fresh one each time (HAIP 1.0's unlinkability).
		BatchCredentialIssuance: &oid4vci.BatchCredentialIssuance{BatchSize: 3},
	}, issuer.Dependencies{
		Nonces:               a.stores.nonces,
		DeferredTransactions: a.stores.deferred,
		// The Nonce Response carries a DPoP nonce for the Credential
		// Endpoint (OpenID4VCI §7.2), from the verifier that checks it, so
		// the wallet's first Credential Request isn't challenged.
		CredentialDPoPNonces: a.resourceVerifier,
		// The pre-authorized code grant (preauth.go): tokens signed with
		// the Authorization Server's keys, for a Wallet Attestation the
		// Authorization Server authenticates.
		PreAuthorizedCodes:  a.stores.preAuthCodes,
		Notifications:       a.stores.notifications,
		NotificationHandler: a.notifications,
		Clock:               issuer.ClockFunc(a.now),
		Random:              rand.Reader,
		// Key Attestations are bound to the provider CA as Wallet
		// Attestations are: their iss must be Wallet.ProviderIssuer,
		// named by the signing certificate.
		AttestationVerifier: issuer.X5CAttestationVerifier{
			IssuerBinding: issuer.AttestationIssuerBoundToAnchor, Anchors: keyAttestationAnchors(a.providerAnchors),
		},
		SDJWTSigner: &issuer.SDJWTSigner{
			Signer: key, Alg: oid4vci.ES256, IssuerCertificate: cert,
		},
		MdocSigner: &issuer.MdocSigner{
			Signer: key, Alg: haip.RecommendedCOSEAlgorithm, X5Chain: [][]byte{cert.Raw},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("issuerapp: issuer.New: %w", err)
	}
	if s.metadata, err = issuer.NewMetadataHandler(s.issuer, &issuer.MetadataSigner{
		Signer: a.id.metadataSigner, Alg: oid4vci.ES256, Certificate: a.id.metadataSignerCert,
	}); err != nil {
		return nil, fmt.Errorf("issuerapp: %w", err)
	}
	if s.credential, err = a.credentialHandler(s.issuer, signerID(cert)); err != nil {
		return nil, err
	}
	if s.deferred, s.notification, err = a.protectedHandlers(s.issuer); err != nil {
		return nil, err
	}
	s.jwtList, s.cwtList = a.statusPublishers(key, cert)
	return s, nil
}

// documentChain is a document signer's certificate chain as signed
// tokens carry it: the signer's certificate, without the CA (the trust
// anchor a verifier already holds).
func documentChain(cert *x509.Certificate) []*x509.Certificate { return []*x509.Certificate{cert} }

// issuerIdentity is this process's demo CA and the two keys certified
// under it: the document signer (the SD-JWT's x5c, the mdoc's x5chain)
// and a separate key that signs the Credential Issuer Metadata. A
// verifier trusts the CA (App.IssuerCACertificate).
type issuerIdentity struct {
	caCert *x509.Certificate
	// caKey signs the CA's CRL, and the document signer that replaces a
	// revoked one (RevokeDocumentSigner).
	caKey              *ecdsa.PrivateKey
	documentSigner     *ecdsa.PrivateKey
	documentSignerCert *x509.Certificate
	metadataSigner     *ecdsa.PrivateKey
	metadataSignerCert *x509.Certificate
}

// Names of the demo issuer's certificates.
const (
	caName             = "passport-vdc demo CA"
	documentSignerName = "passport-vdc demo document signer"
	metadataSignerName = "passport-vdc demo metadata signer"
)

// newIssuerIdentity generates an issuerIdentity. The certificates are
// valid for two years so they outlive any credential the one-year
// validity cap allows. Each names crlURL as its CRL distribution
// point, where the CA, which keeps its key, serves its CRL (ISO/IEC
// 18013-5 Annex B.1 has an IACA's certificates, and its document
// signers', name one).
//
// They're valid from certificateBackdate before now: an mdoc's MSO is
// signed at the start of its issuance's UTC day (credential.ValidFrom),
// and ISO/IEC 18013-5 §9.3.1 has that signed time fall within the
// document signer certificate's validity. The CA's starts as early, so
// the signer's doesn't start before its issuer's.
func newIssuerIdentity(now time.Time, crlURL string) (issuerIdentity, error) {
	return newIssuerIdentityWithSignerEKUs(now, crlURL, mdoc.MDLDocumentSignerEKU)
}

// newIssuerIdentityWithSignerEKUs is newIssuerIdentity, its document
// signer's extended key usages dsEKUs.
func newIssuerIdentityWithSignerEKUs(now time.Time, crlURL string, dsEKUs ...asn1.ObjectIdentifier) (issuerIdentity, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuerIdentity{}, fmt.Errorf("issuerapp: CA key: %w", err)
	}
	id := issuerIdentity{caKey: caKey}
	id.caCert, err = democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: caName, Organization: []string{"IDFoundry demo"}, Country: []string{demoCountry}},
		NotBefore: now.Add(-certificateBackdate), NotAfter: now.AddDate(5, 0, 0),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		CRLDistributionPoints: []string{crlURL},
	}, nil, &caKey.PublicKey, caKey)
	if err != nil {
		return issuerIdentity{}, fmt.Errorf("issuerapp: %w", err)
	}
	if id.documentSigner, id.documentSignerCert, err = issueSigner(now, documentSignerName, id.caCert, caKey, crlURL, "", dsEKUs...); err != nil {
		return issuerIdentity{}, err
	}
	if id.metadataSigner, id.metadataSignerCert, err = issueSigner(now, metadataSignerName, id.caCert, caKey, crlURL, ""); err != nil {
		return issuerIdentity{}, err
	}
	return id, nil
}

// certificateBackdate is how far before its creation an issuerIdentity
// is valid from: the whole UTC day an MSO's signed time is rounded down
// across (see newIssuerIdentity), and an hour for clock skew.
const certificateBackdate = 25 * time.Hour

// demoCountry is the demo CA's and signers' countryName: ISO/IEC
// 18013-5 Annex B makes it mandatory, and verifiers check that a
// document signer's matches its CA's. ZZ is an ISO 3166 user-assigned
// code: the demo issues for no real country.
const demoCountry = "ZZ"

// issueSigner generates a signing key and its certificate under ca,
// naming crlURL, the CA's CRL, as its distribution point, with the
// extended key usages ekus, if any: the document signer's is ISO/IEC
// 18013-5's mDL document signer's (Annex B.1.4), which verifiers
// require of the certificate signing an mdoc. It's valid for two years,
// or until the CA expires if that's sooner. A non-empty issuerURI is
// named as a uniformResourceIdentifier subject alternative name (see
// RevokeDocumentSigner).
func issueSigner(now time.Time, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, crlURL, issuerURI string, ekus ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: %s key: %w", name, err)
	}
	notAfter := now.AddDate(2, 0, 0)
	if notAfter.After(ca.NotAfter) {
		notAfter = ca.NotAfter
	}
	var uris []*url.URL
	if issuerURI != "" {
		u, err := url.Parse(issuerURI)
		if err != nil {
			return nil, nil, fmt.Errorf("issuerapp: %s URI: %w", name, err)
		}
		uris = []*url.URL{u}
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: name, Organization: []string{"IDFoundry demo"}, Country: []string{demoCountry}},
		NotBefore: now.Add(-certificateBackdate), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: ekus,
		CRLDistributionPoints: []string{crlURL}, URIs: uris,
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: %w", err)
	}
	return key, cert, nil
}

// attesterAnchors is each certificate in the PEM data, bound to vouch
// for the Wallet Provider providerIssuer alone.
func attesterAnchors(data []byte, providerIssuer string) (server.StaticAttesterAnchors, error) {
	var anchors server.StaticAttesterAnchors
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("issuerapp: Wallet.ProviderCA: %w", err)
		}
		anchors = append(anchors, server.AttesterAnchor{Certificate: cert, Issuers: []string{providerIssuer}})
	}
	if len(anchors) == 0 {
		return nil, fmt.Errorf("issuerapp: Wallet.ProviderCA holds no PEM certificate")
	}
	return anchors, nil
}

// keyAttestationAnchors is anchors, the Wallet Attestations' bound
// anchors, for the issuer's Key Attestations.
func keyAttestationAnchors(anchors server.StaticAttesterAnchors) []issuer.AttestationAnchor {
	out := make([]issuer.AttestationAnchor, len(anchors))
	for i, a := range anchors {
		out[i] = issuer.AttestationAnchor{Certificate: a.Certificate, Issuers: a.Issuers}
	}
	return out
}

// IssuerCertificate is the current document signer certificate,
// carried in each credential's x5c / x5chain: another after
// RevokeDocumentSigner.
func (a *App) IssuerCertificate() *x509.Certificate { return a.current().cert }

// IssuerCACertificate is the demo CA that issued IssuerCertificate —
// the trust anchor a verifier configures for this issuer.
func (a *App) IssuerCACertificate() *x509.Certificate { return a.caCert }

// identity is this issuer's CA and signers: kept in Config.StateDir
// when set, so credentials it issued still verify after a restart, and
// generated afresh otherwise.
func (a *App) identity() (issuerIdentity, error) {
	if a.cfg.StateDir == "" {
		return newIssuerIdentity(a.now(), a.crlURL)
	}
	return loadOrCreateIdentity(a.cfg.StateDir, a.now(), a.crlURL)
}

// loadStatusList is this issuer's status list: kept in Config.StateDir
// when set, so revocations and allocated indices survive a restart.
func (a *App) loadStatusList() (*statusList, error) {
	if a.cfg.StateDir == "" {
		return newStatusList(), nil
	}
	return loadStatusList(a.cfg.StateDir)
}

// credentialDisplay is a passport credential's display metadata: its
// name, with the demo's description and colours.
func credentialDisplay(name string) *oid4vci.CredentialMetadata {
	return &oid4vci.CredentialMetadata{Display: []oid4vci.CredentialDisplay{{
		Name: name, Locale: "en", Description: "Identity from a verified ePassport. Demo only.",
		BackgroundColor: "#0b3d2e", TextColor: "#ffffff",
	}}}
}

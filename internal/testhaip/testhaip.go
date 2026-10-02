// Package testhaip runs a complete HAIP 1.0 Credential Issuer in
// process, for tests that drive a wallet end to end: a fapigo/server
// Authorization Server authenticating wallets by Wallet Attestation, an
// issuer.Issuer taking Key Attestations (the attestation proof type),
// with the authorization code grant (consent approved automatically),
// the pre-authorized code grant with a PIN, deferred issuance and
// notifications, plus the Wallet Provider that attests the wallet and
// its keys. Each Env serves over TLS on a loopback address.
package testhaip

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/keys/ephemeral"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/serverresource"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/fapiresource"
	oid4vcgostorage "github.com/idfoundry/oid4vcgo/storage"
)

// The credential configurations the issuer offers.
const (
	SDJWTConfigurationID = "test_sdjwt"
	MdocConfigurationID  = "test_mdoc"
	DocType              = "org.example.test.1"
	NameSpace            = "org.example.test.1"
)

// The wallet's registration with the Authorization Server.
const (
	ClientID       = "https://wallet.example/client"
	RedirectURI    = "https://wallet.example/callback"
	ProviderIssuer = "https://wallet-provider.example"
)

// The credentials' claims: family_name and given_name, selectively
// disclosable in the SD-JWT VC, and elements of NameSpace in the mdoc.
const (
	FamilyName = "Doe"
	GivenName  = "Jane"
)

const preAuthorizedCodeGrantType = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// Options configures an Env.
type Options struct {
	// Defer has the Credential Endpoint defer every credential: the
	// wallet polls until Env.Decide approves or denies them.
	Defer bool
}

// Env is a running issuer and Wallet Provider.
type Env struct {
	// IssuerURL is the Credential Issuer and Authorization Server.
	IssuerURL string
	// HTTP trusts the issuer's TLS certificate.
	HTTP *http.Client
	// IssuerRoots is the trust anchor of the credentials' signer.
	IssuerRoots *x509.CertPool
	// Provider attests the wallet and its keys.
	Provider *Provider

	iss          *issuer.Issuer
	srv          *server.Server
	accessTokens server.AccessTokenIssuer
	preAuthCodes issuer.PreAuthorizedCodeStore
	vct          string

	mu            sync.Mutex
	decision      *bool
	notifications []oid4vci.NotificationEvent
}

// New starts an Env, stopped when t ends.
func New(t testing.TB, opts Options) *Env {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	e := &Env{IssuerURL: "https://" + ts.Listener.Addr().String(), preAuthCodes: oid4vcgostorage.NewPreAuthorizedCodeStore()}
	e.vct = e.IssuerURL + "/vct/test"
	e.Provider = newProvider(t)

	tokenEndpoint := e.endpoint(t, "/token")
	accessKeys, err := ephemeral.NewKeyManager(map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.AccessTokenSigning: fapi.ES256})
	must(t, err)
	if e.accessTokens, err = server.NewJWTAccessTokens(accessKeys, fapi.ES256); err != nil {
		t.Fatal(err)
	}
	asCfg, err := haip.RecommendedAuthorizationServerConfig()
	must(t, err)
	asCfg.Issuer = e.issuerURL(t)
	asCfg.Endpoints = server.Endpoints{
		Authorization: e.endpoint(t, "/authorize"), Token: tokenEndpoint,
		PushedAuthorizationRequest: e.endpoint(t, "/par"), JWKS: e.endpoint(t, "/jwks"),
	}
	asCfg.Assurance = server.AssuranceDevelopment
	asCfg.Limits.MaxClientAttestationLifetime = time.Hour
	asCfg.AdditionalGrantTypes = []string{preAuthorizedCodeGrantType}
	clientCfg := haip.RecommendedWalletClient(fapi.ClientID(ClientID), ProviderIssuer)
	clientCfg.RedirectURIs = []fapi.RegisteredRedirectURI{RedirectURI}
	clientCfg.AllowedScopes = []string{SDJWTConfigurationID, MdocConfigurationID}
	client, err := storage.NewRegisteredClient(clientCfg)
	must(t, err)
	clientKeys, err := ephemeral.NewClientKeySource(nil, nil)
	must(t, err)
	deps := server.Dependencies{
		Clients: memstore.NewClientRepository([]storage.RegisteredClient{client}), Transactions: memstore.NewTransactionStore(),
		Grants: memstore.NewGrantStore(), Replay: memstore.NewReplayStore(), ClientKeys: clientKeys, Keys: accessKeys,
		AccessTokens: e.accessTokens, Revocation: memstore.NewRevocationStore(), Clock: server.SystemClock{}, Random: rand.Reader,
		ClientCertificateTrust: server.NoClientCertificateChainTrust{},
		AttesterTrust: server.X5CAttesterChain{
			TrustAnchors:  server.StaticAttesterTrustAnchors{Roots: e.Provider.Roots},
			IssuerBinding: server.AttesterIssuerInCertificate,
		},
	}
	if e.srv, err = server.New(asCfg, deps); err != nil {
		t.Fatal(err)
	}
	resourceVerifier, err := serverresource.NewVerifier(asCfg, deps, serverresource.Options{
		Nonces: memstore.NewNonceStore(), NonceLifetime: 5 * time.Minute,
	})
	must(t, err)
	tokens, err := fapiresource.New(resourceVerifier)
	must(t, err)

	caCert, caKey := testcert.CA(t, "testhaip issuer CA")
	signerCert, signerKey := testcert.Leaf(t, "testhaip document signer", caCert, caKey)
	e.IssuerRoots = x509.NewCertPool()
	e.IssuerRoots.AddCert(caCert)
	proofTypes := map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeAttestation: haip.RecommendedAttestationProofType()}
	e.iss, err = issuer.New(issuer.Config{
		Assurance: issuer.AssuranceDevelopment,
		Issuer:    e.issuerURL(t),
		Endpoints: issuer.Endpoints{
			Credential: e.endpoint(t, "/credential"), Nonce: e.endpoint(t, "/nonce"),
			DeferredCredential: e.endpoint(t, "/deferred_credential"), Notification: e.endpoint(t, "/notification"),
		},
		Limits: issuer.Limits{
			NonceLifetime: 5 * time.Minute, DeferredIssuancePollInterval: time.Second, DeferredTransactionLifetime: time.Hour,
			AccessTokenLifetime: asCfg.Limits.AccessTokenLifetime, MaxTxCodeAttempts: 3,
		},
		PreAuthorizedCodeClientAuthentication: issuer.VerifiedPreAuthorizedCode{},
		CredentialConfigurationsSupported: map[string]issuer.CredentialConfiguration{
			SDJWTConfigurationID: {
				Format: sdjwtvc.CredentialFormat, VCT: e.vct, Scope: SDJWTConfigurationID,
				CryptographicBindingMethodsSupported: []string{"jwk"}, ProofTypesSupported: proofTypes,
			},
			MdocConfigurationID: {
				Format: mdoc.CredentialFormat, DocType: DocType, Scope: MdocConfigurationID,
				CryptographicBindingMethodsSupported: []string{"cose_key"}, ProofTypesSupported: proofTypes,
			},
		},
	}, issuer.Dependencies{
		Nonces: oid4vcgostorage.NewNonceStore(), DeferredTransactions: oid4vcgostorage.NewDeferredTransactionStore(),
		PreAuthorizedCodes: e.preAuthCodes, AccessTokens: accessTokenAdapter{inner: e.accessTokens},
		Notifications: oid4vcgostorage.NewNotificationStore(), NotificationHandler: notificationRecorder{e},
		Clock: issuer.ClockFunc(time.Now), Random: rand.Reader,
		AttestationVerifier: issuer.X5CAttestationVerifier{Roots: e.Provider.Roots},
		SDJWTSigner:         &issuer.SDJWTSigner{Signer: signerKey, Alg: oid4vci.ES256, IssuerCertificate: signerCert},
		MdocSigner:          &issuer.MdocSigner{Signer: signerKey, Alg: haip.RecommendedCOSEAlgorithm, X5Chain: [][]byte{signerCert.Raw}},
	})
	must(t, err)

	credentialURL, deferredURL, notificationURL := e.endpoint(t, "/credential").URL(), e.endpoint(t, "/deferred_credential").URL(), e.endpoint(t, "/notification").URL()
	credentialHandler, err := e.iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: &credentialURL, Tokens: tokens,
		Prepare: func(_ context.Context, _ issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			if opts.Defer {
				req.Defer = &issuer.Deferral{}
				return nil, nil
			}
			req.SDJWTClaims, req.MdocClaims = e.claims()
			return nil, nil
		},
	})
	must(t, err)
	deferredHandler, err := e.iss.DeferredCredentialHandler(issuer.DeferredCredentialHandlerConfig{
		ProtectedEndpointConfig: issuer.ProtectedEndpointConfig{URL: &deferredURL, Tokens: tokens},
		Resolve:                 e.resolveDeferred,
	})
	must(t, err)
	notificationHandler, err := e.iss.NotificationEndpointHandler(issuer.ProtectedEndpointConfig{URL: &notificationURL, Tokens: tokens})
	must(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(e.srv.Metadata(r.Context()))
	})
	mux.HandleFunc("GET /.well-known/openid-credential-issuer", issuer.MetadataHandler(e.iss, nil, "", nil))
	mux.HandleFunc("POST /par", e.handlePAR)
	mux.HandleFunc("GET /authorize", e.handleAuthorize)
	mux.HandleFunc("POST /token", e.handleToken)
	mux.HandleFunc("POST /nonce", func(w http.ResponseWriter, r *http.Request) {
		result, err := e.iss.RequestNonce(r.Context())
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		result.WriteJSON(w)
	})
	mux.Handle("POST /credential", credentialHandler)
	mux.Handle("POST /deferred_credential", deferredHandler)
	mux.Handle("POST /notification", notificationHandler)
	ts.Config.Handler = mux
	ts.StartTLS()
	t.Cleanup(ts.Close)
	e.HTTP = ts.Client()
	return e
}

// AuthorizationCodeOffer returns a Credential Offer URI for configIDs
// redeemed with the authorization code grant.
func (e *Env) AuthorizationCodeOffer(t testing.TB, configIDs ...string) string {
	t.Helper()
	return e.offer(t, configIDs, &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{}})
}

// PreAuthorizedOffer returns a Credential Offer URI for configIDs
// redeemed with the pre-authorized code grant and pin.
func (e *Env) PreAuthorizedOffer(t testing.TB, pin string, configIDs ...string) string {
	t.Helper()
	var b [32]byte
	_, _ = rand.Read(b[:])
	code := base64.RawURLEncoding.EncodeToString(b[:])
	must(t, e.preAuthCodes.Issue(context.Background(), code, issuer.PreAuthorizedCodeRecord{
		TxCode: pin, Scopes: configIDs, ExpiresAt: time.Now().Add(time.Hour), Subject: "holder",
	}))
	return e.offer(t, configIDs, &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{
		PreAuthorizedCode: code, TxCode: &oid4vci.TxCode{InputMode: "numeric", Length: len(pin)},
	}})
}

func (e *Env) offer(t testing.TB, configIDs []string, grants *oid4vci.Grants) string {
	t.Helper()
	result, err := e.iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: configIDs, Grants: grants,
	})
	must(t, err)
	return result.URI
}

// Approve opens authorizationURL as the holder's browser would; the
// issuer approves at once, and Approve returns the redirect back to
// RedirectURI.
func (e *Env) Approve(ctx context.Context, authorizationURL string) (string, error) {
	hc := *e.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizationURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc, err := resp.Location()
	if err != nil {
		return "", errors.New("testhaip: the authorization endpoint didn't redirect")
	}
	return loc.String(), nil
}

// Decide approves or denies every deferred credential, issued or refused
// on the wallet's next poll.
func (e *Env) Decide(approve bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.decision = &approve
}

// Notifications returns the events wallets have reported, in order.
func (e *Env) Notifications() []oid4vci.NotificationEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]oid4vci.NotificationEvent(nil), e.notifications...)
}

func (e *Env) claims() (*sdjwtvc.Claims, *mdoc.Claims) {
	exp := sdjwtvc.RoundedExp(time.Now(), 24*time.Hour)
	sdjwtClaims := &sdjwtvc.Claims{VCT: e.vct, Exp: &exp, Additional: map[string]any{
		"family_name": sdjwtvc.SD(FamilyName), "given_name": sdjwtvc.SD(GivenName),
	}}
	// Within the document signer certificate's validity (testcert.Leaf:
	// an hour back, a day ahead).
	signed := time.Now().UTC().Truncate(time.Second)
	mdocClaims := &mdoc.Claims{
		DocType: DocType, Signed: signed, ValidFrom: signed, ValidUntil: signed.Add(12 * time.Hour),
		NameSpaces: map[string]map[string]any{NameSpace: {"family_name": FamilyName, "given_name": GivenName}},
	}
	return sdjwtClaims, mdocClaims
}

func (e *Env) resolveDeferred(ctx context.Context, _ issuer.Grant, transactionID string, _ issuer.DeferredTransactionRecord) error {
	e.mu.Lock()
	decision := e.decision
	e.mu.Unlock()
	switch {
	case decision == nil:
		return nil
	case !*decision:
		return e.iss.DenyDeferredCredential(ctx, transactionID)
	}
	sdjwtClaims, mdocClaims := e.claims()
	return e.iss.IssueDeferredCredential(ctx, transactionID, issuer.DeferredIssuance{SDJWTClaims: sdjwtClaims, MdocClaims: mdocClaims})
}

type notificationRecorder struct{ e *Env }

func (n notificationRecorder) HandleNotification(_ context.Context, _ string, event oid4vci.NotificationEvent, _ string) error {
	n.e.mu.Lock()
	defer n.e.mu.Unlock()
	n.e.notifications = append(n.e.notifications, event)
	return nil
}

func (e *Env) handlePAR(w http.ResponseWriter, r *http.Request) {
	req, err := server.PushAuthorizationRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	result, err := e.srv.PushAuthorizationRequest(r.Context(), req)
	if err != nil {
		server.WriteError(w, err)
		return
	}
	result.WriteJSON(w)
}

// handleAuthorize approves every request at once, for subject "holder".
func (e *Env) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	req, err := server.BeginAuthorizationRequestFromHTTP(r)
	if err != nil {
		http.Error(w, "malformed authorization request", http.StatusBadRequest)
		return
	}
	action, err := e.srv.BeginAuthorization(r.Context(), req)
	if err != nil {
		http.Error(w, "failed to begin authorization", http.StatusInternalServerError)
		return
	}
	interaction, ok := action.(server.InteractionRequired)
	if !ok {
		http.Error(w, "unexpected authorization action", http.StatusBadRequest)
		return
	}
	subjectID, err := server.NewSubjectID("holder")
	if err != nil {
		http.Error(w, "invalid subject", http.StatusInternalServerError)
		return
	}
	subject, err := server.NewAuthenticatedSubject(subjectID)
	if err != nil {
		http.Error(w, "invalid subject", http.StatusInternalServerError)
		return
	}
	authCtx, err := server.NewAuthenticationContext(time.Now(), "urn:example:testhaip", nil)
	if err != nil {
		http.Error(w, "invalid authentication context", http.StatusInternalServerError)
		return
	}
	done, err := e.srv.CompleteAuthorization(r.Context(), server.CompleteAuthorizationRequest{
		Handle: interaction.Handle,
		Result: server.Authorize(subject, authCtx, server.GrantedAuthorization{Scope: interaction.Interaction.Scope}),
	})
	if err != nil {
		http.Error(w, "failed to complete authorization", http.StatusInternalServerError)
		return
	}
	redirect, ok := done.(server.AuthorizationRedirect)
	if !ok {
		http.Error(w, "authorization failed", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, redirect.Destination().String(), http.StatusFound)
}

// handleToken serves both grants, as the passport-vdc demo does.
func (e *Env) handleToken(w http.ResponseWriter, r *http.Request) {
	req, err := server.TokenEndpointRequestFromHTTP(r)
	if err != nil {
		server.NewError(server.ErrorInvalidRequest, http.StatusBadRequest, err.Error()).WriteJSON(w)
		return
	}
	ctx := r.Context()
	switch req.GrantType() {
	case "authorization_code":
		result, err := e.srv.ExchangeAuthorizationCode(ctx, req.AuthorizationCodeExchange())
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result.WriteJSON(w)
	case preAuthorizedCodeGrantType:
		params, err := req.Parameters()
		if err != nil {
			server.WriteError(w, err)
			return
		}
		attested, err := e.srv.AuthenticateAttestedClient(ctx, req.AttestedClientAuthentication())
		if err != nil {
			server.WriteError(w, err)
			return
		}
		binding, err := e.srv.VerifyTokenRequestBinding(ctx, attested.Client, req)
		if err != nil {
			server.WriteError(w, err)
			return
		}
		result, err := e.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"],
			Verified: &issuer.VerifiedTokenRequest{
				ClientID: attested.Client.ID().String(), DPoPThumbprint: binding.Thumbprint, NextDPoPNonce: binding.NextDPoPNonce,
			},
		})
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			issuer.WriteError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		result.WriteJSON(w)
	default:
		server.NewError(server.ErrorUnsupportedGrantType, http.StatusBadRequest, "unsupported grant_type").WriteJSON(w)
	}
}

func (e *Env) issuerURL(t testing.TB) fapi.URL {
	t.Helper()
	u, err := fapi.ParseIssuerURL(e.IssuerURL)
	must(t, err)
	return u
}

func (e *Env) endpoint(t testing.TB, path string) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL(e.IssuerURL + path)
	must(t, err)
	return u
}

// accessTokenAdapter mints the pre-authorized code grant's access tokens
// with the Authorization Server's keys.
type accessTokenAdapter struct{ inner server.AccessTokenIssuer }

func (a accessTokenAdapter) IssueAccessToken(ctx context.Context, p issuer.AccessTokenParams) (string, string, error) {
	return a.inner.IssueAccessToken(ctx, server.AccessTokenParams{
		Scope: p.Scope, Thumbprint: p.Thumbprint, Claims: p.Claims, Subject: p.Subject,
		ClientID: fapi.ClientID(p.ClientID), Issuer: p.Issuer, Audience: p.Audience,
		Now: p.Now, Lifetime: p.Lifetime, Random: p.Random,
	})
}

// Provider is the Wallet Provider: it attests any wallet instance and
// key it's asked to, in process.
type Provider struct {
	// Roots is the Wallet Provider's CA.
	Roots *x509.CertPool

	key  *ecdsa.PrivateKey
	cert *x509.Certificate

	mu sync.Mutex
	// KeyAttestations counts the Key Attestations issued.
	keyAttestations int
}

func newProvider(t testing.TB) *Provider {
	t.Helper()
	caCert, caKey := testcert.CA(t, "testhaip Wallet Provider CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	issuerURI, err := url.Parse(ProviderIssuer)
	must(t, err)
	now := time.Now()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "testhaip Wallet Provider"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{issuerURI},
	}, caCert, &key.PublicKey, caKey)
	must(t, err)
	cert, err := x509.ParseCertificate(der)
	must(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	return &Provider{Roots: roots, key: key, cert: cert}
}

func (p *Provider) header() attestation.Header {
	return attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(p.cert.Raw)}}
}

// WalletAttestation attests instanceKey as an instance of clientID.
func (p *Provider) WalletAttestation(_ context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	now := time.Now()
	return attestation.IssueWalletAttestation(p.key, oid4vci.ES256, p.header(), attestation.WalletAttestationClaims{
		Issuer: ProviderIssuer, Subject: clientID, InstanceKey: instanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
}

// KeyAttestation attests keys, carrying nonce.
func (p *Provider) KeyAttestation(_ context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	attested := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		raw, err := attestation.AttestedKey(k)
		if err != nil {
			return "", err
		}
		attested = append(attested, raw)
	}
	now := time.Now()
	exp := now.Add(time.Hour).Unix()
	p.mu.Lock()
	p.keyAttestations++
	p.mu.Unlock()
	return attestation.Issue(p.key, oid4vci.ES256, p.header(), attestation.Claims{
		Issuer: ProviderIssuer, IssuedAt: now.Unix(), ExpiresAt: &exp, Nonce: nonce, AttestedKeys: attested,
	})
}

// KeyAttestations returns how many Key Attestations p has issued.
func (p *Provider) KeyAttestations() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keyAttestations
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

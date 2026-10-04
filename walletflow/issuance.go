package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/storage"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Grant is how an offer is redeemed.
type Grant string

const (
	// GrantAuthorizationCode redeems an offer through the issuer's
	// authorization page: BeginAuthorization, then
	// CompleteAuthorization.
	GrantAuthorizationCode Grant = "authorization_code"
	// GrantPreAuthorizedCode redeems an offer with the code it carries,
	// and a PIN when Offer.TxCode is set: RedeemPreAuthorizedCode.
	GrantPreAuthorizedCode Grant = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
)

// Offer is what a Credential Offer offers, for the holder to see.
type Offer struct {
	// CredentialIssuer is the issuer's identifier, and IssuerName and
	// IssuerLogo its display name and logo, if its metadata gives them,
	// in the holder's preferred language (Config.Locales).
	CredentialIssuer string
	IssuerName       string
	IssuerLogo       *Logo
	// Credentials are the credentials offered.
	Credentials []OfferedCredential
	// Grant is how the wallet will redeem the offer.
	Grant Grant
	// TxCode, for GrantPreAuthorizedCode, describes the PIN the holder
	// must enter (sent separately by the issuer); nil means none.
	TxCode *oid4vci.TxCode
}

// OfferedCredential is one credential an offer offers.
type OfferedCredential struct {
	ConfigurationID string
	Format          string
	VCT             string
	DocType         string
	// Name, Description, Logo and the colours are the credential's
	// display metadata, if the issuer's metadata gives them, in the
	// holder's preferred language.
	Name            string
	Description     string
	Logo            *Logo
	BackgroundColor string
	TextColor       string
}

// IssuanceResult is what RequestCredentials obtained.
type IssuanceResult struct {
	// Credentials were issued, checked and stored.
	Credentials []StoredCredential
	// Deferred are credentials the issuer will issue later: poll them.
	Deferred []*Deferred
	// Failed are credentials the issuer refused, or that failed the
	// wallet's checks: asking again won't help, so they don't hold up
	// the rest.
	Failed []FailedCredential
}

// FailedCredential is an offered credential RequestCredentials couldn't
// obtain for good.
type FailedCredential struct {
	ConfigurationID string
	Err             error
}

type issuanceStep int

const (
	stepStarted issuanceStep = iota
	stepAuthorizing
	stepAuthorized
	stepRequested
	stepClosed
)

// Issuance receives the credentials one Credential Offer offers.
type Issuance struct {
	w        *Wallet
	offer    oid4vci.CredentialOffer
	metadata oid4vci.Metadata
	details  Offer

	mu          sync.Mutex
	step        issuanceStep
	instanceKey Key
	dpopKey     Key
	client      *client.Client
	session     client.SessionHandle
	// sessions is the client's SessionStore: it knows the state of the
	// authorization in progress, to forget it.
	sessions *sessionStore
	// resumed is set for an issuance ResumeIssuance rebuilt: its client
	// completes the authorization from the callback alone.
	resumed  bool
	resource wallet.ProtectedResourceClient
	// accessToken and its expiry, if the Token Response gave one, are
	// kept with each deferred credential.
	accessToken     fapi.Secret
	accessExpiresAt time.Time
	// obtained is what RequestCredentials has obtained so far, and
	// handled the configurations it has requested successfully.
	obtained IssuanceResult
	handled  map[string]bool
	// authorizationServer is the one the client authenticates to.
	authorizationServer string
	// refreshToken is the Token Response's, if it gave one
	// (Config.RequestRefresh); grantID, once a credential is stored, the
	// RefreshGrant keeping it, and the instance key with it.
	refreshToken fapi.Secret
	grantID      string
	grantStored  bool
	// replace, for a refresh, is the stored credential the new one
	// replaces.
	replace string
}

// StartIssuance resolves the Credential Offer offerURI (an
// openid-credential-offer:// link, or its credential_offer or
// credential_offer_uri) and fetches the issuer's metadata. Show the
// holder Offer before going on; call Close when done.
func (w *Wallet) StartIssuance(ctx context.Context, offerURI string) (*Issuance, error) {
	if err := w.checkIssuance(); err != nil {
		return nil, err
	}
	offer, err := w.core.ResolveCredentialOffer(ctx, offerURI)
	if err != nil {
		return nil, fmt.Errorf("walletflow: credential offer: %w", err)
	}
	metadata, err := w.core.FetchCredentialIssuerMetadata(ctx, offer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("walletflow: issuer metadata: %w", err)
	}
	if metadata.NonceEndpoint == nil {
		return nil, errors.New("walletflow: the issuer advertises no nonce endpoint, which the attestation proof needs")
	}
	s := &Issuance{w: w, offer: offer, metadata: metadata}
	s.details = describeOffer(offer, metadata, w.cfg.Locales)
	// Refuse an offer whose grant names an Authorization Server the
	// issuer doesn't list before the holder sees it: a pre-authorized
	// code and its PIN would go to that server.
	if s.details.Grant == GrantPreAuthorizedCode {
		_, err = wallet.PlanPreAuthorizedCode(offer, metadata)
	} else {
		_, err = wallet.PlanAuthorization(offer, metadata)
	}
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return s, nil
}

func describeOffer(offer oid4vci.CredentialOffer, metadata oid4vci.Metadata, locales []string) Offer {
	o := Offer{CredentialIssuer: offer.CredentialIssuer, Grant: GrantAuthorizationCode}
	// The pre-authorized code grant only when it's the one offered: an
	// offer with both leaves the choice to the wallet, and the
	// authorization code grant authenticates the holder at the issuer.
	if g := offer.Grants; g != nil && g.PreAuthorizedCode != nil && g.AuthorizationCode == nil {
		o.Grant, o.TxCode = GrantPreAuthorizedCode, g.PreAuthorizedCode.TxCode
	}
	for _, id := range offer.CredentialConfigurationIDs {
		conf := metadata.CredentialConfigurationsSupported[id]
		d := displayFor(metadata, id, locales)
		o.IssuerName, o.IssuerLogo = d.IssuerName, d.IssuerLogo
		o.Credentials = append(o.Credentials, OfferedCredential{
			ConfigurationID: id, Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType,
			Name: d.Name, Description: d.Description, Logo: d.Logo, BackgroundColor: d.BackgroundColor, TextColor: d.TextColor,
		})
	}
	return o
}

// Offer returns what the offer offers.
func (s *Issuance) Offer() Offer { return s.details }

// BeginAuthorization sends the Pushed Authorization Request, with a
// Wallet Attestation, and returns the authorization URL: open it in a
// browser, where the holder authenticates and approves, and pass the
// redirect back to RedirectURI to CompleteAuthorization.
func (s *Issuance) BeginAuthorization(ctx context.Context) (string, error) {
	return s.BeginAuthorizationWith(ctx, AuthorizationOptions{})
}

// AuthorizationOptions adjusts one authorization's request.
type AuthorizationOptions struct {
	// RedirectPort, when not 0, is the loopback port this authorization's
	// redirect comes back on, in place of Config.RedirectURI's own: for a
	// wallet that listens on a port the operating system picks for each
	// authorization (RFC 8252 §7.3). Config.RedirectURI must then be
	// loopback http to 127.0.0.1 or [::1], registered as a native app's,
	// which the Authorization Server matches on any port.
	RedirectPort uint16
}

// BeginAuthorizationWith is BeginAuthorization with opts.
func (s *Issuance) BeginAuthorizationWith(ctx context.Context, opts AuthorizationOptions) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != stepStarted || s.details.Grant != GrantAuthorizationCode {
		return "", ErrWrongStep
	}
	plan, err := wallet.PlanAuthorization(s.offer, s.metadata)
	if err != nil {
		return "", fmt.Errorf("walletflow: %w", err)
	}
	if err := s.newClient(ctx, plan.AuthorizationServer); err != nil {
		return "", err
	}
	authReq, err := wallet.BuildAuthorizationRequest(s.offer, plan.Scopes)
	if err != nil {
		return "", fmt.Errorf("walletflow: %w", err)
	}
	authReq.RedirectPort = opts.RedirectPort
	if s.w.cfg.RequestRefresh {
		authReq.Scope = append(authReq.Scope, offlineAccess)
	}
	session, err := s.client.BeginAuthorization(ctx, authReq)
	if err != nil {
		return "", fmt.Errorf("walletflow: pushed authorization request: %w", err)
	}
	s.session = session.Handle()
	s.step = stepAuthorizing
	return session.URL().String(), nil
}

// CompleteAuthorization takes the redirect back to RedirectURI — the
// whole URL, or just its query — and exchanges its authorization code
// for an access token bound to this issuance's DPoP key. It returns an
// *AuthorizationDeniedError if the redirect carries an error.
func (s *Issuance) CompleteAuthorization(ctx context.Context, redirect string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != stepAuthorizing {
		return ErrWrongStep
	}
	query := redirect
	if u, err := url.Parse(redirect); err == nil && u.Scheme != "" {
		query = u.RawQuery
	}
	result, err := s.client.CompleteAuthorization(ctx, client.AuthorizationCallback{RawQuery: query, Session: s.session})
	if err != nil {
		// fapigo consumes the authorization once the redirect's state
		// matches, whatever fails after (the token request, say): it
		// can't be completed again. Start over from BeginAuthorization,
		// with the same keys.
		_ = s.forgetAuthorization(context.WithoutCancel(ctx))
		s.step = stepStarted
		return fmt.Errorf("walletflow: authorization: %w", err)
	}
	switch r := result.(type) {
	case client.CompletionSuccess:
		s.resource = s.client.ProtectedResource(r.Tokens)
		s.accessToken = r.Tokens.AccessToken
		if r.Tokens.HasRefreshToken {
			s.refreshToken = r.Tokens.RefreshToken
		}
		if r.Tokens.HasExpiresIn {
			s.accessExpiresAt = r.Tokens.ObtainedAt.Add(r.Tokens.ExpiresIn)
		}
		s.step = stepAuthorized
		return nil
	case client.CompletionDenied:
		s.step = stepClosed
		return &AuthorizationDeniedError{Code: r.Code, Description: r.Description}
	default:
		return fmt.Errorf("walletflow: authorization: unexpected result %T", result)
	}
}

// RedeemPreAuthorizedCode redeems the offer's pre-authorized code at the
// token endpoint, with txCode, the PIN the holder entered ("" when
// Offer.TxCode is nil), authenticating with a Wallet Attestation (HAIP
// 1.0 §4.4.1). The access token is bound to this issuance's DPoP key.
// A wrong PIN fails with the issuer's error and can be retried, up to
// the issuer's limit.
func (s *Issuance) RedeemPreAuthorizedCode(ctx context.Context, txCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != stepStarted || s.details.Grant != GrantPreAuthorizedCode {
		return ErrWrongStep
	}
	// The code and PIN go to the server the issuer's metadata allows,
	// never just one the offer names.
	plan, err := wallet.PlanPreAuthorizedCode(s.offer, s.metadata)
	if err != nil {
		return fmt.Errorf("walletflow: %w", err)
	}
	asURL := plan.AuthorizationServer
	if s.client == nil {
		if err := s.newClient(ctx, asURL); err != nil {
			return err
		}
	}
	asMeta, err := s.w.core.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	tokenEndpoint, err := fapi.ParseEndpointURL(asMeta.TokenEndpoint, s.w.urlOptions()...)
	if err != nil {
		return fmt.Errorf("walletflow: token endpoint: %w", err)
	}
	token, err := s.w.core.RequestPreAuthorizedCodeToken(ctx, tokenEndpoint, wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: plan.PreAuthorizedCode, TxCode: txCode, DPoPKey: s.dpopKey, ClientAttestation: s.client,
	})
	if err != nil {
		return fmt.Errorf("walletflow: token: %w", err)
	}
	s.resource = s.w.core.DPoPResourceClient(token.AccessToken, s.dpopKey)
	s.accessToken = token.AccessToken
	if s.w.cfg.RequestRefresh {
		// An Authorization Server may issue a refresh token for this
		// grant too: there's no scope to ask for one with, so it's the
		// server's call.
		s.refreshToken = token.RefreshToken
	}
	if token.HasExpiresIn {
		s.accessExpiresAt = s.w.deps.Clock().Add(token.ExpiresIn)
	}
	s.step = stepAuthorized
	return nil
}

func (w *Wallet) urlOptions() []fapi.URLOption {
	if w.cfg.Development {
		return []fapi.URLOption{fapi.AllowLoopbackHTTP()}
	}
	return nil
}

// newClient creates this issuance's instance and DPoP keys, has the
// Wallet Provider attest the instance key, and builds the
// fapigo/client that authenticates with that attestation at asURL.
func (s *Issuance) newClient(ctx context.Context, asURL string) error {
	asMeta, err := s.w.core.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	issuer, endpoints, err := asMeta.ClientEndpoints()
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	if s.instanceKey == nil {
		if s.instanceKey, err = newKey(ctx, s.w.deps.Keys, KeyPurposeInstance); err != nil {
			return err
		}
	}
	if s.dpopKey == nil {
		if s.dpopKey, err = s.w.newDPoPKey(ctx); err != nil {
			return err
		}
	}
	walletAttestation, err := s.w.deps.Provider.WalletAttestation(ctx, s.w.cfg.ClientID, s.instanceKey.Public())
	if err != nil {
		return fmt.Errorf("walletflow: wallet attestation: %w", err)
	}
	c, err := s.oauthClient(issuer, endpoints, asURL, walletAttestation)
	if err != nil {
		return err
	}
	s.client, s.authorizationServer = c, asURL
	return nil
}

// forgetAuthorization deletes the authorization in progress, if there
// is one.
func (s *Issuance) forgetAuthorization(ctx context.Context) error {
	if s.sessions == nil || s.sessions.state == "" {
		return nil
	}
	return s.w.deps.Authorizations.DeleteAuthorization(ctx, s.sessions.state)
}

// oauthClient builds the fapigo/client for the authorization server
// issuer, authenticating with walletAttestation and the issuance's keys.
func (s *Issuance) oauthClient(issuer fapi.URL, endpoints client.Endpoints, asURL, walletAttestation string) (*client.Client, error) {
	if s.sessions == nil {
		s.sessions = &sessionStore{
			w: s.w, offer: s.offer, authorizationServer: asURL,
			instanceKeyID: s.instanceKey.ID(), dpopKeyID: s.dpopKey.ID(),
		}
	}
	var custody []keys.CustodyOption
	if c, ok := s.w.deps.Keys.(keys.KeyCustodyAssurance); ok {
		custody = append(custody, keys.DeclareCustody(c.KeyCustody()))
	}
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAttestationPoPSigning: s.instanceKey, keys.DPoPProofSigning: s.dpopKey},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAttestationPoPSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256},
		nil, custody...,
	)
	if err != nil {
		return nil, fmt.Errorf("walletflow: key manager: %w", err)
	}
	c, err := client.New(client.Config{
		Issuer: issuer, ClientID: fapi.ClientID(s.w.cfg.ClientID), RedirectURI: s.w.cfg.RedirectURI,
		Endpoints: endpoints,
		Profile:   client.ProfileFAPISecurity, Assurance: s.w.cfg.clientAssurance(),
		ClientAuthMethod:               storage.ClientAuthMethodAttestation,
		AuthorizationResponseIssPolicy: client.RequireAuthorizationResponseIss,
		// A pure OAuth client: no ID tokens or JARM, so no issuer keys.
		OAuthOnly: true,
		// A resumed issuance has no session handle: the session is the
		// callback's state, safe because the AuthorizationStore holds only
		// this wallet's own authorizations. Every other issuance holds
		// its handle, and keeps the stricter default.
		CallbackBinding: callbackBinding(s.resumed),
		Algorithms:      client.Algorithms{DPoP: fapi.ES256, ClientAttestationPoP: fapi.ES256},
		Limits: client.Limits{
			// Short: an authorization pending in the store can be
			// resumed (ResumeIssuance) until it expires, and the issuer
			// bounds its own side at about this too.
			SessionLifetime: 5 * time.Minute, MaxClockSkew: 5 * time.Second,
			HTTPTimeout: httpTimeout, MaxHTTPResponseBytes: maxResponseBytes, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		// The authorization's state, kept so the redirect can complete it
		// after the app is suspended (ResumeIssuance).
		Sessions: s.sessions,
		Keys:     km, HTTP: s.w.deps.HTTP,
		Clock: clientClock(s.w.deps.Clock), Random: s.w.deps.Random,
		Attestation: client.StaticAttestation(walletAttestation),
		// Reuses the DPoP nonce each response hands out, so only the
		// first request to an endpoint is challenged for one.
		DPoPNonceCache: client.NewInMemoryDPoPNonceCache(),
	})
	if err != nil {
		return nil, fmt.Errorf("walletflow: oauth client: %w", err)
	}
	return c, nil
}

type clientClock func() time.Time

func (c clientClock) Now() time.Time { return c() }

// RequestCredentials requests every offered credential, each bound to a
// new holder key that the Wallet Provider attests in a Key Attestation
// carrying the issuer's nonce. Each credential issued is checked
// (wallet.VerifyIssuedCredential), stored, and reported to the issuer's
// Notification Endpoint; each deferred one is returned to poll.
//
// If a request fails, RequestCredentials returns the error with
// everything obtained so far, and can be called again: the retry
// requests only the credentials not yet obtained, and returns
// everything obtained by every call.
func (s *Issuance) RequestCredentials(ctx context.Context) (IssuanceResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != stepAuthorized {
		return IssuanceResult{}, ErrWrongStep
	}
	requestEnc, responseEnc, err := wallet.EncryptionFromMetadata(s.metadata)
	if err != nil {
		return s.obtained, fmt.Errorf("walletflow: %w", err)
	}
	if s.handled == nil {
		s.handled = map[string]bool{}
	}
	for _, id := range s.offer.CredentialConfigurationIDs {
		if s.handled[id] {
			continue
		}
		stored, deferred, err := s.request(ctx, id, requestEnc, responseEnc)
		if err != nil && permanent(err) {
			s.handled[id] = true
			s.obtained.Failed = append(s.obtained.Failed, FailedCredential{ConfigurationID: id, Err: err})
			continue
		}
		if err != nil {
			return s.obtained, err
		}
		s.handled[id] = true
		if deferred != nil {
			s.obtained.Deferred = append(s.obtained.Deferred, deferred)
			continue
		}
		s.obtained.Credentials = append(s.obtained.Credentials, stored)
	}
	s.step = stepRequested
	if len(s.obtained.Credentials) == 0 && len(s.obtained.Deferred) == 0 && len(s.obtained.Failed) > 0 {
		// Nothing obtained: the first refusal is the answer.
		return s.obtained, s.obtained.Failed[0].Err
	}
	return s.obtained, nil
}

// permanent reports whether err, requesting one credential, won't go
// away by asking again: the credential failed the wallet's checks, or
// the issuer refused the request itself (an HTTP 4xx) rather than the
// nonce, the access token or the DPoP proof, which a retry renews.
func permanent(err error) bool {
	if errors.Is(err, errInvalidCredential) {
		return true
	}
	var protocol *wallet.Error
	if !errors.As(err, &protocol) || protocol.HTTPStatus < 400 || protocol.HTTPStatus >= 500 || protocol.HTTPStatus == 429 {
		return false
	}
	switch protocol.Code {
	case "invalid_nonce", "invalid_token", "invalid_dpop_proof", "use_dpop_nonce":
		return false
	}
	return true
}

func (s *Issuance) request(ctx context.Context, configID string, requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (StoredCredential, *Deferred, error) {
	nonce, err := s.w.core.RequestNonce(ctx, *s.metadata.NonceEndpoint)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: nonce: %w", err)
	}
	holders, keyAttestation, err := s.attestedHolders(ctx, nonce.CNonce)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			// Even when ctx is cancelled: a key left behind is an orphan.
			s.w.deleteKeys(context.WithoutCancel(ctx), holders)
		}
	}()
	result, err := s.w.core.RequestCredential(ctx, s.resource, s.metadata.CredentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: configID, Attestation: keyAttestation,
		RequestEncryption: requestEnc, ResponseEncryption: responseEnc,
	})
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: credential %q: %w", configID, err)
	}
	if result.TransactionID != "" {
		d, err := s.deferred(ctx, configID, holders, result, requestEnc, responseEnc)
		if err != nil {
			return StoredCredential{}, nil, err
		}
		keep = true
		return StoredCredential{}, d, nil
	}
	grantID, err := s.grantFor()
	if err != nil {
		return StoredCredential{}, nil, err
	}
	stored, err := s.w.accept(ctx, issued{
		issuer: s.offer.CredentialIssuer, metadata: s.metadata, resource: s.resource,
		configID: configID, holders: holders, result: result, grantID: grantID, replace: s.replace,
	})
	if err != nil {
		return StoredCredential{}, nil, err
	}
	s.storeGrant(ctx)
	keep = true
	s.w.deleteUnused(context.WithoutCancel(ctx), keyIDs(holders), stored)
	return stored, nil, nil
}

// attestedHolders creates one holder key per copy to request, and has
// the Wallet Provider attest them together for nonce: the issuer issues
// one copy bound to each. A key created before a failure is deleted.
func (s *Issuance) attestedHolders(ctx context.Context, nonce string) ([]Key, string, error) {
	holders := make([]Key, 0, s.batchSize())
	pubs := make([]*ecdsa.PublicKey, 0, s.batchSize())
	for range s.batchSize() {
		holder, err := newKey(ctx, s.w.deps.Keys, KeyPurposeHolder)
		if err != nil {
			s.w.deleteKeys(context.WithoutCancel(ctx), holders)
			return nil, "", err
		}
		holders = append(holders, holder)
		pub, _ := p256(holder) // newKey checked it
		pubs = append(pubs, pub)
	}
	keyAttestation, err := s.w.deps.Provider.KeyAttestation(ctx, pubs, nonce)
	if err != nil {
		s.w.deleteKeys(context.WithoutCancel(ctx), holders)
		return nil, "", fmt.Errorf("walletflow: key attestation: %w", err)
	}
	return holders, keyAttestation, nil
}

// deferred keeps a credential the issuer deferred, with holders, to poll.
func (s *Issuance) deferred(ctx context.Context, configID string, holders []Key, result wallet.CredentialResult,
	requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (*Deferred, error) {
	if s.metadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("walletflow: credential %q was deferred, but the issuer advertises no deferred credential endpoint", configID)
	}
	id, err := randomID(s.w.deps.Random)
	if err != nil {
		return nil, err
	}
	return s.w.keepDeferred(ctx, PendingDeferred{
		ID: id, CredentialIssuer: s.offer.CredentialIssuer, ConfigurationID: configID, TransactionID: result.TransactionID,
		AccessToken: s.accessToken, AccessTokenExpiresAt: s.accessExpiresAt,
		DPoPKeyID: s.dpopKey.ID(), HolderKeyIDs: keyIDs(holders), Interval: result.Interval, DeferredAt: s.w.deps.Clock().UTC(),
	}, s.metadata, s.resource, requestEnc, responseEnc)
}

// deleteKeys deletes keys, best effort.
func (w *Wallet) deleteKeys(ctx context.Context, keys []Key) {
	for _, k := range keys {
		_ = w.deps.Keys.DeleteKey(ctx, k.ID())
	}
}

// batchSize is how many copies of each credential to request: the
// wallet's BatchSize (DefaultBatchSize when zero), capped at the
// issuer's batch_size; one when the issuer doesn't offer batches.
func (s *Issuance) batchSize() int {
	b := s.metadata.BatchCredentialIssuance
	if b == nil {
		return 1
	}
	want := s.w.cfg.BatchSize
	if want <= 0 {
		want = DefaultBatchSize
	}
	return max(1, min(want, b.BatchSize))
}

func keyIDs(keys []Key) []string {
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID()
	}
	return ids
}

// errInvalidCredential is wrapped by accept for a credential failing the
// wallet's checks: asking again won't change it.
var errInvalidCredential = errors.New("is invalid")

// issued is a credential result to accept: from issuer, under
// metadata, polled with resource, for configID, its copies bound to
// holders.
type issued struct {
	issuer   string
	metadata oid4vci.Metadata
	resource wallet.ProtectedResourceClient
	configID string
	holders  []Key
	result   wallet.CredentialResult
	// grantID is the RefreshGrant that can refresh it, if any; replace,
	// the stored credential it replaces, if any.
	grantID, replace string
}

// accept checks every copy c's result carries, each bound to one of
// c.holders, stores them as one credential, and tells the issuer whether
// the wallet kept it (§11).
func (w *Wallet) accept(ctx context.Context, c issued) (StoredCredential, error) {
	if n := len(c.result.Credentials); n == 0 || n > len(c.holders) {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: got %d copies for %d keys", c.configID, n, len(c.holders))
	}
	conf := c.metadata.CredentialConfigurationsSupported[c.configID]
	now := w.deps.Clock()
	unbound := slices.Clone(c.holders)
	copies := make([]CredentialCopy, 0, len(c.result.Credentials))
	var first wallet.VerifiedIssuedCredential
	for i, ic := range c.result.Credentials {
		verified, key, err := w.verifyCopy(ctx, conf, ic.Credential, unbound, now)
		if err != nil {
			w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the credential failed the wallet's checks")
			return StoredCredential{}, fmt.Errorf("walletflow: credential %q %w: %w", c.configID, errInvalidCredential, err)
		}
		unbound = slices.DeleteFunc(unbound, func(k Key) bool { return k.ID() == key.ID() })
		copies = append(copies, CredentialCopy{Credential: ic.Credential, HolderKeyID: key.ID()})
		if i == 0 {
			first = verified
		}
	}
	id := c.replace
	if id == "" {
		var err error
		if id, err = randomID(w.deps.Random); err != nil {
			return StoredCredential{}, err
		}
	}
	stored := StoredCredential{
		ID: id, CredentialIssuer: c.issuer, ConfigurationID: c.configID,
		Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType,
		Credential: copies[0].Credential, HolderKeyID: copies[0].HolderKeyID, Copies: copies,
		ReceivedAt: now.UTC(), Claims: first.Claims,
		Display: displayFor(c.metadata, c.configID, w.cfg.Locales), ValidUntil: first.ValidUntil,
		StatusList: first.StatusList, StatusListCWT: first.StatusListCWT, GrantID: c.grantID,
	}
	if err := w.store(ctx, stored, c); err != nil {
		if errors.Is(err, ErrNotFound) {
			// Deleted while it was refreshed: the new copies aren't kept.
			w.notify(ctx, c, oid4vci.NotificationEventCredentialDeleted, "the holder deleted the credential")
			return StoredCredential{}, err
		}
		w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the wallet couldn't store the credential")
		return StoredCredential{}, fmt.Errorf("walletflow: store credential %q: %w", c.configID, err)
	}
	w.notify(ctx, c, oid4vci.NotificationEventCredentialAccepted, "")
	return stored, nil
}

// store stores a new credential, or one replacing c.replace
// (replaceStored).
func (w *Wallet) store(ctx context.Context, stored StoredCredential, c issued) error {
	if c.replace == "" {
		return w.deps.Credentials.Put(ctx, stored)
	}
	w.credMu.Lock()
	defer w.credMu.Unlock()
	return w.replaceStored(ctx, stored, c.grantID)
}

// verifyCopy checks one copy, and finds which of keys it's bound to.
func (w *Wallet) verifyCopy(ctx context.Context, conf oid4vci.CredentialConfigurationMetadata, credential string, keys []Key, now time.Time) (wallet.VerifiedIssuedCredential, Key, error) {
	var lastErr error
	for _, k := range keys {
		verified, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
			Configuration: conf, Credential: credential, HolderKey: k.Public(),
			IssuerRoots: w.cfg.IssuerRoots, Now: now,
		})
		if err == nil {
			return verified, k, nil
		}
		lastErr = err
	}
	return wallet.VerifiedIssuedCredential{}, nil, lastErr
}

// notify sends a Notification Request when the issuer gave the
// credential a notification_id. It's best effort: a wallet is never
// required to notify, so a failure doesn't fail receiving.
func (w *Wallet) notify(ctx context.Context, c issued, event oid4vci.NotificationEvent, description string) {
	if c.result.NotificationID == "" || c.metadata.NotificationEndpoint == nil {
		return
	}
	_ = w.core.RequestNotification(ctx, c.resource, *c.metadata.NotificationEndpoint, wallet.NotificationRequest{
		NotificationID: c.result.NotificationID, Event: event, EventDescription: description,
	})
}

// Close ends the issuance: it deletes its instance key unless a refresh
// grant keeps it (Config.RequestRefresh), and its DPoP key unless a
// deferred credential it obtained still polls with it. Its
// deferred credentials stay pending (Wallet.Deferred) until they're
// settled or abandoned. Close is safe to call more than once.
func (s *Issuance) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.step == stepAuthorizing {
		// An authorization begun and not completed can't be any more.
		errs = append(errs, s.forgetAuthorization(ctx))
	}
	s.step = stepClosed
	// The instance key stays with a refresh grant a stored credential
	// uses: every refresh authenticates with it.
	if s.instanceKey != nil && !s.grantStored {
		errs = append(errs, s.w.deps.Keys.DeleteKey(ctx, s.instanceKey.ID()))
	}
	if s.dpopKey != nil {
		s.w.mu.Lock()
		delete(s.w.liveDPoP, s.dpopKey.ID())
		s.w.mu.Unlock()
		errs = append(errs, s.w.releaseDPoPKey(ctx, s.dpopKey.ID()))
	}
	s.instanceKey, s.dpopKey = nil, nil
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("walletflow: close issuance: %w", err)
	}
	return nil
}

// callbackBinding is how an issuance's client ties the callback to the
// wallet: by its session handle, or for a resumed one by the callback's
// own state in the wallet's own store.
func callbackBinding(resumed bool) client.CallbackBinding {
	if resumed {
		return client.CallbackBindingDeviceLocalStore
	}
	return client.CallbackBindingSessionHandle
}

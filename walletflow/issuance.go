package walletflow

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/url"
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
	// CredentialIssuer is the issuer's identifier, and IssuerName its
	// display name, if its metadata gives one.
	CredentialIssuer string
	IssuerName       string
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
	// Name is the credential's display name, if the issuer's metadata
	// gives one.
	Name string
}

// IssuanceResult is what RequestCredentials obtained.
type IssuanceResult struct {
	// Credentials were issued, checked and stored.
	Credentials []StoredCredential
	// Deferred are credentials the issuer will issue later: poll them.
	Deferred []*Deferred
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
	resource    wallet.ProtectedResourceClient
	// accessToken and its expiry, if the Token Response gave one, are
	// kept with each deferred credential.
	accessToken     fapi.Secret
	accessExpiresAt time.Time
	// obtained is what RequestCredentials has obtained so far, and
	// handled the configurations it has requested successfully.
	obtained IssuanceResult
	handled  map[string]bool
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
	s.details = describeOffer(offer, metadata)
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

func describeOffer(offer oid4vci.CredentialOffer, metadata oid4vci.Metadata) Offer {
	o := Offer{CredentialIssuer: offer.CredentialIssuer, Grant: GrantAuthorizationCode}
	if len(metadata.Display) > 0 {
		o.IssuerName = metadata.Display[0].Name
	}
	// The pre-authorized code grant only when it's the one offered: an
	// offer with both leaves the choice to the wallet, and the
	// authorization code grant authenticates the holder at the issuer.
	if g := offer.Grants; g != nil && g.PreAuthorizedCode != nil && g.AuthorizationCode == nil {
		o.Grant, o.TxCode = GrantPreAuthorizedCode, g.PreAuthorizedCode.TxCode
	}
	for _, id := range offer.CredentialConfigurationIDs {
		conf := metadata.CredentialConfigurationsSupported[id]
		oc := OfferedCredential{ConfigurationID: id, Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType}
		if cm := conf.CredentialMetadata; cm != nil && len(cm.Display) > 0 {
			oc.Name = cm.Display[0].Name
		}
		o.Credentials = append(o.Credentials, oc)
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
		return fmt.Errorf("walletflow: authorization: %w", err)
	}
	switch r := result.(type) {
	case client.CompletionSuccess:
		s.resource = s.client.ProtectedResource(r.Tokens)
		s.accessToken = r.Tokens.AccessToken
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
	s.client = c
	return nil
}

// oauthClient builds the fapigo/client for the authorization server
// issuer, authenticating with walletAttestation and the issuance's keys.
func (s *Issuance) oauthClient(issuer fapi.URL, endpoints client.Endpoints, asURL, walletAttestation string) (*client.Client, error) {
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
		OAuthOnly:  true,
		Algorithms: client.Algorithms{DPoP: fapi.ES256, ClientAttestationPoP: fapi.ES256},
		Limits: client.Limits{
			SessionLifetime: 10 * time.Minute, MaxClockSkew: 5 * time.Second,
			HTTPTimeout: httpTimeout, MaxHTTPResponseBytes: maxResponseBytes, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		// The authorization's state, kept so the redirect can complete it
		// after the app is suspended (ResumeIssuance).
		Sessions: &sessionStore{
			w: s.w, offer: s.offer, authorizationServer: asURL,
			instanceKeyID: s.instanceKey.ID(), dpopKeyID: s.dpopKey.ID(),
		},
		Keys: km, HTTP: s.w.deps.HTTP,
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
	return s.obtained, nil
}

func (s *Issuance) request(ctx context.Context, configID string, requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (StoredCredential, *Deferred, error) {
	nonce, err := s.w.core.RequestNonce(ctx, *s.metadata.NonceEndpoint)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: nonce: %w", err)
	}
	holder, err := newKey(ctx, s.w.deps.Keys, KeyPurposeHolder)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = s.w.deps.Keys.DeleteKey(ctx, holder.ID())
		}
	}()
	pub, _ := p256(holder) // newKey checked it
	keyAttestation, err := s.w.deps.Provider.KeyAttestation(ctx, []*ecdsa.PublicKey{pub}, nonce.CNonce)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: key attestation: %w", err)
	}
	result, err := s.w.core.RequestCredential(ctx, s.resource, s.metadata.CredentialEndpoint, wallet.CredentialRequest{
		CredentialConfigurationID: configID, Attestation: keyAttestation,
		RequestEncryption: requestEnc, ResponseEncryption: responseEnc,
	})
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: credential %q: %w", configID, err)
	}
	if result.TransactionID != "" {
		if s.metadata.DeferredCredentialEndpoint == nil {
			return StoredCredential{}, nil, fmt.Errorf("walletflow: credential %q was deferred, but the issuer advertises no deferred credential endpoint", configID)
		}
		id, err := randomID(s.w.deps.Random)
		if err != nil {
			return StoredCredential{}, nil, err
		}
		d, err := s.w.keepDeferred(ctx, PendingDeferred{
			ID: id, CredentialIssuer: s.offer.CredentialIssuer, ConfigurationID: configID, TransactionID: result.TransactionID,
			AccessToken: s.accessToken, AccessTokenExpiresAt: s.accessExpiresAt,
			DPoPKeyID: s.dpopKey.ID(), HolderKeyID: holder.ID(), Interval: result.Interval, DeferredAt: s.w.deps.Clock().UTC(),
		}, s.metadata, s.resource, requestEnc, responseEnc)
		if err != nil {
			return StoredCredential{}, nil, err
		}
		keep = true
		return StoredCredential{}, d, nil
	}
	stored, err := s.w.accept(ctx, issued{
		issuer: s.offer.CredentialIssuer, metadata: s.metadata, resource: s.resource,
		configID: configID, holder: holder, result: result,
	})
	if err != nil {
		return StoredCredential{}, nil, err
	}
	keep = true
	return stored, nil, nil
}

// issued is a credential result to accept: from issuer, under
// metadata, polled with resource, for configID, bound to holder.
type issued struct {
	issuer   string
	metadata oid4vci.Metadata
	resource wallet.ProtectedResourceClient
	configID string
	holder   Key
	result   wallet.CredentialResult
}

// accept checks the one credential c's result carries, stores it, and
// tells the issuer whether the wallet kept it (§11).
func (w *Wallet) accept(ctx context.Context, c issued) (StoredCredential, error) {
	if len(c.result.Credentials) != 1 {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: got %d credentials, want 1", c.configID, len(c.result.Credentials))
	}
	conf := c.metadata.CredentialConfigurationsSupported[c.configID]
	credential := c.result.Credentials[0].Credential
	now := w.deps.Clock()
	verified, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
		Configuration: conf, Credential: credential, HolderKey: c.holder.Public(),
		IssuerRoots: w.cfg.IssuerRoots, Now: now,
	})
	if err != nil {
		w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the credential failed the wallet's checks")
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q is invalid: %w", c.configID, err)
	}
	id, err := randomID(w.deps.Random)
	if err != nil {
		return StoredCredential{}, err
	}
	stored := StoredCredential{
		ID: id, CredentialIssuer: c.issuer, ConfigurationID: c.configID,
		Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType,
		Credential: credential, HolderKeyID: c.holder.ID(), ReceivedAt: now.UTC(), Claims: verified.Claims,
	}
	if err := w.deps.Credentials.Put(ctx, stored); err != nil {
		w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the wallet couldn't store the credential")
		return StoredCredential{}, fmt.Errorf("walletflow: store credential %q: %w", c.configID, err)
	}
	w.notify(ctx, c, oid4vci.NotificationEventCredentialAccepted, "")
	return stored, nil
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

// Close ends the issuance: it deletes its instance key, and its DPoP
// key unless a deferred credential it obtained still polls with it. Its
// deferred credentials stay pending (Wallet.Deferred) until they're
// settled or abandoned. Close is safe to call more than once.
func (s *Issuance) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	if s.step == stepAuthorizing {
		// An authorization begun and not completed can't be any more.
		errs = append(errs, s.w.deps.Authorizations.DeleteAuthorization(ctx, s.session.String()))
	}
	s.step = stepClosed
	if s.instanceKey != nil {
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

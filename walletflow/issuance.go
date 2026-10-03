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
	"github.com/idfoundry/fapigo/storage/memstore"

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
	deferred    []*Deferred
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
		if s.dpopKey, err = newKey(ctx, s.w.deps.Keys, KeyPurposeDPoP); err != nil {
			return err
		}
	}
	walletAttestation, err := s.w.deps.Provider.WalletAttestation(ctx, s.w.cfg.ClientID, s.instanceKey.Public())
	if err != nil {
		return fmt.Errorf("walletflow: wallet attestation: %w", err)
	}
	km, err := keys.NewKeyManagerFromSigners(
		map[keys.SigningPurpose]crypto.Signer{keys.ClientAttestationPoPSigning: s.instanceKey, keys.DPoPProofSigning: s.dpopKey},
		map[keys.SigningPurpose]fapi.SignatureAlgorithm{keys.ClientAttestationPoPSigning: fapi.ES256, keys.DPoPProofSigning: fapi.ES256},
		nil,
	)
	if err != nil {
		return fmt.Errorf("walletflow: key manager: %w", err)
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
		Sessions: memstore.NewSessionStore(), Keys: km, HTTP: s.w.deps.HTTP,
		Clock: clientClock(s.w.deps.Clock), Random: s.w.deps.Random,
		Attestation: client.StaticAttestation(walletAttestation),
		// Reuses the DPoP nonce each response hands out, so only the
		// first request to an endpoint is challenged for one.
		DPoPNonceCache: client.NewInMemoryDPoPNonceCache(),
	})
	if err != nil {
		return fmt.Errorf("walletflow: oauth client: %w", err)
	}
	s.client = c
	return nil
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
			s.deferred = append(s.deferred, deferred)
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
		keep = true
		return StoredCredential{}, &Deferred{
			s: s, configID: configID, holder: holder, transactionID: result.TransactionID,
			interval: result.Interval, requestEnc: requestEnc, responseEnc: responseEnc,
		}, nil
	}
	stored, err := s.accept(ctx, configID, holder, result)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	keep = true
	return stored, nil, nil
}

// accept checks the one credential result carries, bound to holder,
// stores it, and tells the issuer whether the wallet kept it (§11).
func (s *Issuance) accept(ctx context.Context, configID string, holder Key, result wallet.CredentialResult) (StoredCredential, error) {
	if len(result.Credentials) != 1 {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: got %d credentials, want 1", configID, len(result.Credentials))
	}
	conf := s.metadata.CredentialConfigurationsSupported[configID]
	credential := result.Credentials[0].Credential
	now := s.w.deps.Clock()
	verified, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
		Configuration: conf, Credential: credential, HolderKey: holder.Public(),
		IssuerRoots: s.w.cfg.IssuerRoots, Now: now,
	})
	if err != nil {
		s.notify(ctx, result.NotificationID, oid4vci.NotificationEventCredentialFailure, "the credential failed the wallet's checks")
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q is invalid: %w", configID, err)
	}
	id, err := randomID(s.w.deps.Random)
	if err != nil {
		return StoredCredential{}, err
	}
	stored := StoredCredential{
		ID: id, CredentialIssuer: s.offer.CredentialIssuer, ConfigurationID: configID,
		Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType,
		Credential: credential, HolderKeyID: holder.ID(), ReceivedAt: now.UTC(), Claims: verified.Claims,
	}
	if err := s.w.deps.Credentials.Put(ctx, stored); err != nil {
		s.notify(ctx, result.NotificationID, oid4vci.NotificationEventCredentialFailure, "the wallet couldn't store the credential")
		return StoredCredential{}, fmt.Errorf("walletflow: store credential %q: %w", configID, err)
	}
	s.notify(ctx, result.NotificationID, oid4vci.NotificationEventCredentialAccepted, "")
	return stored, nil
}

// notify sends a Notification Request when the issuer gave the
// credential a notification_id. It's best effort: a wallet is never
// required to notify, so a failure doesn't fail receiving.
func (s *Issuance) notify(ctx context.Context, notificationID string, event oid4vci.NotificationEvent, description string) {
	if notificationID == "" || s.metadata.NotificationEndpoint == nil {
		return
	}
	_ = s.w.core.RequestNotification(ctx, s.resource, *s.metadata.NotificationEndpoint, wallet.NotificationRequest{
		NotificationID: notificationID, Event: event, EventDescription: description,
	})
}

// Close ends the issuance: it deletes its instance and DPoP keys, and
// the holder keys of deferred credentials not yet issued, which can no
// longer be polled. Close is safe to call more than once.
func (s *Issuance) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step == stepClosed && s.instanceKey == nil && s.dpopKey == nil && len(s.deferred) == 0 {
		return nil
	}
	s.step = stepClosed
	var errs []error
	for _, k := range []Key{s.instanceKey, s.dpopKey} {
		if k != nil {
			errs = append(errs, s.w.deps.Keys.DeleteKey(ctx, k.ID()))
		}
	}
	s.instanceKey, s.dpopKey = nil, nil
	for _, d := range s.deferred {
		if d.done {
			continue
		}
		d.done = true
		errs = append(errs, s.w.deps.Keys.DeleteKey(ctx, d.holder.ID()))
	}
	s.deferred = nil
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("walletflow: close issuance: %w", err)
	}
	return nil
}

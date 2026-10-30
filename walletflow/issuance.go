package walletflow

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"maps"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	// CredentialIdentifier is the credential_identifier it was requested
	// by, "" when it was requested by its configuration ID.
	CredentialIdentifier string
	Err                  error
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
	// identifiers are the credential_identifiers the Token Response
	// granted for each configuration, in its authorization_details:
	// a configuration listed here is requested by each of them, one
	// Credential Dataset apiece (OpenID4VCI 1.0 §3.3, §6.2), never by
	// its configuration ID (§8.2).
	identifiers map[string][]string
	// obtained is what RequestCredentials has obtained so far, and
	// handled the requests (requestUnit.key) it has made successfully.
	obtained IssuanceResult
	handled  map[string]bool
	// grant is the grant that redeems the offer, authorizationServer
	// the server it's redeemed at, with its metadata, and auth how the
	// wallet authenticates there (chooseGrant).
	grant               Grant
	authorizationServer string
	asMeta              wallet.AuthorizationServerMetadata
	auth                clientAuth
	// tokenType is the access token's: wallet.TokenTypeDPoP or
	// wallet.TokenTypeBearer.
	tokenType string
	// nonceRetries counts the requests retried on invalid_nonce, each
	// with fresh holder keys (and Key Attestations), up to
	// maxNonceRetries for the whole issuance.
	nonceRetries int
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
	if err := w.checkOffered(metadata, offer.CredentialConfigurationIDs); err != nil {
		return nil, err
	}
	s := &Issuance{w: w, offer: offer, metadata: metadata}
	// The grant, and how its token request authenticates, are settled
	// before the holder sees the offer: an offer the wallet can't redeem
	// is refused now, not after the holder has entered a PIN.
	if err := s.chooseGrant(ctx); err != nil {
		return nil, err
	}
	s.details = describeOffer(offer, metadata, s.grant, w.cfg.Locales)
	return s, nil
}

// chooseGrant settles which grant redeems the offer, at which
// Authorization Server, and how the wallet authenticates there. An
// offer with both grants leaves the choice to the wallet (OpenID4VCI
// 1.0 §4.1.1): the authorization code grant, which authenticates the
// holder at the issuer, where the wallet can complete it, else the
// pre-authorized code. An offer naming an Authorization Server the
// issuer doesn't list is refused: a pre-authorized code and its PIN
// would go to that server.
func (s *Issuance) chooseGrant(ctx context.Context) error {
	g := s.offer.Grants
	var candidates []Grant
	if g == nil {
		// No grants: the authorization code grant, the only one a wallet
		// can begin without an offer's code (§4.1.1).
		candidates = []Grant{GrantAuthorizationCode}
	} else {
		if g.AuthorizationCode != nil {
			candidates = append(candidates, GrantAuthorizationCode)
		}
		if g.PreAuthorizedCode != nil {
			candidates = append(candidates, GrantPreAuthorizedCode)
		}
	}
	var errs []error
	for _, grant := range candidates {
		err := s.planGrant(ctx, grant)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	// Every grant's reason, so errors.Is finds whichever sentinel applies.
	return errors.Join(errs...)
}

// planGrant checks the wallet can redeem the offer with grant, and if
// so keeps the choice: the Authorization Server, and how the wallet
// authenticates at it.
func (s *Issuance) planGrant(ctx context.Context, grant Grant) error {
	var asURL string
	if grant == GrantPreAuthorizedCode {
		plan, err := wallet.PlanPreAuthorizedCode(s.offer, s.metadata)
		if err != nil {
			return fmt.Errorf("walletflow: %w", err)
		}
		asURL = plan.AuthorizationServer
	} else {
		if err := s.w.checkAuthorizationCode(); err != nil {
			return err
		}
		plan, err := wallet.PlanAuthorization(s.offer, s.metadata)
		if err != nil {
			return fmt.Errorf("walletflow: %w", err)
		}
		asURL = plan.AuthorizationServer
	}
	asMeta, err := s.w.core.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	// An offer's grants are the issuer's to give: its server is held to
	// grant_types_supported only for an offer with none, where the
	// wallet chooses the grant (§4.1.1).
	if s.offer.Grants == nil && !asMeta.SupportsGrantType(string(grant)) {
		return fmt.Errorf("walletflow: the authorization server doesn't serve the %s grant", grant)
	}
	auth, err := s.w.chooseClientAuth(asMeta, grant)
	if err != nil {
		return fmt.Errorf("walletflow: %s grant: %w", grant, err)
	}
	if grant == GrantAuthorizationCode && auth != clientAuthAttestation {
		// fapigo/client's authorization code flow authenticates the
		// client; it has no public client.
		return fmt.Errorf("walletflow: %s grant: %w", grant, ErrClientAuthUnsupported)
	}
	s.grant, s.auth, s.authorizationServer, s.asMeta = grant, auth, asURL, asMeta
	return nil
}

// checkBindable reports a credential the wallet can't hold: one bound to
// no key (no cryptographic_binding_methods_supported, OpenID4VCI 1.0
// §12.2.4), which the wallet doesn't receive — anyone holding a copy
// could present it, and an mdoc's MSO always names a device key, so one
// the wallet didn't prove would be someone else's — or one bound by a
// method the wallet lacks.
// checkOffered checks every configuration ids names is one the issuer
// publishes, that this wallet can bind to a key and verify when it
// arrives, and that the issuer follows the wallet's profile: before the
// holder authenticates or enters a code, not once the credential is
// issued.
func (w *Wallet) checkOffered(metadata oid4vci.Metadata, ids []string) error {
	if n := len(distinct(ids)); n > MaxCredentialRequests {
		return fmt.Errorf("walletflow: the offer names %d credentials, more than the %d one issuance requests", n, MaxCredentialRequests)
	}
	for _, id := range ids {
		conf, ok := metadata.CredentialConfigurationsSupported[id]
		if !ok {
			// §4.1.1: each identifies one of credential_configurations_supported.
			return fmt.Errorf("walletflow: credential %q isn't in the issuer's metadata", id)
		}
		if err := checkBindable(conf); err != nil {
			return fmt.Errorf("walletflow: credential %q: %w", id, err)
		}
		if err := checkReceivable(conf); err != nil {
			return fmt.Errorf("walletflow: credential %q: %w", id, err)
		}
	}
	return w.checkProfile(metadata, ids)
}

// checkReceivable refuses a configuration whose credential the wallet
// couldn't verify when it arrives: a format it doesn't support, or one
// with no vct or doctype to check the credential against.
func checkReceivable(conf oid4vci.CredentialConfigurationMetadata) error {
	switch conf.Format {
	case sdjwtvc.CredentialFormat:
		if conf.VCT == "" {
			return fmt.Errorf("%w: it names no vct", ErrFormatUnsupported)
		}
	case mdoc.CredentialFormat:
		if conf.DocType == "" {
			return fmt.Errorf("%w: it names no doctype", ErrFormatUnsupported)
		}
	default:
		return fmt.Errorf("%w: format %q", ErrFormatUnsupported, conf.Format)
	}
	return nil
}

func checkBindable(conf oid4vci.CredentialConfigurationMetadata) error {
	if len(conf.CryptographicBindingMethodsSupported) == 0 {
		return fmt.Errorf("%w: it's bound to no key", ErrProofUnsupported)
	}
	if !supportsBinding(conf) {
		return fmt.Errorf("%w: it binds credentials only by %v", ErrProofUnsupported, conf.CryptographicBindingMethodsSupported)
	}
	return nil
}

func describeOffer(offer oid4vci.CredentialOffer, metadata oid4vci.Metadata, grant Grant, locales []string) Offer {
	o := Offer{CredentialIssuer: offer.CredentialIssuer, Grant: grant}
	if g := offer.Grants; grant == GrantPreAuthorizedCode && g != nil && g.PreAuthorizedCode != nil {
		o.TxCode = g.PreAuthorizedCode.TxCode
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
// redirect back to RedirectURI to CompleteAuthorization. Called again
// before then — the holder closed the issuer's page, say — it starts
// a new authorization with the same keys, and the earlier one's
// redirect no longer completes it.
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
	if (s.step != stepStarted && s.step != stepAuthorizing) || s.grant != GrantAuthorizationCode {
		return "", ErrWrongStep
	}
	plan, err := wallet.PlanAuthorization(s.offer, s.metadata)
	if err != nil {
		return "", fmt.Errorf("walletflow: %w", err)
	}
	if err := s.newClient(ctx, plan.AuthorizationServer, true); err != nil {
		return "", err
	}
	authReq, err := wallet.BuildAuthorizationRequestForPlan(s.offer, plan)
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
		if s.authorizationPending(context.WithoutCancel(ctx)) {
			// Not consumed — a redirect that isn't this authorization's
			// (another's state, a stale one): the genuine redirect can
			// still complete it.
			return fmt.Errorf("walletflow: authorization: %w", err)
		}
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
		if s.tokenType, err = s.w.tokenType(r.Tokens.TokenType); err != nil {
			s.step = stepClosed
			return err
		}
		s.resource = s.client.ProtectedResource(r.Tokens)
		s.accessToken = r.Tokens.AccessToken
		if s.identifiers, err = credentialIdentifiers(r.Tokens.AuthorizationDetails); err != nil {
			s.step = stepClosed
			return fmt.Errorf("walletflow: token response: %w", err)
		}
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
		// The callback's text is anyone's who can make the redirect.
		return &AuthorizationDeniedError{Code: cleanText(r.Code), Description: cleanText(r.Description)}
	default:
		return fmt.Errorf("walletflow: authorization: unexpected result %T", result)
	}
}

// RedeemPreAuthorizedCode redeems the offer's pre-authorized code at the
// token endpoint, with txCode, the PIN the holder entered ("" when
// Offer.TxCode is nil). It authenticates with a Wallet Attestation
// where the Authorization Server takes one (HAIP 1.0 §4.4.1), and
// otherwise with none, where the server allows that (OpenID4VCI 1.0
// §12.3). The access token is bound to this issuance's DPoP key, unless
// the server issues a Bearer one. A refused PIN fails with
// ErrTxCodeRefused and can be retried, up to the issuer's limit.
func (s *Issuance) RedeemPreAuthorizedCode(ctx context.Context, txCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.step != stepStarted || s.grant != GrantPreAuthorizedCode {
		return ErrWrongStep
	}
	if err := checkTxCode(s.details.TxCode, txCode); err != nil {
		return err
	}
	// The code and PIN go to the server the issuer's metadata allows,
	// never just one the offer names.
	plan, err := wallet.PlanPreAuthorizedCode(s.offer, s.metadata)
	if err != nil {
		return fmt.Errorf("walletflow: %w", err)
	}
	tokenEndpoint, err := fapi.ParseEndpointURL(s.asMeta.TokenEndpoint, s.w.urlOptions()...)
	if err != nil {
		return fmt.Errorf("walletflow: token endpoint: %w", err)
	}
	// The token is for this Credential Issuer (RFC 8707), as in the
	// authorization code flow.
	req := wallet.PreAuthorizedCodeTokenRequest{PreAuthorizedCode: plan.PreAuthorizedCode, TxCode: txCode, Resource: []string{s.offer.CredentialIssuer}}
	if s.auth == clientAuthAttestation {
		if s.client == nil {
			if err := s.newClient(ctx, plan.AuthorizationServer, false); err != nil {
				return err
			}
		}
		req.ClientAttestation = s.client
	} else if s.dpopKey == nil {
		if s.dpopKey, err = s.w.newDPoPKey(ctx); err != nil {
			return err
		}
	}
	req.DPoPKey = s.dpopKey
	token, err := s.w.core.RequestPreAuthorizedCodeToken(ctx, tokenEndpoint, req)
	var refused *wallet.Error
	if errors.As(err, &refused) && txCode != "" && refused.Endpoint == wallet.EndpointToken && refused.Code == "invalid_grant" {
		return fmt.Errorf("walletflow: token: %w: %w", ErrTxCodeRefused, err)
	}
	if err != nil {
		return fmt.Errorf("walletflow: token: %w", err)
	}
	if s.tokenType, err = s.w.tokenType(token.TokenType); err != nil {
		return err
	}
	s.resource = s.w.resourceClient(token.AccessToken, s.tokenType, s.dpopKey)
	s.accessToken = token.AccessToken
	s.identifiers = identifiersByConfiguration(token.AuthorizationDetails)
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

// checkTxCode checks the PIN against what the offer asked for
// (OpenID4VCI 1.0 §4.1.1, §6.1): one where it asked for one (an empty
// tx_code object asks too), of its length and input mode when it gives
// them, and none where it didn't, which the issuer would refuse.
func checkTxCode(want *oid4vci.TxCode, got string) error {
	switch {
	case want == nil && got != "":
		return errors.New("walletflow: the offer asks for no PIN")
	case want == nil:
		return nil
	case got == "":
		return errors.New("walletflow: the offer asks for a PIN")
	case want.Length > 0 && utf8.RuneCountInString(got) != want.Length:
		return fmt.Errorf("walletflow: the PIN must be %d characters", want.Length)
	case want.InputMode != "text" && strings.Trim(got, "0123456789") != "":
		// numeric, the default input mode.
		return errors.New("walletflow: the PIN must be digits")
	}
	return nil
}

// resourceClient presents accessToken, of tokenType, to the issuer's
// protected endpoints: DPoP-bound to dpopKey, or as a Bearer token.
func (w *Wallet) resourceClient(accessToken fapi.Secret, tokenType string, dpopKey Key) wallet.ProtectedResourceClient {
	if tokenType == wallet.TokenTypeBearer {
		return w.core.BearerResourceClient(accessToken)
	}
	return w.core.DPoPResourceClient(accessToken, dpopKey)
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
// Only a client that starts an authorization (authorize) needs the
// server's authorization and pushed authorization request endpoints:
// redeeming a pre-authorized code, refreshing and revoking need only
// its token endpoint.
func (s *Issuance) newClient(ctx context.Context, asURL string, authorize bool) error {
	if s.w.deps.Provider == nil || s.w.cfg.ClientID == "" {
		return fmt.Errorf("walletflow: a Wallet Attestation needs Dependencies.Provider and Config.ClientID: %w", ErrClientAuthUnsupported)
	}
	asMeta, err := s.w.core.FetchAuthorizationServerMetadata(ctx, asURL)
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	endpointsOf := asMeta.TokenClientEndpoints
	if authorize {
		endpointsOf = asMeta.ClientEndpoints
	}
	issuer, endpoints, err := endpointsOf()
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	if err := s.ensureClientKeys(ctx); err != nil {
		return err
	}
	walletAttestation, err := s.w.deps.Provider.WalletAttestation(ctx, s.w.cfg.ClientID, s.instanceKey.Public())
	if err != nil {
		return fmt.Errorf("walletflow: wallet attestation: %w", err)
	}
	attestation := client.StaticAttestation(walletAttestation)
	if asMeta.ChallengeEndpoint != "" {
		endpoint, err := fapi.ParseEndpointURL(asMeta.ChallengeEndpoint, s.w.urlOptions()...)
		if err != nil {
			return fmt.Errorf("walletflow: authorization server challenge_endpoint: %w", err)
		}
		attestation = challengedAttestation{AttestationSource: attestation, w: s.w.core, endpoint: endpoint}
	}
	c, err := s.oauthClient(issuer, endpoints, asURL, attestation)
	if err != nil {
		return err
	}
	s.client, s.authorizationServer = c, asURL
	return nil
}

// challengedAttestation is the Wallet Attestation for an Authorization
// Server with a challenge endpoint, where the client MUST put a fresh
// challenge in every Client Attestation PoP
// (draft-ietf-oauth-attestation-based-client-auth-07 §8). fapigo/client
// asks the attestation source itself for one (client.ChallengeSource),
// for every request it signs a PoP for.
type challengedAttestation struct {
	client.AttestationSource
	w        *wallet.Wallet
	endpoint fapi.URL
}

// CurrentChallenge implements client.ChallengeSource.
func (a challengedAttestation) CurrentChallenge(ctx context.Context) (string, error) {
	return a.w.RequestAttestationChallenge(ctx, a.endpoint)
}

// forgetAuthorization deletes the authorization in progress, if there
// is one.
// authorizationPending reports whether the authorization in progress is
// still recorded — not yet consumed by a redirect.
func (s *Issuance) authorizationPending(ctx context.Context) bool {
	if s.sessions == nil || s.sessions.state == "" {
		return false
	}
	_, err := s.w.deps.Authorizations.GetAuthorization(ctx, s.sessions.state)
	return err == nil
}

func (s *Issuance) forgetAuthorization(ctx context.Context) error {
	if s.sessions == nil || s.sessions.state == "" {
		return nil
	}
	return s.w.deps.Authorizations.DeleteAuthorization(ctx, s.sessions.state)
}

// ensureClientKeys creates the instance key a Wallet Attestation binds
// and the DPoP key, where the issuance doesn't have them yet.
func (s *Issuance) ensureClientKeys(ctx context.Context) error {
	var err error
	if s.instanceKey == nil {
		if s.instanceKey, err = newKey(ctx, s.w.deps.Keys, KeyPurposeInstance); err != nil {
			return err
		}
		s.w.holdKey(s.instanceKey.ID())
	}
	if s.dpopKey == nil {
		if s.dpopKey, err = s.w.newDPoPKey(ctx); err != nil {
			return err
		}
	}
	return nil
}

// oauthClient builds the fapigo/client for the authorization server
// issuer, authenticating with attestation and the issuance's keys.
func (s *Issuance) oauthClient(issuer fapi.URL, endpoints client.Endpoints, asURL string, attestation client.AttestationSource) (*client.Client, error) {
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
	km, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.ClientAttestationPoPSigning, Algorithm: fapi.ES256, Signer: s.instanceKey},
		{Purpose: keys.DPoPProofSigning, Algorithm: fapi.ES256, Signer: s.dpopKey},
	}, custody...)
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
			SessionLifetime: 5 * time.Minute, MaxClockSkew: 10 * time.Second, // fapigo/client's production minimum
			HTTPTimeout: httpTimeout, MaxHTTPResponseBytes: maxResponseBytes, MaxJOSECompactBytes: 16 * 1024,
		},
	}, client.Dependencies{
		// The authorization's state, kept so the redirect can complete it
		// after the app is suspended (ResumeIssuance).
		Sessions: s.sessions,
		Keys:     km, HTTP: s.w.deps.HTTP,
		Clock: clientClock{now: s.w.deps.Clock, system: s.w.systemClock}, Random: s.w.deps.Random,
		Attestation: attestation,
		// Reuses the DPoP nonce each response hands out, so only the
		// first request to an endpoint is challenged for one.
		DPoPNonceCache: client.NewInMemoryDPoPNonceCache(),
	})
	if err != nil {
		return nil, fmt.Errorf("walletflow: oauth client: %w", err)
	}
	return c, nil
}

// credentialIdentifiers is identifiersByConfiguration for a Token
// Response's raw authorization_details, as fapigo/client returns it.
func credentialIdentifiers(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var details []oid4vci.AuthorizationDetail
	if err := strictjson.Unmarshal(raw, &details); err != nil {
		return nil, fmt.Errorf("authorization_details: %w", err)
	}
	return identifiersByConfiguration(details), nil
}

// identifiersByConfiguration maps each configuration an
// "openid_credential" authorization detail names to the
// credential_identifiers it granted (OpenID4VCI 1.0 §6.2). Details of
// any other type are ignored, as are unrecognized fields (§6.2: the
// Wallet MUST ignore them).
func identifiersByConfiguration(details []oid4vci.AuthorizationDetail) map[string][]string {
	var ids map[string][]string
	total := 0
	for _, d := range details {
		if d.Type != oid4vci.AuthorizationDetailsTypeOpenIDCredential || len(d.CredentialIdentifiers) == 0 {
			continue
		}
		if ids == nil {
			ids = map[string][]string{}
		}
		for _, id := range d.CredentialIdentifiers {
			// Each is a Credential Request, with its own nonce, holder
			// keys and key attestation: an offer, which anyone can make,
			// mustn't make the wallet generate keys without bound.
			if id == "" || slices.Contains(ids[d.CredentialConfigurationID], id) ||
				len(ids[d.CredentialConfigurationID]) >= maxIdentifiersPerConfiguration || total >= maxIdentifiers {
				continue
			}
			ids[d.CredentialConfigurationID] = append(ids[d.CredentialConfigurationID], id)
			total++
		}
	}
	return ids
}

// maxIdentifiersPerConfiguration and maxIdentifiers bound the
// credential_identifiers an issuance requests: a household's datasets
// fit, a flood doesn't. The rest are not requested.
const (
	maxIdentifiersPerConfiguration = 16
	maxIdentifiers                 = 32
)

// MaxCredentialRequests is the most Credential Requests one issuance
// makes, each with its own nonce, holder keys and key attestation: an
// offer, which anyone can make, mustn't make the wallet generate keys
// without bound. An offer naming more credentials is refused, and so
// is an issuance whose token grants more credential_identifiers than
// fit, before requesting any.
const MaxCredentialRequests = 32

// maxConsecutiveRefusals is how many Credential Requests in a row an
// issuer may refuse for good before RequestCredentials stops asking:
// each costs holder keys and a key attestation.
const maxConsecutiveRefusals = 3

// clientClock is the wallet's clock as fapigo/client's, declaring
// whether it's the system's (client.ClockAssurance).
type clientClock struct {
	now    func() time.Time
	system bool
}

func (c clientClock) Now() time.Time { return c.now() }

func (c clientClock) ReadsSystemTime() bool { return c.system }

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
	units := s.requestUnits()
	if len(units) > MaxCredentialRequests {
		return s.obtained, fmt.Errorf("walletflow: the issuance would make %d Credential Requests, more than %d", len(units), MaxCredentialRequests)
	}
	refusals := 0
	for _, u := range units {
		if s.handled[u.key()] {
			continue
		}
		if refusals >= maxConsecutiveRefusals {
			s.handled[u.key()] = true
			s.obtained.Failed = append(s.obtained.Failed, FailedCredential{ConfigurationID: u.configID, CredentialIdentifier: u.identifier,
				Err: fmt.Errorf("walletflow: credential %q: not requested: the issuer refused %d requests in a row", u.configID, refusals)})
			continue
		}
		stored, deferred, err := s.request(ctx, u.configID, u.identifier, requestEnc, responseEnc)
		if err != nil && permanent(err) {
			refusals++
			s.handled[u.key()] = true
			s.obtained.Failed = append(s.obtained.Failed, FailedCredential{ConfigurationID: u.configID, CredentialIdentifier: u.identifier, Err: err})
			continue
		}
		if err == nil {
			refusals = 0
		}
		if err != nil {
			return s.obtained, err
		}
		s.handled[u.key()] = true
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

// requestUnit is one Credential Request: a configuration, by one of
// the credential_identifiers the token granted for it, or by its ID
// ("" identifier) where it granted none.
type requestUnit struct{ configID, identifier string }

func (u requestUnit) key() string { return u.configID + "\x00" + u.identifier }

// requestUnits are the offer's Credential Requests: one for each
// credential_identifier granted for a configuration, each a separate
// Credential Dataset (OpenID4VCI 1.0 §3.3, §6.2), else one by its ID.
func (s *Issuance) requestUnits() []requestUnit {
	var out []requestUnit
	for _, id := range distinct(s.offer.CredentialConfigurationIDs) {
		ids := s.identifiers[id]
		if len(ids) == 0 {
			out = append(out, requestUnit{configID: id})
			continue
		}
		for _, identifier := range ids {
			out = append(out, requestUnit{configID: id, identifier: identifier})
		}
	}
	return out
}

// distinct is ids without repeats, in order.
func distinct(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// permanent reports whether err, requesting one credential, won't go
// away by asking again: the credential failed the wallet's checks, or
// the issuer refused the request itself (an HTTP 4xx) rather than the
// nonce, the access token or the DPoP proof, which a retry renews.
func permanent(err error) bool {
	if errors.Is(err, errInvalidCredential) || errors.Is(err, errNoFreshNonce) {
		return true
	}
	var protocol *wallet.Error
	// A 401 is the access token's or DPoP proof's (RFC 6750 §3, RFC 9449
	// §7.1), which a retry renews, whatever error it names.
	if !errors.As(err, &protocol) || protocol.HTTPStatus < 400 || protocol.HTTPStatus >= 500 || protocol.HTTPStatus == 429 || protocol.HTTPStatus == 401 {
		return false
	}
	switch protocol.Code {
	case "invalid_nonce", "invalid_token", "invalid_dpop_proof", "use_dpop_nonce":
		return false
	}
	return true
}

func (s *Issuance) request(ctx context.Context, configID, identifier string, requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (StoredCredential, *Deferred, error) {
	plan, err := s.w.chooseProof(s.metadata.CredentialConfigurationsSupported[configID])
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: credential %q: %w", configID, err)
	}
	var holders []Key
	keep := false
	defer func() {
		if !keep {
			// Even when ctx is cancelled: a key left behind is an orphan.
			s.w.deleteKeys(context.WithoutCancel(ctx), holders)
		}
	}()
	var result wallet.CredentialResult
	if holders, result, err = s.sendCredentialRequest(ctx, configID, identifier, plan, requestEnc, responseEnc); err != nil {
		return StoredCredential{}, nil, err
	}
	if result.TransactionID != "" {
		d, err := s.deferred(ctx, configID, identifier, holders, result, requestEnc, responseEnc)
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
		configID: configID, identifier: identifier, holders: holders, result: result, grantID: grantID, replace: s.replace,
	})
	if err != nil {
		return StoredCredential{}, nil, err
	}
	s.storeGrant(ctx)
	keep = true
	s.w.deleteUnused(context.WithoutCancel(ctx), keyIDs(holders), stored)
	return stored, nil, nil
}

// sendCredentialRequest requests configID's credential with fresh
// holder keys, which it returns, proved by plan, even on failure, for
// the caller to delete. It retries once on invalid_nonce, with fresh keys
// and a fresh nonce (OpenID4VCI 1.0 §8.3.1.2): the issuer may expire a
// nonce before it's used. An issuer with no nonce endpoint has none to
// renew.
func (s *Issuance) sendCredentialRequest(ctx context.Context, configID, identifier string, plan proofPlan, requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) ([]Key, wallet.CredentialResult, error) {
	var holders []Key
	for attempt := 0; ; attempt++ {
		s.w.deleteKeys(context.WithoutCancel(ctx), holders)
		var (
			req wallet.CredentialRequest
			err error
		)
		if holders, req, err = s.proofs(ctx, plan); err != nil {
			return holders, wallet.CredentialResult{}, err
		}
		req.RequestEncryption, req.ResponseEncryption = requestEnc, responseEnc
		if identifier != "" {
			req.CredentialIdentifier = identifier
		} else {
			req.CredentialConfigurationID = configID
		}
		result, err := s.w.core.RequestCredential(ctx, s.resource, s.metadata.CredentialEndpoint, req)
		if err == nil {
			return holders, result, nil
		}
		if invalidNonce(err) && s.metadata.NonceEndpoint == nil {
			// No nonce to renew: asking again would be refused again.
			return holders, wallet.CredentialResult{}, fmt.Errorf("walletflow: credential %q: %w: %w", configID, errNoFreshNonce, err)
		}
		if attempt == 0 && s.nonceRetries < maxNonceRetries && invalidNonce(err) {
			s.nonceRetries++
			continue
		}
		return holders, wallet.CredentialResult{}, fmt.Errorf("walletflow: credential %q: %w", configID, err)
	}
}

// proofs creates one holder key per copy to request, and proves
// possession of them by plan, with a fresh c_nonce where the issuer has
// a nonce endpoint (OpenID4VCI 1.0 §7): one jwt proof each, or one key
// attestation for them all, alone or in one jwt proof. The issuer
// issues one copy bound to each.
func (s *Issuance) proofs(ctx context.Context, plan proofPlan) ([]Key, wallet.CredentialRequest, error) {
	var nonce string
	if s.metadata.NonceEndpoint != nil {
		n, err := s.w.core.RequestNonce(ctx, *s.metadata.NonceEndpoint)
		if err != nil {
			return nil, wallet.CredentialRequest{}, fmt.Errorf("walletflow: nonce: %w", err)
		}
		nonce = n.CNonce
		// §7.2: a DPoP nonce the Nonce Response carries is for the
		// Credential Request, which then needn't be challenged first.
		if user, ok := s.resource.(wallet.DPoPNonceUser); ok && n.DPoPNonce != "" {
			endpoint := s.metadata.CredentialEndpoint.URL()
			user.UseDPoPNonce(ctx, &endpoint, n.DPoPNonce)
		}
	}
	switch plan {
	case proofAttestation:
		holders, attestation, err := s.attestedHolders(ctx, nonce)
		return holders, wallet.CredentialRequest{Attestation: attestation}, err
	case proofJWTKeyAttestation:
		return s.jwtProofsWithKeyAttestation(ctx, nonce)
	}
	holders := make([]Key, 0, s.batchSize())
	req := wallet.CredentialRequest{CredentialIssuer: s.offer.CredentialIssuer, Nonce: nonce}
	for range s.batchSize() {
		holder, err := newKey(ctx, s.w.deps.Keys, KeyPurposeHolder)
		if err != nil {
			s.w.deleteKeys(context.WithoutCancel(ctx), holders)
			return nil, wallet.CredentialRequest{}, err
		}
		holders = append(holders, holder)
		req.Keys = append(req.Keys, holder)
	}
	return holders, req, nil
}

// errNoFreshNonce is wrapped for an invalid_nonce from an issuer with no
// nonce endpoint, or for a proof with no nonce: there's none to renew.
var errNoFreshNonce = errors.New("the issuer has no fresh nonce to give")

// maxNonceRetries caps an issuance's invalid_nonce retries.
const maxNonceRetries = 2

// invalidNonce reports whether err is the issuer refusing a proof's
// c_nonce (OpenID4VCI 1.0 §8.3.1.2).
func invalidNonce(err error) bool {
	var protocol *wallet.Error
	return errors.As(err, &protocol) && protocol.Code == "invalid_nonce"
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

// jwtProofsWithKeyAttestation creates one holder key per copy to
// request, has the Wallet Provider attest them together for nonce, and
// sends one jwt proof, signed by the first, carrying that attestation in
// its key_attestation header (Appendix D.1, F.1). The issuer "SHOULD
// issue a Credential for each cryptographic public key specified in the
// attested_keys claim" (F.1), so one proof covers the batch: a holder
// key that asks for user presence to sign asks once, not once per copy.
// An issuer issuing fewer copies leaves keys unused, which receiving
// deletes. A key created before a failure is deleted.
func (s *Issuance) jwtProofsWithKeyAttestation(ctx context.Context, nonce string) ([]Key, wallet.CredentialRequest, error) {
	holders, keyAttestation, err := s.attestedHolders(ctx, nonce)
	if err != nil {
		return nil, wallet.CredentialRequest{}, err
	}
	proof, err := s.w.core.GenerateProofWithKeyAttestation(holders[0], s.offer.CredentialIssuer, nonce, keyAttestation)
	if err != nil {
		s.w.deleteKeys(context.WithoutCancel(ctx), holders)
		return nil, wallet.CredentialRequest{}, fmt.Errorf("walletflow: proof: %w", err)
	}
	return holders, wallet.CredentialRequest{CredentialIssuer: s.offer.CredentialIssuer, Nonce: nonce, JWTProofs: []string{proof}}, nil
}

// deferred keeps a credential the issuer deferred, requested by
// identifier ("" for none), with holders, to poll.
func (s *Issuance) deferred(ctx context.Context, configID, identifier string, holders []Key, result wallet.CredentialResult,
	requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (*Deferred, error) {
	if s.metadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("walletflow: credential %q was deferred, but the issuer advertises no deferred credential endpoint", configID)
	}
	id, err := randomID(s.w.deps.Random)
	if err != nil {
		return nil, err
	}
	// The refresh grant the credential will use, kept from now: the
	// deferred credential names it.
	grantID, err := s.grantFor()
	if err != nil {
		return nil, err
	}
	p := PendingDeferred{
		ID: id, CredentialIssuer: s.offer.CredentialIssuer, ConfigurationID: configID, CredentialIdentifier: identifier,
		TransactionID: result.TransactionID, AccessToken: s.accessToken, AccessTokenExpiresAt: s.accessExpiresAt,
		HolderKeyIDs: keyIDs(holders), Interval: result.Interval, DeferredAt: s.w.deps.Clock().UTC(),
		GrantID: grantID, Replaces: s.replace,
	}
	if s.tokenType == wallet.TokenTypeBearer {
		p.TokenType = wallet.TokenTypeBearer
	} else {
		p.DPoPKeyID = s.dpopKey.ID()
	}
	d, err := s.w.keepDeferred(ctx, p, s.metadata, s.resource, requestEnc, responseEnc)
	if err != nil {
		return nil, err
	}
	s.storeGrant(ctx)
	return d, nil
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
// metadata, polled with resource, for configID by identifier ("" for
// none), its copies bound to holders.
type issued struct {
	issuer     string
	metadata   oid4vci.Metadata
	resource   wallet.ProtectedResourceClient
	configID   string
	identifier string
	holders    []Key
	result     wallet.CredentialResult
	// grantID is the RefreshGrant that can refresh it, if any; replace,
	// the stored credential it replaces, if any.
	grantID, replace string
}

// accept checks every copy c's result carries, each bound to one of
// c.holders, stores them as one credential, and tells the issuer whether
// the wallet kept it (§11).
func (w *Wallet) accept(ctx context.Context, c issued) (StoredCredential, error) {
	conf := c.metadata.CredentialConfigurationsSupported[c.configID]
	if err := checkBindable(conf); err != nil {
		// The issuer's metadata changed since the request: a deferred
		// credential's, re-fetched after a restart.
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: %w", c.configID, err)
	}
	if n := len(c.result.Credentials); n == 0 || n > len(c.holders) {
		return StoredCredential{}, fmt.Errorf("walletflow: credential %q: got %d copies for %d keys", c.configID, n, len(c.holders))
	}
	now := w.deps.Clock()
	unbound := slices.Clone(c.holders)
	copies := make([]CredentialCopy, 0, len(c.result.Credentials))
	claims := make([]map[string]any, 0, len(c.result.Credentials))
	var first wallet.VerifiedIssuedCredential
	for i, ic := range c.result.Credentials {
		verified, key, err := w.verifyCopy(ctx, c.issuer, conf, ic.Credential, unbound, now)
		if err != nil {
			w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the credential failed the wallet's checks")
			return StoredCredential{}, fmt.Errorf("walletflow: credential %q %w: %w", c.configID, errInvalidCredential, err)
		}
		keyID := key.ID()
		unbound = slices.DeleteFunc(unbound, func(k Key) bool { return k.ID() == keyID })
		copies = append(copies, CredentialCopy{Credential: ic.Credential, HolderKeyID: keyID, StatusList: verified.StatusList, ValidUntil: verified.ValidUntil})
		claims = append(claims, verified.Claims)
		if i == 0 {
			first = verified
		} else if (verified.StatusList == nil) != (first.StatusList == nil) {
			// A copy without a status the others have couldn't be
			// revoked with them.
			w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the credential's copies differ")
			return StoredCredential{}, fmt.Errorf("walletflow: credential %q %w: copy %d's status differs from copy 0's", c.configID, errInvalidCredential, i)
		} else if !sameHolderClaims(first.Claims, verified.Claims) || !samePlaintext(c.result.Credentials[0].Credential, ic.Credential) {
			// The holder sees copy 0's claims, and DCQL chooses per copy:
			// copies that differ would present what the holder didn't see.
			w.notify(ctx, c, oid4vci.NotificationEventCredentialFailure, "the credential's copies differ")
			return StoredCredential{}, fmt.Errorf("walletflow: credential %q %w: copy %d's claims differ from copy 0's", c.configID, errInvalidCredential, i)
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
		ID: id, CredentialIssuer: c.issuer, ConfigurationID: c.configID, CredentialIdentifier: c.identifier,
		Format: conf.Format, VCT: conf.VCT, DocType: conf.DocType,
		Credential: copies[0].Credential, HolderKeyID: copies[0].HolderKeyID, Copies: copies,
		ReceivedAt: now.UTC(), Claims: first.Claims,
		Display: displayFor(c.metadata, c.configID, w.cfg.Locales), ValidUntil: earliestExpiry(copies),
		StatusList: first.StatusList, StatusListCWT: first.StatusListCWT, GrantID: c.grantID,
		CopiesCorrelated: copiesCorrelated(conf.Format, copies, claims),
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
	return w.replaceStored(ctx, stored, c.grantID)
}

// verifyCopy checks one copy, requested from issuer, and finds which of
// keys it's bound to.
func (w *Wallet) verifyCopy(ctx context.Context, issuer string, conf oid4vci.CredentialConfigurationMetadata, credential string, keys []Key, now time.Time) (wallet.VerifiedIssuedCredential, Key, error) {
	if w.cfg.AllowForeignIss {
		issuer = ""
	}
	roots, policy := w.cfg.issuerTrust(conf.Format, conf.DocType)
	var lastErr error
	for _, k := range keys {
		verified, err := wallet.VerifyIssuedCredential(ctx, wallet.VerifyIssuedCredentialParams{
			Configuration: conf, Credential: credential, HolderKey: k.Public(),
			IssuerRoots: roots, IssuerLeafPolicy: policy, IssuerRevocation: w.cfg.IssuerRevocation, Now: now, RequireIssuerName: w.cfg.RequireIssuerName,
			CredentialIssuer: issuer,
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
	// uses: every refresh authenticates with it. A grant nothing uses
	// once the issuance is done is released, revoking its token.
	if s.instanceKey != nil && !s.grantStored {
		// Unless another open issuance holds it: a resume of this one.
		s.w.unholdKey(s.instanceKey.ID())
		if !s.w.keyHeld(s.instanceKey.ID()) {
			errs = append(errs, s.w.deps.Keys.DeleteKey(ctx, s.instanceKey.ID()))
		}
	} else if s.instanceKey != nil {
		s.w.unholdKey(s.instanceKey.ID())
	}
	if s.grantID != "" && s.replace == "" {
		s.w.holdGrant(s.grantID, false)
		if s.grantStored && len(s.offer.CredentialConfigurationIDs) > 0 {
			errs = append(errs, s.w.releaseUnusedGrant(ctx, s.grantID, s.offer.CredentialConfigurationIDs[0]))
		}
	}
	if s.dpopKey != nil {
		s.w.unholdKey(s.dpopKey.ID())
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

// perCopyClaims are an SD-JWT VC's claims that may differ between copies
// of one batch: when and how long each is valid, its holder key, its
// status list entry, its ID and a pseudonymous subject.
var perCopyClaims = []string{"iat", "nbf", "exp", "cnf", "status", "jti", "sub"}

// correlatingClaims are an SD-JWT VC's per-copy claims (perCopyClaims)
// that, the same in two copies, identify the credential rather than the
// copy: a Verifier shown either recognises the other.
var correlatingClaims = []string{"jti", "sub"}

// copiesCorrelated reports whether two of a batch's copies, in format,
// with claims each, share what should set them apart — an SD-JWT VC's
// jti or sub (correlatingClaims), a status list entry (an mdoc's too),
// a disclosure digest or a validity timestamp not rounded to the day
// (copyMarks) — so presenting different copies doesn't keep
// presentations unlinkable. The copies are kept all the same: they're
// still valid.
func copiesCorrelated(format string, copies []CredentialCopy, claims []map[string]any) bool {
	for i := range copies {
		for j := range i {
			if pairCorrelated(format, copies[i], copies[j], claims[i], claims[j]) {
				return true
			}
		}
	}
	if len(copies) < 2 {
		return false
	}
	marks := make([]copyMarks, len(copies))
	for i, cp := range copies {
		marks[i] = marksOf(format, cp.Credential)
	}
	return marksShared(marks)
}

// pairCorrelated reports whether copies a and b, with claims ca and cb,
// share what copiesCorrelated looks for.
func pairCorrelated(format string, a, b CredentialCopy, ca, cb map[string]any) bool {
	if a.StatusList != nil && b.StatusList != nil && *a.StatusList == *b.StatusList {
		return true
	}
	if format != sdjwtvc.CredentialFormat {
		return false
	}
	for _, name := range correlatingClaims {
		va, okA := ca[name]
		vb, okB := cb[name]
		if okA && okB && reflect.DeepEqual(va, vb) {
			return true
		}
	}
	return false
}

// sameHolderClaims reports whether two copies of a credential carry the
// same claims, those that may differ per copy aside.
func sameHolderClaims(a, b map[string]any) bool {
	strip := func(m map[string]any) map[string]any {
		out := maps.Clone(m)
		for _, name := range perCopyClaims {
			delete(out, name)
		}
		return out
	}
	return reflect.DeepEqual(strip(a), strip(b))
}

// earliestExpiry is when the first of copies expires, zero when none
// says.
func earliestExpiry(copies []CredentialCopy) time.Time {
	var earliest time.Time
	for _, cp := range copies {
		if !cp.ValidUntil.IsZero() && (earliest.IsZero() || cp.ValidUntil.Before(earliest)) {
			earliest = cp.ValidUntil
		}
	}
	return earliest
}

// samePlaintext reports whether two copies of an SD-JWT VC leave the
// same claims plaintext, those that may differ per copy aside: the
// preview the holder is shown is built from one copy, so another that
// always discloses a claim the first made selectively disclosable
// would send what the holder didn't see. Decoys may differ, so they
// aren't compared; another format has no plaintext to compare.
func samePlaintext(a, b string) bool {
	pa, okA := plaintextPaths(a)
	pb, okB := plaintextPaths(b)
	return okA == okB && slices.Equal(pa, pb)
}

// plaintextPaths are credential's plaintext claim paths, sorted, as
// "/"-joined keys ("[]" for an array element), for an SD-JWT VC; false
// for anything else.
func plaintextPaths(credential string) ([]string, bool) {
	pres, err := sdjwtvc.Parse(credential)
	if err != nil {
		return nil, false
	}
	_, raw, err := jose.DecodeUnverified(pres.IssuerJWT)
	if err != nil {
		return nil, false
	}
	var payload map[string]any
	if json.Unmarshal(raw, &payload) != nil {
		return nil, false
	}
	for _, name := range perCopyClaims {
		delete(payload, name)
	}
	out := appendPlaintextPaths(nil, "", payload)
	slices.Sort(out)
	return slices.Compact(out), true
}

// appendPlaintextPaths appends to out the plaintext claim paths of v,
// found at prefix, as plaintextPaths names them.
func appendPlaintextPaths(out []string, prefix string, v any) []string {
	switch v := v.(type) {
	case map[string]any:
		if _, digest := v["..."]; digest && len(v) == 1 {
			return out // a selectively disclosable array element
		}
		for k, child := range v {
			if k == "_sd" || k == "_sd_alg" {
				continue
			}
			out = append(out, prefix+"/"+k)
			out = appendPlaintextPaths(out, prefix+"/"+k, child)
		}
	case []any:
		for _, child := range v {
			out = appendPlaintextPaths(out, prefix+"/[]", child)
		}
	}
	return out
}

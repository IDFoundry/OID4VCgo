package walletflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/client"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// RefreshGrant is what an issuance keeps to refresh its credentials
// later without the holder (OpenID4VCI 1.0 §14.5): the refresh token the
// Authorization Server issued, and how the wallet authenticated when it
// did, which every refresh must do again. With a Wallet Attestation
// that's the wallet instance key the attestation was bound to
// (draft-ietf-oauth-attestation-based-client-auth-07 §10.3); with no
// client authentication, a public client's refresh token is bound to
// the DPoP key instead (RFC 9449 §5). It's a secret, like a credential.
type RefreshGrant struct {
	ID string
	// CredentialIssuer and AuthorizationServer are where the credentials
	// came from, and where the refresh token is redeemed.
	CredentialIssuer    string
	AuthorizationServer string
	// ConfigurationID is a credential configuration the grant was for:
	// what revoking it checks the issuer still names its Authorization
	// Server for, once no credential does. Empty for a grant stored
	// before it was kept, which is then forgotten without revoking.
	ConfigurationID string
	RefreshToken    fapi.Secret
	// InstanceKeyID names the wallet instance key, kept in the KeyStore
	// while the grant is: a ClientAuth "attestation" grant's.
	InstanceKeyID string
	CreatedAt     time.Time
	// ClientAuth is how the refresh authenticates: GrantAuthAttestation,
	// the empty value, with a Wallet Attestation bound to InstanceKeyID;
	// GrantAuthNone with none. Empty for a grant stored before it was
	// kept: those all authenticated with a Wallet Attestation.
	ClientAuth GrantAuth
	// DPoPKeyID names the DPoP key a GrantAuthNone grant's refresh token
	// may be bound to — the key of the token request that obtained it,
	// whatever the access tokens' TokenType — kept in the KeyStore while
	// the grant is.
	DPoPKeyID string
	// TokenType is the access tokens' type: "" for DPoP (and every grant
	// stored before it was kept), or "Bearer" (wallet.TokenTypeBearer).
	TokenType string
}

// GrantAuth is how a refresh grant's refreshes authenticate.
type GrantAuth string

const (
	// GrantAuthAttestation authenticates with a Wallet Attestation bound
	// to RefreshGrant.InstanceKeyID. It's the empty value.
	GrantAuthAttestation GrantAuth = ""
	// GrantAuthNone authenticates no client: the refresh token is held
	// to RefreshGrant.DPoPKeyID instead.
	GrantAuthNone GrantAuth = "none"
)

// keyIDs are the keys g keeps in the KeyStore.
func (g RefreshGrant) keyIDs() []string {
	if g.ClientAuth == GrantAuthNone {
		return []string{g.DPoPKeyID}
	}
	return []string{g.InstanceKeyID}
}

// GrantStore keeps refresh grants.
type GrantStore interface {
	// PutGrant stores g, replacing any with its ID.
	PutGrant(ctx context.Context, g RefreshGrant) error
	// GetGrant returns the one id names, or an error wrapping
	// ErrNotFound.
	GetGrant(ctx context.Context, id string) (RefreshGrant, error)
	// ListGrants returns every one.
	ListGrants(ctx context.Context) ([]RefreshGrant, error)
	// DeleteGrant deletes the one id names; deleting one that doesn't
	// exist isn't an error.
	DeleteGrant(ctx context.Context, id string) error
	// Durable reports whether what's stored survives a restart.
	Durable() bool
}

// MemoryGrantStore is a GrantStore in memory, for development and
// tests: not Durable.
type MemoryGrantStore struct {
	mu     sync.Mutex
	grants map[string]RefreshGrant
}

// NewMemoryGrantStore returns an empty MemoryGrantStore.
func NewMemoryGrantStore() *MemoryGrantStore {
	return &MemoryGrantStore{grants: map[string]RefreshGrant{}}
}

// PutGrant implements GrantStore.
func (s *MemoryGrantStore) PutGrant(_ context.Context, g RefreshGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.grants[g.ID] = g
	return nil
}

// GetGrant implements GrantStore.
func (s *MemoryGrantStore) GetGrant(_ context.Context, id string) (RefreshGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[id]
	if !ok {
		return RefreshGrant{}, fmt.Errorf("walletflow: refresh grant %q: %w", id, ErrNotFound)
	}
	return g, nil
}

// ListGrants implements GrantStore.
func (s *MemoryGrantStore) ListGrants(context.Context) ([]RefreshGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RefreshGrant, 0, len(s.grants))
	for _, g := range s.grants {
		out = append(out, g)
	}
	return out, nil
}

// DeleteGrant implements GrantStore.
func (s *MemoryGrantStore) DeleteGrant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.grants, id)
	return nil
}

// Durable implements GrantStore.
func (s *MemoryGrantStore) Durable() bool { return false }

// offlineAccess is the scope that asks the Authorization Server for a
// refresh token.
const offlineAccess = "offline_access"

// grantFor returns the ID of the issuance's refresh grant, choosing it
// the first time: "" when the issuance has no refresh token. The grant
// itself is stored once a credential naming it is (storeGrant).
func (s *Issuance) grantFor() (string, error) {
	if s.grantID != "" || s.refreshToken.Reveal() == "" {
		return s.grantID, nil
	}
	id, err := randomID(s.w.deps.Random)
	if err != nil {
		return "", err
	}
	s.grantID = id
	// In use while the issuance is open, whatever happens to the
	// credentials it has stored so far.
	s.w.holdGrant(id, true)
	return id, nil
}

// storeGrant stores the issuance's refresh grant once a credential
// naming it is stored, and keeps the instance key with it. It's best
// effort: without it, the credential can't be refreshed
// (ErrReissueRequired).
func (s *Issuance) storeGrant(ctx context.Context) {
	if s.grantID == "" || s.grantStored {
		return
	}
	g := RefreshGrant{
		ID: s.grantID, CredentialIssuer: s.offer.CredentialIssuer, AuthorizationServer: s.authorizationServer,
		ConfigurationID: s.offer.CredentialConfigurationIDs[0],
		RefreshToken:    s.refreshToken, CreatedAt: s.w.deps.Clock().UTC(),
	}
	if s.tokenType == wallet.TokenTypeBearer {
		g.TokenType = wallet.TokenTypeBearer
	}
	if s.auth == clientAuthAttestation {
		g.InstanceKeyID = s.instanceKey.ID()
	} else {
		// Kept even with a Bearer access token: the token request sent a
		// DPoP proof, and the server may have bound the refresh token to
		// its key all the same (RFC 9449 §5).
		g.ClientAuth, g.DPoPKeyID = GrantAuthNone, s.dpopKey.ID()
	}
	if err := s.w.deps.Grants.PutGrant(ctx, g); err == nil {
		s.grantStored = true
	}
}

// lockGrant serializes refreshes with grant id, and returns the unlock.
func (w *Wallet) lockGrant(id string) func() {
	w.grantMu.Lock()
	m, ok := w.grantLocks[id]
	if !ok {
		m = &sync.Mutex{}
		w.grantLocks[id] = m
	}
	w.grantMu.Unlock()
	m.Lock()
	return m.Unlock
}

// RefreshCredential replaces the copies of the credential id names with
// a fresh batch, without the holder (OpenID4VCI 1.0 §13.5): it redeems
// the refresh token its issuance kept (Config.RequestRefresh), with the
// same wallet instance key, and requests the credential again, each
// copy bound to a new holder key the Wallet Provider attests. The
// credential keeps its ID; the old copies, and their holder keys, are
// gone. Use it when CopiesLeft runs low, so each presentation can still
// use a copy no Verifier has seen.
//
// It returns an error wrapping ErrReissueRequired when the credential
// can't be refreshed: it came without a refresh token, or the
// Authorization Server no longer accepts it (invalid_grant). Receive it
// again from a new Credential Offer then.
//
// If the issuer defers the new credential, the old one stays as it is
// and the Deferred is returned to poll: once settled, its credential
// replaces the old one, as a refresh does, keeping the grant — unless
// the old one was deleted meanwhile, when it isn't kept.
func (w *Wallet) RefreshCredential(ctx context.Context, id string) (StoredCredential, *Deferred, error) {
	if err := w.checkIssuance(); err != nil {
		return StoredCredential{}, nil, err
	}
	old, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	if old.GrantID == "" {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: it came without a refresh token: %w", ErrReissueRequired)
	}
	// One refresh with a grant at a time: an Authorization Server that
	// rotates refresh tokens refuses the old one once the new is issued.
	defer w.lockGrant(old.GrantID)()
	g, grantKey, err := w.loadGrant(ctx, old)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	metadata, err := w.planGrant(ctx, g, old.ConfigurationID)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	// The issuer may have changed since the credential was received: a
	// HAIP wallet refreshes only from an issuer that still follows HAIP.
	if err := w.checkProfile(metadata, []string{old.ConfigurationID}); err != nil {
		return StoredCredential{}, nil, err
	}
	// Nor one that no longer binds it to a key the wallet can hold.
	conf, ok := metadata.CredentialConfigurationsSupported[old.ConfigurationID]
	if !ok {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: the issuer no longer offers it: %w", ErrReissueRequired)
	}
	if err := checkBindable(conf); err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: %w: %w", ErrReissueRequired, err)
	}
	s := &Issuance{
		w: w, metadata: metadata, grantID: g.ID, grantStored: true, replace: old.ID, grant: GrantAuthorizationCode,
		authorizationServer: g.AuthorizationServer,
		offer:               oid4vci.CredentialOffer{CredentialIssuer: old.CredentialIssuer, CredentialConfigurationIDs: []string{old.ConfigurationID}},
	}
	if g.ClientAuth == GrantAuthNone {
		s.auth, s.dpopKey = clientAuthNone, grantKey
	} else {
		s.auth, s.instanceKey = clientAuthAttestation, grantKey
	}
	defer s.endRefresh(context.WithoutCancel(ctx))
	if err := s.redeemGrant(ctx, g); err != nil {
		return StoredCredential{}, nil, err
	}
	requestEnc, responseEnc, err := wallet.EncryptionFromMetadata(metadata)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: %w", err)
	}
	stored, deferred, err := s.request(ctx, old.ConfigurationID, requestEnc, responseEnc)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	if deferred != nil {
		return old, deferred, nil
	}
	return stored, nil, nil
}

// loadGrant is the refresh grant of credential c, with the key its
// refreshes need — its instance key, or for a GrantAuthNone grant its
// DPoP key, nil for a Bearer one: ErrReissueRequired when either is
// gone, or the grant is another issuer's, and ErrProfileViolation for
// one ProfileHAIP doesn't allow. Called with the grant's lock held.
func (w *Wallet) loadGrant(ctx context.Context, c StoredCredential) (RefreshGrant, Key, error) {
	g, err := w.deps.Grants.GetGrant(ctx, c.GrantID)
	if errors.Is(err, ErrNotFound) {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: its refresh grant is gone: %w", ErrReissueRequired)
	}
	if err != nil {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	if g.CredentialIssuer != c.CredentialIssuer {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: its refresh grant is another issuer's: %w", ErrReissueRequired)
	}
	if w.cfg.IssuanceProfile == ProfileHAIP && (g.ClientAuth == GrantAuthNone || g.TokenType == wallet.TokenTypeBearer) {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: %w: its grant authenticates no client, or isn't DPoP-bound", ErrProfileViolation)
	}
	keyID := g.keyIDs()[0]
	if keyID == "" {
		return g, nil, nil
	}
	key, err := w.deps.Keys.Key(ctx, keyID)
	if errors.Is(err, ErrNotFound) {
		w.forgetGrant(context.WithoutCancel(ctx), g)
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: its key is gone: %w", ErrReissueRequired)
	}
	if err != nil {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	return g, key, nil
}

// planGrant fetches g's issuer's metadata, and checks the issuer still
// lists g's Authorization Server, as at issuance, for configuration
// configID: the refresh token goes nowhere else. A server no longer
// listed is ErrReissueRequired.
func (w *Wallet) planGrant(ctx context.Context, g RefreshGrant, configID string) (oid4vci.Metadata, error) {
	metadata, err := w.core.FetchCredentialIssuerMetadata(ctx, g.CredentialIssuer)
	if err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("walletflow: issuer metadata: %w", err)
	}
	offer := oid4vci.CredentialOffer{
		CredentialIssuer: g.CredentialIssuer, CredentialConfigurationIDs: []string{configID},
		Grants: &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{AuthorizationServer: g.AuthorizationServer}},
	}
	if _, err := wallet.PlanAuthorization(offer, metadata); err != nil {
		return oid4vci.Metadata{}, fmt.Errorf("walletflow: refresh credential: the issuer no longer names its authorization server: %w: %w", ErrReissueRequired, err)
	}
	return metadata, nil
}

// redeemGrant redeems g's refresh token for an access token, keeping a
// rotated refresh token: with a Wallet Attestation through
// fapigo/client, or for a GrantAuthNone grant as a public client. The
// grant is refused, ErrReissueRequired, where its Authorization Server
// no longer takes how it authenticates, or the wallet can no longer
// give a Wallet Attestation; and where the server refuses the refresh
// token, when it's forgotten too.
func (s *Issuance) redeemGrant(ctx context.Context, g RefreshGrant) error {
	asMeta, err := s.w.core.FetchAuthorizationServerMetadata(ctx, g.AuthorizationServer)
	if err != nil {
		return fmt.Errorf("walletflow: authorization server metadata: %w", err)
	}
	if g.ClientAuth != GrantAuthNone && !takesAttestation(asMeta) {
		// Never a silent switch to no client authentication.
		return fmt.Errorf("walletflow: refresh credential: the authorization server no longer takes a Wallet Attestation: %w", ErrReissueRequired)
	}
	s.asMeta = asMeta
	var res refreshResult
	if g.ClientAuth == GrantAuthNone {
		res, err = s.refreshAsPublicClient(ctx, g, asMeta)
	} else {
		res, err = s.refreshWithAttestation(ctx, g)
	}
	if err != nil {
		return err
	}
	tokenType, accessToken, details := res.tokenType, res.accessToken, res.details
	expiresIn, hasExpiry := res.expiresIn, res.hasExpiresIn
	if err := s.keepRotatedRefreshToken(ctx, g, res); err != nil {
		return err
	}
	if s.tokenType, err = s.w.tokenType(tokenType); err != nil {
		return err
	}
	if g.ClientAuth == GrantAuthNone && s.tokenType == wallet.TokenTypeDPoP && s.dpopKey == nil {
		// A Bearer grant's refresh sent no DPoP proof to bind it to.
		return fmt.Errorf("walletflow: refresh credential: a DPoP access token for a refresh with no DPoP key: %w", ErrReissueRequired)
	}
	if g.ClientAuth == GrantAuthNone {
		s.resource = s.w.resourceClient(accessToken, s.tokenType, s.dpopKey)
	}
	s.accessToken = accessToken
	if s.identifiers, err = credentialIdentifiers(details); err != nil {
		return fmt.Errorf("walletflow: token response: %w", err)
	}
	if hasExpiry {
		s.accessExpiresAt = s.w.deps.Clock().Add(expiresIn)
	}
	return nil
}

// keepRotatedRefreshToken stores the refresh token res rotated g's to,
// if it did.
func (s *Issuance) keepRotatedRefreshToken(ctx context.Context, g RefreshGrant, res refreshResult) error {
	if !res.hasRefreshToken || res.refreshToken.Reveal() == g.RefreshToken.Reveal() {
		return nil
	}
	g.RefreshToken = res.refreshToken
	if err := s.w.deps.Grants.PutGrant(ctx, g); err != nil {
		return fmt.Errorf("walletflow: store refresh grant: %w", err)
	}
	return nil
}

// refreshResult is what a refresh's token response gave.
type refreshResult struct {
	refreshToken    fapi.Secret
	hasRefreshToken bool
	tokenType       string
	accessToken     fapi.Secret
	details         json.RawMessage
	expiresIn       time.Duration
	hasExpiresIn    bool
}

// refreshAsPublicClient redeems a GrantAuthNone grant's refresh token
// at asMeta's token endpoint, with a DPoP proof when the issuance has a
// DPoP key.
func (s *Issuance) refreshAsPublicClient(ctx context.Context, g RefreshGrant, asMeta wallet.AuthorizationServerMetadata) (refreshResult, error) {
	tokenEndpoint, err := fapi.ParseEndpointURL(asMeta.TokenEndpoint, s.w.urlOptions()...)
	if err != nil {
		return refreshResult{}, fmt.Errorf("walletflow: token endpoint: %w", err)
	}
	req := wallet.RefreshTokenRequest{RefreshToken: g.RefreshToken}
	if s.dpopKey != nil {
		// A grant stored before DPoPKeyID was kept for Bearer grants
		// has no key: a nil Key in the interface would send a proof.
		req.DPoPKey = s.dpopKey
	}
	res, err := s.w.core.RequestRefreshToken(ctx, tokenEndpoint, req)
	if err != nil {
		return refreshResult{}, s.refreshFailed(ctx, g, err)
	}
	details, err := json.Marshal(res.AuthorizationDetails)
	if err != nil {
		return refreshResult{}, fmt.Errorf("walletflow: token response: %w", err)
	}
	return refreshResult{
		refreshToken: res.RefreshToken, hasRefreshToken: res.RefreshToken.Reveal() != "",
		tokenType: res.TokenType, accessToken: res.AccessToken, details: details,
		expiresIn: res.ExpiresIn, hasExpiresIn: res.HasExpiresIn,
	}, nil
}

// refreshWithAttestation redeems g's refresh token through fapigo/client,
// authenticating with a Wallet Attestation, and keeps the protected
// resource client for the new tokens.
func (s *Issuance) refreshWithAttestation(ctx context.Context, g RefreshGrant) (refreshResult, error) {
	if err := s.newClient(ctx, g.AuthorizationServer, false); err != nil {
		if errors.Is(err, ErrClientAuthUnsupported) {
			// A wallet without its Wallet Provider now.
			return refreshResult{}, fmt.Errorf("walletflow: refresh credential: %w: %w", ErrReissueRequired, err)
		}
		return refreshResult{}, err
	}
	// The grant's own authorization server, so fapigo/client refuses to
	// send its refresh token to any other.
	tokens, err := s.client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: client.TokenSet{
		RefreshToken: g.RefreshToken, HasRefreshToken: true, Issuer: g.AuthorizationServer,
	}})
	if err != nil {
		return refreshResult{}, s.refreshFailed(ctx, g, err)
	}
	s.resource = s.client.ProtectedResource(tokens)
	return refreshResult{
		refreshToken: tokens.RefreshToken, hasRefreshToken: tokens.HasRefreshToken,
		tokenType: tokens.TokenType, accessToken: tokens.AccessToken, details: tokens.AuthorizationDetails,
		expiresIn: tokens.ExpiresIn, hasExpiresIn: tokens.HasExpiresIn,
	}, nil
}

// refreshFailed is a refresh's failure: ErrReissueRequired, with the
// grant forgotten, where the Authorization Server refused the refresh
// token itself.
func (s *Issuance) refreshFailed(ctx context.Context, g RefreshGrant, err error) error {
	if invalidGrant(err) {
		s.w.forgetRefusedGrant(context.WithoutCancel(ctx), g)
		return fmt.Errorf("walletflow: refresh credential: %w: %w", ErrReissueRequired, err)
	}
	return fmt.Errorf("walletflow: refresh token: %w", err)
}

// replaceStored stores stored in place of the credential it replaces,
// if that still exists and still uses grantID — it may have been
// deleted while it was refreshed — and deletes the replaced copies'
// holder keys. It's called with credMu held.
func (w *Wallet) replaceStored(ctx context.Context, stored StoredCredential, grantID string) error {
	cur, err := w.deps.Credentials.Get(ctx, stored.ID)
	if err != nil || cur.GrantID != grantID {
		return fmt.Errorf("walletflow: credential %q is gone: %w", stored.ID, ErrNotFound)
	}
	if err := w.deps.Credentials.Put(ctx, stored); err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, cp := range stored.AllCopies() {
		kept[cp.HolderKeyID] = true
	}
	for _, cp := range cur.AllCopies() {
		if !kept[cp.HolderKeyID] {
			_ = w.deps.Keys.DeleteKey(context.WithoutCancel(ctx), cp.HolderKeyID)
		}
	}
	return nil
}

// endRefresh releases a refresh's DPoP key, and never its instance key,
// which the grant keeps.
func (s *Issuance) endRefresh(ctx context.Context) {
	if s.dpopKey == nil {
		return
	}
	s.w.mu.Lock()
	delete(s.w.liveDPoP, s.dpopKey.ID())
	s.w.mu.Unlock()
	_ = s.w.releaseDPoPKey(ctx, s.dpopKey.ID())
}

// invalidGrant reports whether err is the Authorization Server refusing
// the refresh token itself: expired, revoked or unknown.
func invalidGrant(err error) bool {
	// A public client's refresh fails with a *wallet.Error, fapigo/client's
	// with a *client.Error.
	var we *wallet.Error
	if errors.As(err, &we) {
		return we.Code == "invalid_grant"
	}
	var ce *client.Error
	if !errors.As(err, &ce) {
		return false
	}
	r, ok := ce.ServerResponse()
	return ok && r.Code == "invalid_grant"
}

// forgetGrant deletes g and its instance key, best effort. Credentials
// still naming it can't be refreshed any more (ErrReissueRequired).
func (w *Wallet) forgetGrant(ctx context.Context, g RefreshGrant) {
	_ = w.deps.Grants.DeleteGrant(ctx, g.ID)
	w.deleteGrantKeys(ctx, g)
}

// deleteGrantKeys deletes the keys g kept, best effort, once g itself
// is deleted: a GrantAuthNone grant's DPoP key only once nothing else
// holds it.
func (w *Wallet) deleteGrantKeys(ctx context.Context, g RefreshGrant) {
	if g.ClientAuth == GrantAuthNone {
		_ = w.releaseDPoPKey(ctx, g.DPoPKeyID)
		return
	}
	_ = w.deps.Keys.DeleteKey(ctx, g.InstanceKeyID)
}

// forgetRefusedGrant forgets g after the Authorization Server refused
// its refresh token — unless the grant now holds another token, which a
// refresh elsewhere stored after this one read it.
func (w *Wallet) forgetRefusedGrant(ctx context.Context, g RefreshGrant) {
	cur, err := w.deps.Grants.GetGrant(ctx, g.ID)
	if err != nil || cur.RefreshToken.Reveal() != g.RefreshToken.Reveal() {
		return
	}
	w.forgetGrant(ctx, cur)
}

// unusedGrant returns the grant id names when no stored credential,
// pending deferred credential or open issuance uses it, nil otherwise or
// when there's none.
func (w *Wallet) unusedGrant(ctx context.Context, id string) (*RefreshGrant, error) {
	if id == "" || w.grantHeld(id) {
		return nil, nil
	}
	creds, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(creds, func(c StoredCredential) bool { return c.GrantID == id }) {
		return nil, nil
	}
	pending, err := w.deps.Deferred.ListDeferred(ctx)
	if err != nil {
		return nil, err
	}
	if slices.ContainsFunc(pending, func(p PendingDeferred) bool { return p.GrantID == id }) {
		return nil, nil
	}
	g, err := w.deps.Grants.GetGrant(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// releaseUnusedGrant ends the grant grantID names once nothing uses it
// — no stored or pending deferred credential, and no open issuance: it
// revokes the refresh token (revokeGrant), then deletes the grant and
// its instance key. It decides holding the grant's lock, on the grant as
// it is then, so a refresh can't change it in between. configID is a
// configuration the grant was for.
func (w *Wallet) releaseUnusedGrant(ctx context.Context, grantID, configID string) error {
	if grantID == "" {
		return nil
	}
	defer w.lockGrant(grantID)()
	g, err := w.unusedGrant(ctx, grantID)
	if err != nil || g == nil {
		return err
	}
	w.revokeGrant(ctx, *g, configID)
	if err := w.deps.Grants.DeleteGrant(ctx, g.ID); err != nil {
		return err
	}
	w.deleteGrantKeys(ctx, *g)
	return nil
}

// holdGrant marks grant id in use by an open issuance, or with held
// false no longer.
func (w *Wallet) holdGrant(id string, held bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if held {
		w.openGrants[id] = true
	} else {
		delete(w.openGrants, id)
	}
}

func (w *Wallet) grantHeld(id string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.openGrants[id]
}

// revokeGrant asks the Authorization Server to revoke g's refresh token
// (RFC 7009), authenticating with g's instance key, as a refresh does;
// configID is a configuration the grant was for.
// It's best effort: a server without a revocation endpoint, an
// unreachable one, or an issuer no longer naming it leaves the token to
// expire there, and it's forgotten here all the same.
func (w *Wallet) revokeGrant(ctx context.Context, g RefreshGrant, configID string) {
	if g.ClientAuth == GrantAuthNone {
		w.revokePublicGrant(ctx, g, configID)
		return
	}
	if w.deps.Provider == nil || w.cfg.ClientID == "" {
		return
	}
	instanceKey, err := w.deps.Keys.Key(ctx, g.InstanceKeyID)
	if err != nil {
		return
	}
	metadata, err := w.planGrant(ctx, g, configID)
	if err != nil {
		return
	}
	s := &Issuance{w: w, metadata: metadata, instanceKey: instanceKey, offer: oid4vci.CredentialOffer{CredentialIssuer: g.CredentialIssuer}}
	defer s.endRefresh(context.WithoutCancel(ctx))
	if err := s.newClient(ctx, g.AuthorizationServer, false); err != nil {
		return
	}
	_ = s.client.RevokeToken(ctx, g.RefreshToken)
}

// revokePublicGrant revokes a GrantAuthNone grant's refresh token as a
// public client (RFC 7009 §5), best effort, as revokeGrant does.
func (w *Wallet) revokePublicGrant(ctx context.Context, g RefreshGrant, configID string) {
	if _, err := w.planGrant(ctx, g, configID); err != nil {
		return
	}
	asMeta, err := w.core.FetchAuthorizationServerMetadata(ctx, g.AuthorizationServer)
	if err != nil || asMeta.RevocationEndpoint == "" {
		return
	}
	endpoint, err := fapi.ParseEndpointURL(asMeta.RevocationEndpoint, w.urlOptions()...)
	if err != nil {
		return
	}
	_ = w.core.RevokeToken(ctx, endpoint, g.RefreshToken, "refresh_token")
}

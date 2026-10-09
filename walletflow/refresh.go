package walletflow

import (
	"context"
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
// later without the holder (OpenID4VCI 1.0 §13.5): the refresh token the
// Authorization Server issued, and the wallet instance key the Wallet
// Attestation was bound to when it did, which every refresh must
// authenticate with again (draft-ietf-oauth-attestation-based-client-auth-07
// §10.3). It's a secret, like a credential.
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
	// while the grant is.
	InstanceKeyID string
	CreatedAt     time.Time
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
		RefreshToken:    s.refreshToken, InstanceKeyID: s.instanceKey.ID(), CreatedAt: s.w.deps.Clock().UTC(),
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
	g, instanceKey, err := w.loadGrant(ctx, old)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	metadata, err := w.planGrant(ctx, g, old.ConfigurationID)
	if err != nil {
		return StoredCredential{}, nil, err
	}
	if metadata.NonceEndpoint == nil {
		return StoredCredential{}, nil, errors.New("walletflow: the issuer advertises no nonce endpoint, which the attestation proof needs")
	}
	s := &Issuance{
		w: w, metadata: metadata, instanceKey: instanceKey, grantID: g.ID, grantStored: true, replace: old.ID,
		offer: oid4vci.CredentialOffer{CredentialIssuer: old.CredentialIssuer, CredentialConfigurationIDs: []string{old.ConfigurationID}},
	}
	defer s.endRefresh(context.WithoutCancel(ctx))
	if err := s.newClient(ctx, g.AuthorizationServer, false); err != nil {
		return StoredCredential{}, nil, err
	}
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

// loadGrant is the refresh grant of credential c, with its instance
// key: ErrReissueRequired when either is gone, or the grant is another
// issuer's. Called with the grant's lock held.
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
	instanceKey, err := w.deps.Keys.Key(ctx, g.InstanceKeyID)
	if errors.Is(err, ErrNotFound) {
		w.forgetGrant(context.WithoutCancel(ctx), g)
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: its wallet instance key is gone: %w", ErrReissueRequired)
	}
	if err != nil {
		return RefreshGrant{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	return g, instanceKey, nil
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
// rotated refresh token. A refused one is ErrReissueRequired, and the
// grant is forgotten.
func (s *Issuance) redeemGrant(ctx context.Context, g RefreshGrant) error {
	tokens, err := s.client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: client.TokenSet{RefreshToken: g.RefreshToken, HasRefreshToken: true}})
	if err != nil {
		if invalidGrant(err) {
			s.w.forgetRefusedGrant(context.WithoutCancel(ctx), g)
			return fmt.Errorf("walletflow: refresh credential: %w: %w", ErrReissueRequired, err)
		}
		return fmt.Errorf("walletflow: refresh token: %w", err)
	}
	if tokens.HasRefreshToken && tokens.RefreshToken.Reveal() != g.RefreshToken.Reveal() {
		g.RefreshToken = tokens.RefreshToken
		if err := s.w.deps.Grants.PutGrant(ctx, g); err != nil {
			return fmt.Errorf("walletflow: store refresh grant: %w", err)
		}
	}
	s.resource = s.client.ProtectedResource(tokens)
	s.accessToken = tokens.AccessToken
	if s.identifiers, err = credentialIdentifiers(tokens.AuthorizationDetails); err != nil {
		return fmt.Errorf("walletflow: token response: %w", err)
	}
	if tokens.HasExpiresIn {
		s.accessExpiresAt = tokens.ObtainedAt.Add(tokens.ExpiresIn)
	}
	return nil
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
	return w.deps.Keys.DeleteKey(ctx, g.InstanceKeyID)
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

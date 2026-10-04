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
	RefreshToken        fapi.Secret
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

// keepGrant stores the issuance's refresh grant the first time one of
// its credentials is stored, and returns its ID: "" when the issuance
// has no refresh token. The instance key is then kept with it.
func (s *Issuance) keepGrant(ctx context.Context) (string, error) {
	if s.grantID != "" || s.refreshToken.Reveal() == "" {
		return s.grantID, nil
	}
	id, err := randomID(s.w.deps.Random)
	if err != nil {
		return "", err
	}
	g := RefreshGrant{
		ID: id, CredentialIssuer: s.offer.CredentialIssuer, AuthorizationServer: s.authorizationServer,
		RefreshToken: s.refreshToken, InstanceKeyID: s.instanceKey.ID(), CreatedAt: s.w.deps.Clock().UTC(),
	}
	if err := s.w.deps.Grants.PutGrant(ctx, g); err != nil {
		return "", fmt.Errorf("walletflow: store refresh grant: %w", err)
	}
	s.grantID = id
	return id, nil
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
// and the Deferred is returned to poll: once settled, its credential is
// stored as a new one.
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
	g, err := w.deps.Grants.GetGrant(ctx, old.GrantID)
	if errors.Is(err, ErrNotFound) {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: its refresh grant is gone: %w", ErrReissueRequired)
	}
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	instanceKey, err := w.deps.Keys.Key(ctx, g.InstanceKeyID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			w.forgetGrant(context.WithoutCancel(ctx), g)
			return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: its wallet instance key is gone: %w", ErrReissueRequired)
		}
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: %w", err)
	}
	metadata, err := w.core.FetchCredentialIssuerMetadata(ctx, old.CredentialIssuer)
	if err != nil {
		return StoredCredential{}, nil, fmt.Errorf("walletflow: issuer metadata: %w", err)
	}
	if metadata.NonceEndpoint == nil {
		return StoredCredential{}, nil, errors.New("walletflow: the issuer advertises no nonce endpoint, which the attestation proof needs")
	}
	s := &Issuance{
		w: w, metadata: metadata, instanceKey: instanceKey, grantID: g.ID, replace: old.ID,
		offer: oid4vci.CredentialOffer{CredentialIssuer: old.CredentialIssuer, CredentialConfigurationIDs: []string{old.ConfigurationID}},
	}
	defer s.endRefresh(context.WithoutCancel(ctx))
	if err := s.newClient(ctx, g.AuthorizationServer); err != nil {
		return StoredCredential{}, nil, err
	}
	tokens, err := s.client.RefreshTokens(ctx, client.RefreshTokenRequest{Tokens: client.TokenSet{RefreshToken: g.RefreshToken, HasRefreshToken: true}})
	if err != nil {
		if invalidGrant(err) {
			w.forgetGrant(context.WithoutCancel(ctx), g)
			return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh credential: %w: %w", ErrReissueRequired, err)
		}
		return StoredCredential{}, nil, fmt.Errorf("walletflow: refresh token: %w", err)
	}
	if tokens.HasRefreshToken && tokens.RefreshToken.Reveal() != g.RefreshToken.Reveal() {
		g.RefreshToken = tokens.RefreshToken
		if err := w.deps.Grants.PutGrant(ctx, g); err != nil {
			return StoredCredential{}, nil, fmt.Errorf("walletflow: store refresh grant: %w", err)
		}
	}
	s.resource = s.client.ProtectedResource(tokens)
	s.accessToken = tokens.AccessToken
	if tokens.HasExpiresIn {
		s.accessExpiresAt = tokens.ObtainedAt.Add(tokens.ExpiresIn)
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
	kept := map[string]bool{}
	for _, cp := range stored.AllCopies() {
		kept[cp.HolderKeyID] = true
	}
	for _, cp := range old.AllCopies() {
		if !kept[cp.HolderKeyID] {
			_ = w.deps.Keys.DeleteKey(context.WithoutCancel(ctx), cp.HolderKeyID)
		}
	}
	return stored, nil, nil
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

// releaseGrant forgets the grant id names once no stored credential
// other than except uses it.
func (w *Wallet) releaseGrant(ctx context.Context, id, except string) error {
	if id == "" {
		return nil
	}
	creds, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return err
	}
	if slices.ContainsFunc(creds, func(c StoredCredential) bool { return c.GrantID == id && c.ID != except }) {
		return nil
	}
	g, err := w.deps.Grants.GetGrant(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := w.deps.Grants.DeleteGrant(ctx, id); err != nil {
		return err
	}
	return w.deps.Keys.DeleteKey(ctx, g.InstanceKeyID)
}

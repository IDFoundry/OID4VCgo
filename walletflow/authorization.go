package walletflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/storage"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// ErrNoAuthorization is returned by ResumeIssuance for a redirect that
// matches no authorization in progress — one this wallet didn't begin,
// already completed, or that has expired.
var ErrNoAuthorization = errors.New("walletflow: no authorization in progress for this redirect")

// PendingAuthorization is an issuance's authorization in progress — the
// holder at the issuer's pages, between BeginAuthorization and the
// redirect back — as an AuthorizationStore keeps it, so the redirect can
// complete it after the app was suspended and relaunched
// (Wallet.ResumeIssuance).
type PendingAuthorization struct {
	// State is the authorization request's state parameter, which the
	// redirect carries back: the key it's found by.
	State string
	// Session is fapigo/client's own record of the authorization (its
	// PKCE verifier among it), kept as is. It's no use without the DPoP
	// key the authorization code is bound to, and the instance key the
	// client authenticates with, which never leave the KeyStore.
	Session   json.RawMessage
	ExpiresAt time.Time
	// Offer is the resolved Credential Offer, and AuthorizationServer
	// the server the authorization is at.
	Offer               oid4vci.CredentialOffer
	AuthorizationServer string
	InstanceKeyID       string
	DPoPKeyID           string
	CreatedAt           time.Time
}

// AuthorizationStore keeps the authorizations in progress, under the
// platform's data protection. A production wallet needs a Durable one:
// the authorization's state must survive the app being suspended while
// the holder is at the issuer's pages. MemoryAuthorizationStore isn't.
//
// It holds only this wallet's own authorizations — a native app's
// on-device storage — never one shared between users or browsers: the
// redirect's state alone then finds the authorization it completes
// (fapigo's storage.Capabilities.SingleUserAgent). A wallet serving
// several browsers must not call ResumeIssuance.
type AuthorizationStore interface {
	// PutAuthorization stores a, replacing any with its State.
	PutAuthorization(ctx context.Context, a PendingAuthorization) error
	// GetAuthorization returns the one state names, or an error wrapping
	// ErrNotFound.
	GetAuthorization(ctx context.Context, state string) (PendingAuthorization, error)
	// ListAuthorizations returns every one.
	ListAuthorizations(ctx context.Context) ([]PendingAuthorization, error)
	// DeleteAuthorization deletes the one state names; deleting one that
	// doesn't exist isn't an error.
	DeleteAuthorization(ctx context.Context, state string) error
	// Durable reports whether what's stored survives a restart.
	Durable() bool
}

// MemoryAuthorizationStore is an AuthorizationStore in memory, for
// development and tests: not Durable.
type MemoryAuthorizationStore struct {
	mu   sync.Mutex
	auth map[string]PendingAuthorization
}

// NewMemoryAuthorizationStore returns an empty MemoryAuthorizationStore.
func NewMemoryAuthorizationStore() *MemoryAuthorizationStore {
	return &MemoryAuthorizationStore{auth: map[string]PendingAuthorization{}}
}

// PutAuthorization implements AuthorizationStore.
func (s *MemoryAuthorizationStore) PutAuthorization(_ context.Context, a PendingAuthorization) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth[a.State] = a
	return nil
}

// GetAuthorization implements AuthorizationStore.
func (s *MemoryAuthorizationStore) GetAuthorization(_ context.Context, state string) (PendingAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.auth[state]
	if !ok {
		return PendingAuthorization{}, fmt.Errorf("walletflow: authorization: %w", ErrNotFound)
	}
	return a, nil
}

// ListAuthorizations implements AuthorizationStore.
func (s *MemoryAuthorizationStore) ListAuthorizations(context.Context) ([]PendingAuthorization, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingAuthorization, 0, len(s.auth))
	for _, a := range s.auth {
		out = append(out, a)
	}
	return out, nil
}

// DeleteAuthorization implements AuthorizationStore.
func (s *MemoryAuthorizationStore) DeleteAuthorization(_ context.Context, state string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.auth, state)
	return nil
}

// Durable implements AuthorizationStore: a MemoryAuthorizationStore isn't.
func (s *MemoryAuthorizationStore) Durable() bool { return false }

// sessionStore is an issuance's fapigo/client SessionStore over the
// wallet's AuthorizationStore: Create records the authorization with
// what resuming it needs, Consume retrieves and retires it.
type sessionStore struct {
	w *Wallet
	// What Create records alongside fapigo's session.
	offer               oid4vci.CredentialOffer
	authorizationServer string
	instanceKeyID       string
	dpopKeyID           string
	// state is the authorization in progress's, once Create has recorded
	// it (or the one ResumeIssuance resumes).
	state string
}

var (
	_ storage.SessionStore   = (*sessionStore)(nil)
	_ storage.StoreAssurance = (*sessionStore)(nil)
)

func (s *sessionStore) Create(ctx context.Context, n storage.NewSession) error {
	s.state = n.State
	return s.w.deps.Authorizations.PutAuthorization(ctx, PendingAuthorization{
		State: n.State, Session: n.Record, ExpiresAt: n.ExpiresAt,
		Offer: s.offer, AuthorizationServer: s.authorizationServer,
		InstanceKeyID: s.instanceKeyID, DPoPKeyID: s.dpopKeyID, CreatedAt: s.w.deps.Clock().UTC(),
	})
}

func (s *sessionStore) Consume(ctx context.Context, c storage.SessionConsumption) (storage.ConsumedSession, error) {
	// One consume at a time, so two callbacks for one state can't both
	// retrieve it: the wallet is one process over its own store.
	s.w.authMu.Lock()
	defer s.w.authMu.Unlock()
	a, err := s.w.deps.Authorizations.GetAuthorization(ctx, c.State)
	if err != nil {
		return storage.ConsumedSession{}, err
	}
	if err := s.w.deps.Authorizations.DeleteAuthorization(ctx, c.State); err != nil {
		return storage.ConsumedSession{}, err
	}
	return storage.ConsumedSession{Record: a.Session, ExpiresAt: a.ExpiresAt}, nil
}

// Capabilities implements storage.StoreAssurance: Durable as the
// AuthorizationStore is, and Consume is atomic within the wallet's one
// process. It's SingleUserAgent: a wallet's AuthorizationStore holds
// only the authorizations the wallet itself began, so the callback's
// state alone finds the one the redirect completes (ResumeIssuance).
func (s *sessionStore) Capabilities() storage.Capabilities {
	return storage.Capabilities{Durable: s.w.deps.Authorizations.Durable(), AtomicConsume: true, SingleUserAgent: true}
}

// ResumeIssuance completes an authorization begun before the app was
// suspended and relaunched: redirect is the redirect back to
// RedirectURI, the whole URL. It finds the authorization the redirect's
// state names, rebuilds its issuance — fetching the issuer's metadata
// again, with the same instance and DPoP keys and a fresh Wallet
// Attestation — and completes it, returning the Issuance ready for
// RequestCredentials. It returns ErrNoAuthorization when nothing is in
// progress for the redirect, and an *AuthorizationDeniedError as
// CompleteAuthorization does. Close the Issuance when done, as usual.
func (w *Wallet) ResumeIssuance(ctx context.Context, redirect string) (*Issuance, error) {
	if err := w.checkIssuance(); err != nil {
		return nil, err
	}
	u, err := url.Parse(redirect)
	if err != nil {
		return nil, fmt.Errorf("walletflow: redirect: %w", err)
	}
	state := u.Query().Get("state")
	if state == "" {
		return nil, ErrNoAuthorization
	}
	a, err := w.deps.Authorizations.GetAuthorization(ctx, state)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoAuthorization
	}
	if err != nil {
		return nil, fmt.Errorf("walletflow: authorization: %w", err)
	}
	if !w.deps.Clock().Before(a.ExpiresAt) {
		_ = w.forgetAuthorization(ctx, a)
		return nil, ErrNoAuthorization
	}
	s, err := w.rebuild(ctx, a)
	if err != nil {
		return nil, err
	}
	// No session handle: the store is single-user-agent, so fapigo takes
	// the session from the callback itself.
	if err := s.CompleteAuthorization(ctx, redirect); err != nil {
		var denied *AuthorizationDeniedError
		if !errors.As(err, &denied) {
			// The session is consumed: nothing more can complete it.
			_ = s.Close(ctx)
		}
		return nil, err
	}
	return s, nil
}

// rebuild is the issuance a, at the authorization step: the offer's
// metadata fetched again, its keys loaded, and its client built.
func (w *Wallet) rebuild(ctx context.Context, a PendingAuthorization) (*Issuance, error) {
	metadata, err := w.core.FetchCredentialIssuerMetadata(ctx, a.Offer.CredentialIssuer)
	if err != nil {
		return nil, fmt.Errorf("walletflow: issuer metadata: %w", err)
	}
	plan, err := wallet.PlanAuthorization(a.Offer, metadata)
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	if plan.AuthorizationServer != a.AuthorizationServer {
		return nil, errors.New("walletflow: the issuer no longer names the authorization server the authorization began at")
	}
	s := &Issuance{w: w, offer: a.Offer, metadata: metadata, step: stepAuthorizing}
	s.details = describeOffer(a.Offer, metadata)
	if s.instanceKey, err = w.deps.Keys.Key(ctx, a.InstanceKeyID); err != nil {
		return nil, fmt.Errorf("walletflow: the authorization's instance key: %w", err)
	}
	if s.dpopKey, err = w.deps.Keys.Key(ctx, a.DPoPKeyID); err != nil {
		return nil, fmt.Errorf("walletflow: the authorization's DPoP key: %w", err)
	}
	w.mu.Lock()
	w.liveDPoP[a.DPoPKeyID] = true
	w.mu.Unlock()
	s.sessions = &sessionStore{
		w: w, offer: a.Offer, authorizationServer: a.AuthorizationServer,
		instanceKeyID: a.InstanceKeyID, dpopKeyID: a.DPoPKeyID, state: a.State,
	}
	if err := s.newClient(ctx, a.AuthorizationServer); err != nil {
		_ = s.Close(ctx)
		return nil, err
	}
	return s, nil
}

// forgetAuthorization deletes a, and its keys.
func (w *Wallet) forgetAuthorization(ctx context.Context, a PendingAuthorization) error {
	return errors.Join(
		w.deps.Authorizations.DeleteAuthorization(ctx, a.State),
		w.deps.Keys.DeleteKey(ctx, a.InstanceKeyID),
		w.releaseDPoPKey(ctx, a.DPoPKeyID),
	)
}

// pendingAuthorizations are the authorizations still in progress,
// oldest first; it forgets, with their keys, those that have expired.
func (w *Wallet) pendingAuthorizations(ctx context.Context) ([]PendingAuthorization, error) {
	all, err := w.deps.Authorizations.ListAuthorizations(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list authorizations: %w", err)
	}
	now := w.deps.Clock()
	var live []PendingAuthorization
	for _, a := range all {
		if !now.Before(a.ExpiresAt) {
			_ = w.forgetAuthorization(ctx, a)
			continue
		}
		live = append(live, a)
	}
	sort.Slice(live, func(i, j int) bool { return live[i].CreatedAt.Before(live[j].CreatedAt) })
	return live, nil
}

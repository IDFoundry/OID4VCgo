package walletflow

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	fapi "github.com/idfoundry/fapigo"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// minPollInterval is the shortest wait between Wait's polls, whatever
// interval the issuer asks for.
const minPollInterval = time.Second

// PendingDeferred is a deferred credential (OpenID4VCI 1.0 §9) as a
// DeferredStore keeps it: what polling it needs after the wallet
// restarts. The access token is bound to the DPoP key (RFC 9449), which
// never leaves the KeyStore, so it's no use to anyone without that key.
type PendingDeferred struct {
	ID               string
	CredentialIssuer string
	ConfigurationID  string
	TransactionID    string
	// AccessToken is the issuance's access token, which the Deferred
	// Credential Endpoint takes.
	AccessToken fapi.Secret
	// AccessTokenExpiresAt is when the access token expires, or zero
	// when the Token Response didn't say. Once it has passed, the issuer
	// refuses to be polled with it.
	AccessTokenExpiresAt time.Time
	// DPoPKeyID and HolderKeyID name the DPoP key the access token is
	// bound to and the key the credential will be bound to.
	DPoPKeyID   string
	HolderKeyID string
	// Interval is how long the issuer asked the wallet to wait between
	// polls.
	Interval   time.Duration
	DeferredAt time.Time
}

// DeferredStore keeps the wallet's pending deferred credentials, so they
// can be polled after the wallet restarts: under the platform's data
// protection, like the CredentialStore, since each holds an access
// token. MemoryDeferredStore keeps them only for the process's life.
type DeferredStore interface {
	// PutDeferred stores p, replacing any with its ID.
	PutDeferred(ctx context.Context, p PendingDeferred) error
	// ListDeferred returns every pending deferred credential.
	ListDeferred(ctx context.Context) ([]PendingDeferred, error)
	// DeleteDeferred deletes the one id names; deleting one that doesn't
	// exist isn't an error.
	DeleteDeferred(ctx context.Context, id string) error
}

// MemoryDeferredStore is a DeferredStore in memory: what's pending is
// lost when the process ends. It's the default.
type MemoryDeferredStore struct {
	mu      sync.Mutex
	pending map[string]PendingDeferred
}

// NewMemoryDeferredStore returns an empty MemoryDeferredStore.
func NewMemoryDeferredStore() *MemoryDeferredStore {
	return &MemoryDeferredStore{pending: map[string]PendingDeferred{}}
}

// PutDeferred implements DeferredStore.
func (s *MemoryDeferredStore) PutDeferred(_ context.Context, p PendingDeferred) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[p.ID] = p
	return nil
}

// ListDeferred implements DeferredStore.
func (s *MemoryDeferredStore) ListDeferred(context.Context) ([]PendingDeferred, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PendingDeferred, 0, len(s.pending))
	for _, p := range s.pending {
		out = append(out, p)
	}
	return out, nil
}

// DeleteDeferred implements DeferredStore.
func (s *MemoryDeferredStore) DeleteDeferred(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.pending, id)
	return nil
}

// Deferred is a credential the issuer will issue later (OpenID4VCI 1.0
// §9), polled with its issuance's access token. It's kept in the
// DeferredStore until it's settled, so it outlives its Issuance and,
// with a persistent store, the process: Wallet.Deferred returns the
// pending ones.
type Deferred struct {
	w *Wallet

	mu          sync.Mutex
	p           PendingDeferred
	metadata    *oid4vci.Metadata // fetched on the first poll after a restart
	resource    wallet.ProtectedResourceClient
	requestEnc  *wallet.RequestEncryption
	responseEnc *wallet.ResponseEncryption
	done        bool
}

// ID identifies the Deferred in the DeferredStore.
func (d *Deferred) ID() string { return d.p.ID }

// ConfigurationID is the credential configuration deferred.
func (d *Deferred) ConfigurationID() string { return d.p.ConfigurationID }

// CredentialIssuer is the issuer that deferred it.
func (d *Deferred) CredentialIssuer() string { return d.p.CredentialIssuer }

// DeferredAt is when the issuer deferred it.
func (d *Deferred) DeferredAt() time.Time { return d.p.DeferredAt }

// AccessTokenExpiresAt is when the access token it's polled with
// expires — after which the issuer refuses the poll, and it can only be
// abandoned — or zero when the Token Response didn't say.
func (d *Deferred) AccessTokenExpiresAt() time.Time { return d.p.AccessTokenExpiresAt }

// Done reports whether the Deferred is settled — issued, denied,
// refused by the wallet's checks, or abandoned: polling it again returns
// ErrWrongStep.
func (d *Deferred) Done() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.done
}

// Interval is how long the issuer asked the wallet to wait between
// polls.
func (d *Deferred) Interval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.p.Interval
}

// Poll asks the issuer once. It returns the credential once issued
// (checked, stored, and the issuer notified), nil while it's still
// pending, or ErrCredentialDenied. Once it has returned the credential,
// ErrCredentialDenied, or an issued credential failing the wallet's
// checks, the Deferred is done (Done), and Poll returns ErrWrongStep;
// after any other error — a request that failed — it can be polled
// again.
func (d *Deferred) Poll(ctx context.Context) (*StoredCredential, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return nil, ErrWrongStep
	}
	if err := d.prepare(ctx); err != nil {
		return nil, err
	}
	result, err := d.w.core.RequestDeferredCredential(ctx, d.resource, *d.metadata.DeferredCredentialEndpoint, wallet.DeferredCredentialRequest{
		TransactionID: d.p.TransactionID, RequestEncryption: d.requestEnc, ResponseEncryption: d.responseEnc,
	})
	var werr *wallet.Error
	switch {
	case errors.As(err, &werr) && werr.Code == "credential_request_denied":
		// Cleanup is best effort: what it leaves behind, a key sweep
		// (KeysInUse) or Abandon removes later.
		_ = d.settle(ctx, true)
		return nil, ErrCredentialDenied
	case err != nil:
		return nil, fmt.Errorf("walletflow: deferred credential %q: %w", d.p.ConfigurationID, err)
	case len(result.Credentials) == 0:
		if result.Interval > 0 && result.Interval != d.p.Interval {
			d.p.Interval = result.Interval
			_ = d.w.deps.Deferred.PutDeferred(ctx, d.p) // best effort: only the next wait's length
		}
		return nil, nil
	}
	holder, err := d.w.deps.Keys.Key(ctx, d.p.HolderKeyID)
	if err != nil {
		return nil, fmt.Errorf("walletflow: deferred credential %q's holder key: %w", d.p.ConfigurationID, err)
	}
	stored, err := d.w.accept(ctx, issued{
		issuer: d.p.CredentialIssuer, metadata: *d.metadata, resource: d.resource,
		configID: d.p.ConfigurationID, holder: holder, result: result,
	})
	if err != nil {
		_ = d.settle(ctx, true)
		return nil, err
	}
	_ = d.settle(ctx, false)
	return &stored, nil
}

// prepare readies a Deferred resumed after a restart: the issuer's
// metadata, its DPoP key and access token, and fresh encryption.
func (d *Deferred) prepare(ctx context.Context) error {
	if d.metadata != nil {
		return nil
	}
	metadata, err := d.w.core.FetchCredentialIssuerMetadata(ctx, d.p.CredentialIssuer)
	if err != nil {
		return fmt.Errorf("walletflow: issuer metadata: %w", err)
	}
	if metadata.DeferredCredentialEndpoint == nil {
		return fmt.Errorf("walletflow: the issuer no longer advertises a deferred credential endpoint")
	}
	dpop, err := d.w.deps.Keys.Key(ctx, d.p.DPoPKeyID)
	if err != nil {
		return fmt.Errorf("walletflow: deferred credential %q's DPoP key: %w", d.p.ConfigurationID, err)
	}
	if d.requestEnc, d.responseEnc, err = wallet.EncryptionFromMetadata(metadata); err != nil {
		return fmt.Errorf("walletflow: %w", err)
	}
	d.resource = d.w.core.DPoPResourceClient(d.p.AccessToken, dpop)
	d.metadata = &metadata
	return nil
}

// Abandon gives up on the Deferred: it's deleted from the DeferredStore
// with its holder key, and the issuer is never asked again. Use it when
// the issuer can no longer be polled — the access token has expired,
// say — or the holder no longer wants the credential.
func (d *Deferred) Abandon(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return nil
	}
	return d.settle(ctx, true)
}

// settle ends the Deferred: it leaves the DeferredStore, its holder key
// goes unless the credential was stored, and its DPoP key goes once no
// other pending one shares it.
func (d *Deferred) settle(ctx context.Context, deleteHolder bool) error {
	d.done = true
	errs := []error{d.w.deps.Deferred.DeleteDeferred(ctx, d.p.ID)}
	if deleteHolder {
		errs = append(errs, d.w.deps.Keys.DeleteKey(ctx, d.p.HolderKeyID))
	}
	errs = append(errs, d.w.releaseDPoPKey(ctx, d.p.DPoPKeyID))
	d.w.forgetDeferred(d.p.ID)
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("walletflow: settle deferred credential: %w", err)
	}
	return nil
}

// Wait polls, at the issuer's interval, until the credential is issued
// or denied, or ctx is done.
func (d *Deferred) Wait(ctx context.Context) (StoredCredential, error) {
	for {
		stored, err := d.Poll(ctx)
		if err != nil {
			return StoredCredential{}, err
		}
		if stored != nil {
			return *stored, nil
		}
		select {
		case <-ctx.Done():
			return StoredCredential{}, fmt.Errorf("walletflow: waiting for deferred credential %q: %w", d.p.ConfigurationID, ctx.Err())
		case <-time.After(max(d.Interval(), minPollInterval)):
		}
	}
}

// Deferred returns the wallet's pending deferred credentials, oldest
// first — after a restart, the ones a persistent DeferredStore kept. A
// pending one is the same *Deferred each time, however it was obtained.
// Listing them makes no network calls: a resumed one fetches the
// issuer's metadata on its first Poll.
func (w *Wallet) Deferred(ctx context.Context) ([]*Deferred, error) {
	pending, err := w.deps.Deferred.ListDeferred(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list deferred credentials: %w", err)
	}
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].DeferredAt.Equal(pending[j].DeferredAt) {
			return pending[i].DeferredAt.Before(pending[j].DeferredAt)
		}
		return pending[i].ID < pending[j].ID
	})
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]*Deferred, 0, len(pending))
	for _, p := range pending {
		d, ok := w.deferred[p.ID]
		if !ok {
			d = &Deferred{w: w, p: p}
			w.deferred[p.ID] = d
		}
		out = append(out, d)
	}
	return out, nil
}

// keepDeferred stores p as pending, already prepared to poll with its
// issuance's metadata and resource client, and returns its Deferred.
func (w *Wallet) keepDeferred(ctx context.Context, p PendingDeferred, metadata oid4vci.Metadata, resource wallet.ProtectedResourceClient,
	requestEnc *wallet.RequestEncryption, responseEnc *wallet.ResponseEncryption) (*Deferred, error) {
	if err := w.deps.Deferred.PutDeferred(ctx, p); err != nil {
		return nil, fmt.Errorf("walletflow: store deferred credential %q: %w", p.ConfigurationID, err)
	}
	d := &Deferred{w: w, p: p, metadata: &metadata, resource: resource, requestEnc: requestEnc, responseEnc: responseEnc}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.deferred[p.ID] = d
	return d, nil
}

func (w *Wallet) forgetDeferred(id string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.deferred, id)
}

// releaseDPoPKey deletes the DPoP key id names unless an open issuance
// holds it or a pending deferred credential still polls with it.
func (w *Wallet) releaseDPoPKey(ctx context.Context, id string) error {
	w.mu.Lock()
	live := w.liveDPoP[id]
	w.mu.Unlock()
	if id == "" || live {
		return nil
	}
	pending, err := w.deps.Deferred.ListDeferred(ctx)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.DPoPKeyID == id {
			return nil
		}
	}
	return w.deps.Keys.DeleteKey(ctx, id)
}

// KeysInUse are the IDs of the keys the wallet still needs: its
// credentials' holder keys, each pending deferred credential's holder
// and DPoP keys, and each authorization in progress's instance and DPoP
// keys (ResumeIssuance). Any other key in the KeyStore — when no
// issuance is open — is left over from one that never finished. It
// forgets, with their keys, authorizations that have expired.
func (w *Wallet) KeysInUse(ctx context.Context) ([]string, error) {
	creds, err := w.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	pending, err := w.deps.Deferred.ListDeferred(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list deferred credentials: %w", err)
	}
	seen := map[string]bool{}
	var out []string
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, c := range creds {
		add(c.HolderKeyID)
	}
	for _, p := range pending {
		add(p.HolderKeyID)
		add(p.DPoPKeyID)
	}
	authorizing, err := w.pendingAuthorizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range authorizing {
		add(a.InstanceKeyID)
		add(a.DPoPKeyID)
	}
	sort.Strings(out)
	return out, nil
}

// newDPoPKey creates an issuance's DPoP key, held until it's closed.
func (w *Wallet) newDPoPKey(ctx context.Context) (Key, error) {
	k, err := newKey(ctx, w.deps.Keys, KeyPurposeDPoP)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.liveDPoP[k.ID()] = true
	return k, nil
}

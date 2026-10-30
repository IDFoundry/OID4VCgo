package sqlstore

import (
	"context"
	"errors"
	"fmt"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// notFound turns errNoRow into walletflow.ErrNotFound.
func notFound(what, id string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNoRow):
		return fmt.Errorf("sqlstore: %s %q: %w", what, id, walletflow.ErrNotFound)
	}
	return fmt.Errorf("sqlstore: %s %q: %w", what, id, err)
}

// updateOnce is t.update with fn's own error returned as it is.
func updateOnce[T any](t *table[T], ctx context.Context, what, id string, fn func(*T) error, idOf func(T) string) error {
	var fnErr error
	err := t.update(ctx, id, func(v *T) error {
		fnErr = fn(v)
		return fnErr
	}, idOf)
	if fnErr != nil {
		return fnErr
	}
	return notFound(what, id, err)
}

// CredentialStore is a walletflow.CredentialStore:
// Dependencies.Credentials. Credentials carry personal data: give the
// DB a Sealer. List returns them ordered by ID.
type CredentialStore struct {
	t *table[walletflow.StoredCredential]
}

// Credentials returns d's walletflow.CredentialStore.
func (d *DB) Credentials() *CredentialStore {
	return &CredentialStore{&table[walletflow.StoredCredential]{
		d: d, name: "wallet_credentials", sql: tableSQL{
			upsert: d.sql.credentialUpsert, get: d.sql.credentialGet, getForUpdate: d.sql.credentialGetForUpdate,
			update: d.sql.credentialUpdate, list: d.sql.credentialList, delete: d.sql.credentialDelete,
		}, rowOf: func(walletflow.StoredCredential) row { return row{} },
	}}
}

// Put implements walletflow.CredentialStore.
func (s *CredentialStore) Put(ctx context.Context, c walletflow.StoredCredential) error {
	return notFound("put credential", c.ID, s.t.put(ctx, c.ID, c))
}

// Get implements walletflow.CredentialStore.
func (s *CredentialStore) Get(ctx context.Context, id string) (walletflow.StoredCredential, error) {
	c, err := s.t.get(ctx, id)
	return c, notFound("credential", id, err)
}

// List implements walletflow.CredentialStore.
func (s *CredentialStore) List(ctx context.Context) ([]walletflow.StoredCredential, error) {
	out, err := s.t.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list credentials: %w", err)
	}
	return out, nil
}

// Update implements walletflow.CredentialStore, in one transaction
// holding the credential's row: across every process sharing the
// database, concurrent Updates of one credential run one after
// another. fn is called once.
func (s *CredentialStore) Update(ctx context.Context, id string, fn func(*walletflow.StoredCredential) error) error {
	return updateOnce(s.t, ctx, "credential", id, fn, func(c walletflow.StoredCredential) string { return c.ID })
}

// Delete implements walletflow.CredentialStore.
func (s *CredentialStore) Delete(ctx context.Context, id string) error {
	_, err := s.t.remove(ctx, id)
	return notFound("delete credential", id, err)
}

// AuthorizationStore is a walletflow.AuthorizationStore:
// Dependencies.Authorizations. ResumeIssuance needs one holding only
// one wallet's authorizations: don't share its tables between users.
type AuthorizationStore struct {
	t *table[walletflow.PendingAuthorization]
}

// Authorizations returns d's walletflow.AuthorizationStore.
func (d *DB) Authorizations() *AuthorizationStore {
	return &AuthorizationStore{&table[walletflow.PendingAuthorization]{
		d: d, name: "wallet_authorizations", sql: tableSQL{
			upsert: d.sql.authorizationUpsert, get: d.sql.authorizationGet, consume: d.sql.authorizationConsume,
			list: d.sql.authorizationList, delete: d.sql.authorizationDelete,
		},
		rowOf: func(a walletflow.PendingAuthorization) row { return row{sweepAfter: a.ExpiresAt} },
	}}
}

// PutAuthorization implements walletflow.AuthorizationStore.
func (s *AuthorizationStore) PutAuthorization(ctx context.Context, a walletflow.PendingAuthorization) error {
	return notFound("put authorization", a.State, s.t.put(ctx, a.State, a))
}

// GetAuthorization implements walletflow.AuthorizationStore.
func (s *AuthorizationStore) GetAuthorization(ctx context.Context, state string) (walletflow.PendingAuthorization, error) {
	a, err := s.t.get(ctx, state)
	return a, notFound("authorization", state, err)
}

// ConsumeAuthorization implements walletflow.AuthorizationStore: one
// DELETE … RETURNING.
func (s *AuthorizationStore) ConsumeAuthorization(ctx context.Context, state string) (walletflow.PendingAuthorization, error) {
	a, err := s.t.consume(ctx, state)
	return a, notFound("authorization", state, err)
}

// ListAuthorizations implements walletflow.AuthorizationStore.
func (s *AuthorizationStore) ListAuthorizations(ctx context.Context) ([]walletflow.PendingAuthorization, error) {
	out, err := s.t.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list authorizations: %w", err)
	}
	return out, nil
}

// DeleteAuthorization implements walletflow.AuthorizationStore.
func (s *AuthorizationStore) DeleteAuthorization(ctx context.Context, state string) error {
	_, err := s.t.remove(ctx, state)
	return notFound("delete authorization", state, err)
}

// Durable implements walletflow.AuthorizationStore: true.
func (s *AuthorizationStore) Durable() bool { return true }

// withEncoding has t encode each record as to gives it, and decode it
// back with from: for a record holding a fapi.Secret, which refuses to
// be encoded.
func withEncoding[T, R any](t *table[T], to func(T) R, from func(R) T) *table[T] {
	t.encode = func(id string, v T) ([]byte, error) { return t.d.encodeRecord(t.name, id, to(v)) }
	t.decode = func(id string, data []byte) (T, error) {
		var r R
		if err := t.d.decodeRecord(t.name, id, data, &r); err != nil {
			var zero T
			return zero, err
		}
		return from(r), nil
	}
	return t
}

// grantRecord is a RefreshGrant as a GrantStore encodes it: fapi.Secret
// refuses to be encoded, so its refresh token is a field of its own,
// sealed with the rest when the DB has a Sealer.
type grantRecord struct {
	walletflow.RefreshGrant
	RefreshToken string `json:"RefreshToken"`
}

// GrantStore is a walletflow.GrantStore: Dependencies.Grants. A grant
// holds a refresh token: give the DB a Sealer.
type GrantStore struct {
	t *table[walletflow.RefreshGrant]
}

// Grants returns d's walletflow.GrantStore.
func (d *DB) Grants() *GrantStore {
	return &GrantStore{withEncoding(&table[walletflow.RefreshGrant]{d: d, name: "wallet_grants", sql: tableSQL{
		upsert: d.sql.grantUpsert, get: d.sql.grantGet, getForUpdate: d.sql.grantGetForUpdate,
		update: d.sql.grantUpdate, list: d.sql.grantList, delete: d.sql.grantDelete,
	}, rowOf: func(walletflow.RefreshGrant) row { return row{} }},
		func(g walletflow.RefreshGrant) grantRecord {
			return grantRecord{RefreshGrant: g, RefreshToken: g.RefreshToken.Reveal()}
		},
		func(r grantRecord) walletflow.RefreshGrant {
			r.RefreshGrant.RefreshToken = fapi.NewSecret(r.RefreshToken)
			return r.RefreshGrant
		})}
}

// PutGrant implements walletflow.GrantStore.
func (s *GrantStore) PutGrant(ctx context.Context, g walletflow.RefreshGrant) error {
	return notFound("put refresh grant", g.ID, s.t.put(ctx, g.ID, g))
}

// GetGrant implements walletflow.GrantStore.
func (s *GrantStore) GetGrant(ctx context.Context, id string) (walletflow.RefreshGrant, error) {
	g, err := s.t.get(ctx, id)
	return g, notFound("refresh grant", id, err)
}

// UpdateGrant implements walletflow.GrantStore, as
// CredentialStore.Update does a credential.
func (s *GrantStore) UpdateGrant(ctx context.Context, id string, fn func(*walletflow.RefreshGrant) error) error {
	return updateOnce(s.t, ctx, "refresh grant", id, fn, func(g walletflow.RefreshGrant) string { return g.ID })
}

// ListGrants implements walletflow.GrantStore.
func (s *GrantStore) ListGrants(ctx context.Context) ([]walletflow.RefreshGrant, error) {
	out, err := s.t.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list refresh grants: %w", err)
	}
	return out, nil
}

// DeleteGrant implements walletflow.GrantStore.
func (s *GrantStore) DeleteGrant(ctx context.Context, id string) error {
	_, err := s.t.remove(ctx, id)
	return notFound("delete refresh grant", id, err)
}

// Durable implements walletflow.GrantStore: true.
func (s *GrantStore) Durable() bool { return true }

// deferredRecord is a PendingDeferred as a DeferredStore encodes it,
// its access token a field of its own (see grantRecord).
type deferredRecord struct {
	walletflow.PendingDeferred
	AccessToken string `json:"AccessToken"`
}

// DeferredStore is a walletflow.DeferredStore: Dependencies.Deferred.
// Each pending credential holds an access token: give the DB a Sealer.
type DeferredStore struct {
	t *table[walletflow.PendingDeferred]
}

// Deferred returns d's walletflow.DeferredStore.
func (d *DB) Deferred() *DeferredStore {
	return &DeferredStore{withEncoding(&table[walletflow.PendingDeferred]{d: d, name: "wallet_deferred", sql: tableSQL{
		upsert: d.sql.deferredUpsert, list: d.sql.deferredList, delete: d.sql.deferredDelete,
	}, rowOf: func(walletflow.PendingDeferred) row { return row{} }},
		func(p walletflow.PendingDeferred) deferredRecord {
			return deferredRecord{PendingDeferred: p, AccessToken: p.AccessToken.Reveal()}
		},
		func(r deferredRecord) walletflow.PendingDeferred {
			r.PendingDeferred.AccessToken = fapi.NewSecret(r.AccessToken)
			return r.PendingDeferred
		})}
}

// PutDeferred implements walletflow.DeferredStore.
func (s *DeferredStore) PutDeferred(ctx context.Context, p walletflow.PendingDeferred) error {
	return notFound("put deferred credential", p.ID, s.t.put(ctx, p.ID, p))
}

// ListDeferred implements walletflow.DeferredStore.
func (s *DeferredStore) ListDeferred(ctx context.Context) ([]walletflow.PendingDeferred, error) {
	out, err := s.t.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list deferred credentials: %w", err)
	}
	return out, nil
}

// DeleteDeferred implements walletflow.DeferredStore.
func (s *DeferredStore) DeleteDeferred(ctx context.Context, id string) error {
	_, err := s.t.remove(ctx, id)
	return notFound("delete deferred credential", id, err)
}

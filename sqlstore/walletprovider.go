package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// wpNotFound turns errNoRow into walletprovider.ErrNotFound.
func wpNotFound(what, id string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNoRow):
		return fmt.Errorf("sqlstore: %s %q: %w", what, id, walletprovider.ErrNotFound)
	}
	return fmt.Errorf("sqlstore: %s %q: %w", what, id, err)
}

// insertNew runs t's insert, an INSERT … ON CONFLICT DO NOTHING, saving
// v under id, and reports walletprovider.ErrExists if it inserted
// nothing: a row already held id, or another of the table's unique
// columns' values.
func insertNew[T any](t *table[T], ctx context.Context, id string, v T) error {
	if !storableKeys(id) || !storableArgs(t.rowOf(v).extra) {
		return errUnstorableKey
	}
	vals, err := t.values(id, v)
	if err != nil {
		return err
	}
	var n int64
	err = t.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, t.sql.insert, append([]any{id}, vals...)...)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return err
	case n == 0:
		return walletprovider.ErrExists
	}
	return nil
}

// instanceRecord is an Instance as an InstanceStore encodes it: its Key
// as the bytes it holds, which encoding a json.RawMessage would
// compact, or refuse were they not JSON.
type instanceRecord struct {
	walletprovider.Instance
	Key []byte `json:"Key"`
}

// InstanceStore is a walletprovider.InstanceStore:
// walletprovider.Dependencies.Instances. Each instance is a row keyed
// by its ID, its record sealed when the DB has a Sealer, beside the
// readable key_thumbprint and revision columns: a UNIQUE constraint on
// key_thumbprint, as the primary key on id, makes Create's check and
// store one atomic INSERT, and Update is one UPDATE … WHERE id = ? AND
// revision = ?. The record holds the instance's public keys, its
// registration evidence's summary, its App Attest key and counter, and
// the operator's Reason for a suspension or revocation: nothing secret,
// but sealing keeps a database writer from altering it unnoticed —
// though not from putting back an older copy, an older Counter with it,
// which would let an App Attest assertion the provider accepted be
// accepted again: the database must be trusted for that.
// Instances never expire: Sweep leaves them alone, and nothing here
// deletes one.
type InstanceStore struct {
	t *table[walletprovider.Instance]
}

var _ walletprovider.InstanceStore = (*InstanceStore)(nil)

// WalletProviderInstances returns d's walletprovider.InstanceStore.
func (d *DB) WalletProviderInstances() *InstanceStore {
	t := &table[walletprovider.Instance]{
		d: d, name: "walletprovider_instances", sql: tableSQL{insert: d.sql.wpInstanceInsert, get: d.sql.wpInstanceGet},
		rowOf: func(in walletprovider.Instance) row {
			return row{extra: []any{in.KeyThumbprint, revisionArg(in.Revision)}}
		},
	}
	t.encode = func(id string, in walletprovider.Instance) ([]byte, error) {
		return d.encodeRecord(t.name, id, instanceRecord{Instance: in, Key: in.Key})
	}
	t.decode = func(id string, data []byte) (walletprovider.Instance, error) {
		var r instanceRecord
		if err := d.decodeRecord(t.name, id, data, &r); err != nil {
			return walletprovider.Instance{}, err
		}
		if r.ID != id {
			return walletprovider.Instance{}, fmt.Errorf("%w: wallet instance %q is stored as %q", ErrRecordFormat, r.ID, id)
		}
		r.Instance.Key = r.Key
		return r.Instance, nil
	}
	return &InstanceStore{t}
}

// revisionArg is rev as a BIGINT argument: callers store revisions
// from 1 up, and Update refuses one that would pass math.MaxInt64.
func revisionArg(rev uint64) int64 {
	return int64(min(rev, math.MaxInt64)) // #nosec G115 -- capped at math.MaxInt64
}

// Get implements walletprovider.InstanceStore.
func (s *InstanceStore) Get(ctx context.Context, id string) (walletprovider.Instance, error) {
	in, err := s.t.get(ctx, id)
	return in, wpNotFound("wallet instance", id, err)
}

// Create implements walletprovider.InstanceStore: one INSERT … ON
// CONFLICT DO NOTHING, which inserts nothing, and reports ErrExists, if
// a row holds the instance's ID or key thumbprint.
func (s *InstanceStore) Create(ctx context.Context, in walletprovider.Instance) error {
	in.Revision = 1
	return wpNotFound("create wallet instance", in.ID, insertNew(s.t, ctx, in.ID, in))
}

// Update implements walletprovider.InstanceStore: one UPDATE … WHERE
// id = ? AND revision = ?, a compare-and-swap across every process
// sharing the database. It refuses an update changing the instance's
// KeyThumbprint, which a registered instance keeps.
func (s *InstanceStore) Update(ctx context.Context, in walletprovider.Instance) error {
	next := in
	next.Revision++
	return updateRevision(ctx, s.t, revisioned{
		what: "update wallet instance", update: s.t.d.sql.wpInstanceUpdate, read: s.t.d.sql.wpInstanceRevision,
		fixedName: "key thumbprint",
	}, in.ID, in.Revision, in.KeyThumbprint, next)
}

// revisioned is a table whose rows a compare-and-swap updates: update
// sets the record and revision of the row whose id, revision and fixed
// column — one an update may not change — are as given, and read
// selects a row's revision and fixed column.
type revisioned struct {
	what, update, read, fixedName string
}

// updateRevision stores next as the record of id, with revision rev+1,
// if its row's revision is rev and its fixed column fixed: one UPDATE
// (r.update). Should it update nothing, it reads the row (r.read) to
// say why: it's unknown, its fixed column differs, or its revision.
func updateRevision[T any](ctx context.Context, t *table[T], r revisioned, id string, rev uint64, fixed string, next T) error {
	if !storableKeys(id) {
		return wpNotFound(r.what, id, errNoRow)
	}
	var n int64
	// A revision past math.MaxInt64, or a fixed value no row can hold,
	// matches no row.
	if rev < math.MaxInt64 && storableKeys(fixed) {
		data, err := t.encodeOf(id, next)
		if err != nil {
			return wpNotFound(r.what, id, err)
		}
		err = t.d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, r.update, data, revisionArg(rev+1), id, revisionArg(rev), fixed)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return wpNotFound(r.what, id, err)
		}
	}
	if n == 1 {
		return nil
	}
	// Nothing was updated: say why. A row is never deleted, so one found
	// now was there for the UPDATE.
	var revision int64
	var stored string
	err := t.d.db.QueryRowContext(ctx, r.read, id).Scan(&revision, &stored)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return wpNotFound(r.what, id, errNoRow)
	case err != nil:
		return wpNotFound(r.what, id, err)
	case stored != fixed:
		return fmt.Errorf("sqlstore: %s %q: an update can't change its %s", r.what, id, r.fixedName)
	}
	return fmt.Errorf("sqlstore: %s %q: %w", r.what, id, walletprovider.ErrConflict)
}

// List implements walletprovider.InstanceStore: one SELECT … WHERE
// id > ? ORDER BY id LIMIT ?, comparing IDs bytewise.
func (s *InstanceStore) List(ctx context.Context, after string, limit int) ([]walletprovider.Instance, error) {
	out := []walletprovider.Instance{}
	switch {
	case limit <= 0:
		return out, nil
	case !storableKeys(after):
		return nil, fmt.Errorf("sqlstore: list wallet instances: %w", errUnstorableKey)
	}
	rows, err := s.t.d.db.QueryContext(ctx, s.t.d.sql.wpInstanceList, after, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list wallet instances: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, fmt.Errorf("sqlstore: list wallet instances: %w", err)
		}
		in, err := s.t.decodeOf(id, data)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: list wallet instances: %w", err)
		}
		out = append(out, in)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list wallet instances: %w", err)
	}
	return out, nil
}

// instanceKeyRecord is an InstanceKey as an InstanceKeyStore encodes
// it: its Key as the bytes it holds, as instanceRecord keeps an
// Instance's.
type instanceKeyRecord struct {
	walletprovider.InstanceKey
	Key []byte `json:"Key"`
}

// InstanceKeyStore is a walletprovider.InstanceKeyStore:
// walletprovider.Dependencies.InstanceKeys. Each instance key is a row
// keyed by its thumbprint, its record sealed when the DB has a Sealer,
// beside the readable instance_id column, indexed with the thumbprint
// for List. The primary key makes Create's check and store one atomic
// INSERT, so one key belongs to one instance across every process.
// The record holds the key, the instance it belongs to, its status
// list index and its evidence's summary: nothing secret, but which
// instance keys are one instance's is what the provider keeps from
// issuers, so the table is as private as the instances'; sealing keeps
// a database writer from altering a record, or moving it to another
// instance, unnoticed. Update is one UPDATE … WHERE id = ? AND
// revision = ?, on the readable revision column, as InstanceStore's
// is. Records never expire: Sweep leaves them alone, and nothing here
// deletes one.
type InstanceKeyStore struct {
	t *table[walletprovider.InstanceKey]
}

var _ walletprovider.InstanceKeyStore = (*InstanceKeyStore)(nil)

// WalletProviderInstanceKeys returns d's walletprovider.InstanceKeyStore.
func (d *DB) WalletProviderInstanceKeys() *InstanceKeyStore {
	t := &table[walletprovider.InstanceKey]{
		d: d, name: "walletprovider_instance_keys", sql: tableSQL{insert: d.sql.wpInstanceKeyInsert, get: d.sql.wpInstanceKeyGet},
		rowOf: func(k walletprovider.InstanceKey) row {
			return row{extra: []any{k.InstanceID, revisionArg(k.Revision)}}
		},
	}
	t.encode = func(id string, k walletprovider.InstanceKey) ([]byte, error) {
		return d.encodeRecord(t.name, id, instanceKeyRecord{InstanceKey: k, Key: k.Key})
	}
	t.decode = func(id string, data []byte) (walletprovider.InstanceKey, error) {
		var r instanceKeyRecord
		if err := d.decodeRecord(t.name, id, data, &r); err != nil {
			return walletprovider.InstanceKey{}, err
		}
		if r.Thumbprint != id {
			return walletprovider.InstanceKey{}, fmt.Errorf("%w: instance key %q is stored as %q", ErrRecordFormat, r.Thumbprint, id)
		}
		r.InstanceKey.Key = r.Key
		// A record from before migration 0008 has no Revision: its row's
		// is 1.
		r.Revision = max(r.Revision, 1)
		return r.InstanceKey, nil
	}
	return &InstanceKeyStore{t}
}

// Get implements walletprovider.InstanceKeyStore.
func (s *InstanceKeyStore) Get(ctx context.Context, thumbprint string) (walletprovider.InstanceKey, error) {
	k, err := s.t.get(ctx, thumbprint)
	return k, wpNotFound("instance key", thumbprint, err)
}

// Create implements walletprovider.InstanceKeyStore: one INSERT … ON
// CONFLICT DO NOTHING, which inserts nothing, and reports ErrExists, if
// a row holds the key's thumbprint, whatever its instance.
func (s *InstanceKeyStore) Create(ctx context.Context, k walletprovider.InstanceKey) error {
	k.Revision = 1
	return wpNotFound("create instance key", k.Thumbprint, insertNew(s.t, ctx, k.Thumbprint, k))
}

// Update implements walletprovider.InstanceKeyStore: one UPDATE … WHERE
// id = ? AND revision = ? AND instance_id = ?, a compare-and-swap across
// every process sharing the database, which refuses an update moving
// the key to another instance.
func (s *InstanceKeyStore) Update(ctx context.Context, k walletprovider.InstanceKey) error {
	next := k
	next.Revision++
	return updateRevision(ctx, s.t, revisioned{
		what: "update instance key", update: s.t.d.sql.wpInstanceKeyUpdate, read: s.t.d.sql.wpInstanceKeyRevision,
		fixedName: "instance",
	}, k.Thumbprint, k.Revision, k.InstanceID, next)
}

// List implements walletprovider.InstanceKeyStore: one SELECT … WHERE
// instance_id = ? AND id > ? ORDER BY id LIMIT ?, comparing thumbprints
// bytewise, on the (instance_id, id) index. A record whose instance
// isn't its row's instance_id is refused with ErrRecordFormat.
func (s *InstanceKeyStore) List(ctx context.Context, instanceID, after string, limit int) ([]walletprovider.InstanceKey, error) {
	out := []walletprovider.InstanceKey{}
	switch {
	case limit <= 0:
		return out, nil
	case !storableKeys(instanceID, after):
		return nil, fmt.Errorf("sqlstore: list instance keys: %w", errUnstorableKey)
	}
	rows, err := s.t.d.db.QueryContext(ctx, s.t.d.sql.wpInstanceKeyList, instanceID, after, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: list instance keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, fmt.Errorf("sqlstore: list instance keys: %w", err)
		}
		k, err := s.t.decodeOf(id, data)
		if err != nil {
			return nil, fmt.Errorf("sqlstore: list instance keys: %w", err)
		}
		if k.InstanceID != instanceID {
			return nil, fmt.Errorf("sqlstore: list instance keys: %w: instance key %q of instance %q is stored as instance %q's", ErrRecordFormat, id, k.InstanceID, instanceID)
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: list instance keys: %w", err)
	}
	return out, nil
}

// ChallengeStore is a walletprovider.ChallengeStore:
// walletprovider.Dependencies.Challenges. Each challenge is a row keyed
// by its value, its record sealed when the DB has a Sealer. Consume is
// one DELETE … RETURNING, so of concurrent Consumes of one challenge,
// across every process sharing the database, one gets it. The store
// doesn't delete expired challenges itself: Sweep does, after their
// ExpiresAt.
type ChallengeStore struct {
	t *table[walletprovider.ChallengeRecord]
}

var _ walletprovider.ChallengeStore = (*ChallengeStore)(nil)

// WalletProviderChallenges returns d's walletprovider.ChallengeStore.
func (d *DB) WalletProviderChallenges() *ChallengeStore {
	t := &table[walletprovider.ChallengeRecord]{
		d: d, name: "walletprovider_challenges", sql: tableSQL{insert: d.sql.wpChallengeInsert, consume: d.sql.wpChallengeConsume},
		rowOf: func(rec walletprovider.ChallengeRecord) row { return row{sweepAfter: rec.ExpiresAt} },
	}
	t.decode = func(id string, data []byte) (walletprovider.ChallengeRecord, error) {
		var rec walletprovider.ChallengeRecord
		if err := d.decodeRecord(t.name, id, data, &rec); err != nil {
			return rec, err
		}
		if rec.Value != id {
			return walletprovider.ChallengeRecord{}, fmt.Errorf("%w: challenge %q is stored as %q", ErrRecordFormat, rec.Value, id)
		}
		return rec, nil
	}
	return &ChallengeStore{t}
}

// Create implements walletprovider.ChallengeStore: one INSERT … ON
// CONFLICT DO NOTHING, which inserts nothing, and reports ErrExists, if
// the value is stored.
func (s *ChallengeStore) Create(ctx context.Context, rec walletprovider.ChallengeRecord) error {
	if err := insertNew(s.t, ctx, rec.Value, rec); err != nil {
		return fmt.Errorf("sqlstore: create challenge: %w", err)
	}
	return nil
}

// Consume implements walletprovider.ChallengeStore: one DELETE …
// RETURNING.
func (s *ChallengeStore) Consume(ctx context.Context, value string) (walletprovider.ChallengeRecord, error) {
	rec, err := s.t.consume(ctx, value)
	switch {
	case errors.Is(err, errNoRow):
		return walletprovider.ChallengeRecord{}, fmt.Errorf("sqlstore: challenge: %w", walletprovider.ErrNotFound)
	case err != nil:
		return walletprovider.ChallengeRecord{}, fmt.Errorf("sqlstore: consume challenge: %w", err)
	}
	return rec, nil
}

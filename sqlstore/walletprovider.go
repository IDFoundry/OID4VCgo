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
	id := in.ID
	if !storableKeys(id) {
		return wpNotFound("update wallet instance", id, errNoRow)
	}
	var n int64
	// A revision past math.MaxInt64, or a key thumbprint no row can
	// hold, matches no row.
	if in.Revision < math.MaxInt64 && storableKeys(in.KeyThumbprint) {
		next := in
		next.Revision++
		data, err := s.t.encodeOf(id, next)
		if err != nil {
			return wpNotFound("update wallet instance", id, err)
		}
		err = s.t.d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, s.t.d.sql.wpInstanceUpdate,
				data, revisionArg(next.Revision), id, revisionArg(in.Revision), in.KeyThumbprint)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return wpNotFound("update wallet instance", id, err)
		}
	}
	if n == 1 {
		return nil
	}
	// Nothing was updated: say why. A row is never deleted, so one found
	// now was there for the UPDATE.
	var revision int64
	var thumbprint string
	err := s.t.d.db.QueryRowContext(ctx, s.t.d.sql.wpInstanceRevision, id).Scan(&revision, &thumbprint)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return wpNotFound("update wallet instance", id, errNoRow)
	case err != nil:
		return wpNotFound("update wallet instance", id, err)
	case thumbprint != in.KeyThumbprint:
		return fmt.Errorf("sqlstore: update wallet instance %q: an update can't change an instance's key thumbprint", id)
	}
	return fmt.Errorf("sqlstore: update wallet instance %q: %w", id, walletprovider.ErrConflict)
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

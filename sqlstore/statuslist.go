package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// errUnstorableIndex is what StatusIndexStore.Reserve returns for an
// index above math.MaxInt64, which a BIGINT column can't hold.
var errUnstorableIndex = errors.New("sqlstore: a status list index must be at most 2^63-1")

// StatusIndexStore is a statuslist.IndexStore: statuslist.Allocator's
// Store. It keeps one row per index an Allocator has handed out, keyed
// by the list's uri and the index, with the index's status, and a count
// of each list's rows. An index once handed out stays reserved while
// its list is in use: Sweep never frees one, and only Delete deletes a
// whole list's rows, once the list is retired. Statuses aren't secret —
// a Status List publishes them — so the rows aren't sealed.
//
// Reserve is one INSERT … ON CONFLICT DO NOTHING on the (uri, idx)
// primary key: of concurrent Reserves of one index, across every
// process sharing the database, exactly one inserts the row, and the
// others find it taken. A uri that isn't valid UTF-8, or holds a NUL
// byte, is never stored, nor an index above math.MaxInt64, which a
// BIGINT can't hold: Reserve refuses either, and every other method
// finds no such index reserved. A list's indices are far fewer.
type StatusIndexStore struct{ d *DB }

var _ statuslist.IndexStore = (*StatusIndexStore)(nil)

// StatusIndices returns d's statuslist.IndexStore.
func (d *DB) StatusIndices() *StatusIndexStore { return &StatusIndexStore{d} }

// storableIndex reports whether uri and idx can be stored.
func storableIndex(uri string, idx uint64) bool {
	return idx <= math.MaxInt64 && storableKeys(uri)
}

// Reserve implements statuslist.IndexStore: one INSERT, which inserts
// nothing, and reports statuslist.ErrIndexTaken, if idx is reserved.
func (s *StatusIndexStore) Reserve(ctx context.Context, uri string, idx uint64) error {
	switch {
	case !storableKeys(uri):
		return errUnstorableKey
	case idx > math.MaxInt64:
		return errUnstorableIndex
	}
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.sql.statusIndexReserve, uri, indexArg(idx))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return fmt.Errorf("sqlstore: reserve index %d of %s: %w", idx, uri, err)
	case n == 0:
		return fmt.Errorf("sqlstore: index %d of %s: %w", idx, uri, statuslist.ErrIndexTaken)
	}
	return nil
}

// Reserved implements statuslist.IndexStore. It reads the list's
// count, which a trigger keeps as each reservation is inserted, rather
// than counting rows: statuslist.Allocator calls it on every Allocate.
func (s *StatusIndexStore) Reserved(ctx context.Context, uri string) (int, error) {
	if !storableKeys(uri) {
		return 0, nil
	}
	var n int64
	if err := s.d.db.QueryRowContext(ctx, s.d.sql.statusIndexCount, uri).Scan(&n); err != nil {
		return 0, fmt.Errorf("sqlstore: count the reserved indices of %s: %w", uri, err)
	}
	return int(n), nil
}

// SetStatus implements statuslist.IndexStore: one UPDATE.
func (s *StatusIndexStore) SetStatus(ctx context.Context, uri string, idx uint64, status statuslist.StatusType) error {
	if !storableIndex(uri, idx) {
		return notReserved(uri, idx)
	}
	var n int64
	err := s.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, s.d.sql.statusIndexSet, int64(status), uri, indexArg(idx))
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return fmt.Errorf("sqlstore: set the status of index %d of %s: %w", idx, uri, err)
	case n == 0:
		return notReserved(uri, idx)
	}
	return nil
}

// Status implements statuslist.IndexStore. With an error, it returns
// statuslist.StatusInvalid, as statuslist.MemoryIndexStore does.
func (s *StatusIndexStore) Status(ctx context.Context, uri string, idx uint64) (statuslist.StatusType, error) {
	if !storableIndex(uri, idx) {
		return statuslist.StatusInvalid, notReserved(uri, idx)
	}
	var status int64
	switch err := s.d.db.QueryRowContext(ctx, s.d.sql.statusIndexGet, uri, indexArg(idx)).Scan(&status); {
	case errors.Is(err, sql.ErrNoRows):
		return statuslist.StatusInvalid, notReserved(uri, idx)
	case err != nil:
		return statuslist.StatusInvalid, fmt.Errorf("sqlstore: read the status of index %d of %s: %w", idx, uri, err)
	case status < 0 || status > math.MaxUint8:
		return statuslist.StatusInvalid, fmt.Errorf("sqlstore: index %d of %s has status %d, not a byte", idx, uri, status)
	}
	return statuslist.StatusType(status), nil
}

// Statuses implements statuslist.IndexStore. It reads only the rows
// it needs to: those with a status other than StatusValid, through an
// index that holds only those, and any outside the list, which it
// refuses.
func (s *StatusIndexStore) Statuses(ctx context.Context, uri string, size int) ([]uint8, error) {
	if size < 0 {
		return nil, fmt.Errorf("sqlstore: list size %d is negative", size)
	}
	statuses := make([]uint8, size)
	if !storableKeys(uri) {
		return statuses, nil
	}
	rows, err := s.d.db.QueryContext(ctx, s.d.sql.statusIndexList, uri, uri, int64(size))
	if err != nil {
		return nil, fmt.Errorf("sqlstore: read the statuses of %s: %w", uri, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var idx, status int64
		if err := rows.Scan(&idx, &status); err != nil {
			return nil, fmt.Errorf("sqlstore: read the statuses of %s: %w", uri, err)
		}
		switch {
		case idx < 0 || idx >= int64(size):
			return nil, fmt.Errorf("sqlstore: index %d of %s is reserved, outside its %d indices", idx, uri, size)
		case status < 0 || status > math.MaxUint8:
			return nil, fmt.Errorf("sqlstore: index %d of %s has status %d, not a byte", idx, uri, status)
		}
		statuses[idx] = uint8(status)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlstore: read the statuses of %s: %w", uri, err)
	}
	return statuses, nil
}

// deleteBatch is how many of a list's rows each of Delete's writes
// deletes.
const deleteBatch = 10000

// Delete implements statuslist.IndexStore. A list may hold millions of
// rows, so it deletes them in batches of deleteBatch, each its own
// write that holds no lock for long, then the list's count. Reserved
// counts the list's indices until that last write, so a Delete that
// fails part-way still finds the list, and another finishes it.
func (s *StatusIndexStore) Delete(ctx context.Context, uri string) error {
	if !storableKeys(uri) {
		return nil
	}
	for {
		var n int64
		err := s.d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, s.d.sql.statusIndexDeleteBatch, uri, uri, deleteBatch)
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		if err != nil {
			return fmt.Errorf("sqlstore: delete the indices of %s: %w", uri, err)
		}
		if n < deleteBatch {
			break
		}
	}
	err := s.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, s.d.sql.statusIndexDeleteCount, uri)
		return err
	})
	if err != nil {
		return fmt.Errorf("sqlstore: delete the count of %s: %w", uri, err)
	}
	return nil
}

// indexArg is idx as a BIGINT argument. Every caller has checked
// idx <= math.MaxInt64 (storableIndex).
func indexArg(idx uint64) int64 {
	return int64(idx) // #nosec G115 -- the callers refuse an idx above math.MaxInt64
}

// notReserved is statuslist.ErrIndexNotReserved for idx of uri.
func notReserved(uri string, idx uint64) error {
	return fmt.Errorf("sqlstore: index %d of %s: %w", idx, uri, statuslist.ErrIndexNotReserved)
}

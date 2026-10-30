package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// errNoRow is what a table's methods return, wrapped, for a key with no
// row: each store turns it into its interface's own not-found error.
var errNoRow = errors.New("no such record")

// row is what a table keeps of a record beside its encoding: the
// columns a store looks it up or sweeps it by.
type row struct {
	owner      string
	sweepAfter time.Time
	// extra are the values of the table's extra columns, in the order
	// its insert and update statements name them.
	extra []any
}

// tableSQL are a table's statements, from the DB's queries: those the
// table's store doesn't use are empty. Each writing statement names the
// columns id, owner, sweep_after and record, then the table's extra
// columns, in that order: insert and upsert from id, update from owner,
// with id last.
type tableSQL struct {
	insert, upsert        string
	get, getForUpdate     string
	update, list, consume string
	delete                string
}

// table is one of a DB's record tables: each row is a record of type T,
// keyed by id, with the owner, sweep_after and record columns every
// table has, and the table's own extra columns.
type table[T any] struct {
	d *DB
	// name is the table's name without its oid4vc_ prefix, which a
	// sealed record is bound to.
	name string
	sql  tableSQL
	// encode and decode turn a record into its record column and back;
	// nil means the DB's own (encodeRecord, decodeRecord).
	encode func(id string, v T) ([]byte, error)
	decode func(id string, data []byte) (T, error)
	// rowOf is what the table keeps of v beside its encoding.
	rowOf func(v T) row
}

func (t *table[T]) encodeOf(id string, v T) ([]byte, error) {
	if t.encode != nil {
		return t.encode(id, v)
	}
	return t.d.encodeRecord(t.name, id, v)
}

func (t *table[T]) decodeOf(id string, data []byte) (T, error) {
	if t.decode != nil {
		return t.decode(id, data)
	}
	var v T
	err := t.d.decodeRecord(t.name, id, data, &v)
	return v, err
}

// values are the column values for v, from owner on, in the order the
// table's statements name them.
func (t *table[T]) values(id string, v T) ([]any, error) {
	data, err := t.encodeOf(id, v)
	if err != nil {
		return nil, err
	}
	r := t.rowOf(v)
	return append([]any{r.owner, unixSeconds(r.sweepAfter), data}, r.extra...), nil
}

// insert saves v under id, which must be unused.
func (t *table[T]) insert(ctx context.Context, id string, v T) error {
	vals, err := t.values(id, v)
	if err != nil {
		return err
	}
	return t.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, t.sql.insert, append([]any{id}, vals...)...)
		return err
	})
}

// put saves v under id, replacing any row there.
func (t *table[T]) put(ctx context.Context, id string, v T) error {
	vals, err := t.values(id, v)
	if err != nil {
		return err
	}
	return t.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, t.sql.upsert, append([]any{id}, vals...)...)
		return err
	})
}

// get returns the record keyed by id, or errNoRow.
func (t *table[T]) get(ctx context.Context, id string) (T, error) {
	return t.scanRecord(id, t.d.db.QueryRowContext(ctx, t.sql.get, id))
}

// scanRecord is the record r, a row of one record column, holds for id,
// or errNoRow.
func (t *table[T]) scanRecord(id string, r *sql.Row) (T, error) {
	var data []byte
	if err := r.Scan(&data); err != nil {
		var zero T
		if errors.Is(err, sql.ErrNoRows) {
			return zero, errNoRow
		}
		return zero, err
	}
	return t.decodeOf(id, data)
}

// list returns every record, ordered by id.
func (t *table[T]) list(ctx context.Context) ([]T, error) {
	rows, err := t.d.db.QueryContext(ctx, t.sql.list)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []T{}
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		v, err := t.decodeOf(id, data)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// remove deletes the row keyed by id, reporting whether there was one.
func (t *table[T]) remove(ctx context.Context, id string) (bool, error) {
	var n int64
	err := t.d.writeOne(ctx, func(q querier) error {
		res, err := q.ExecContext(ctx, t.sql.delete, id)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n > 0, err
}

// consume deletes the row keyed by id (and by more, where the table's
// consume statement takes more), returning its record: of concurrent
// calls, one gets it, and the others errNoRow.
func (t *table[T]) consume(ctx context.Context, id string, more ...any) (T, error) {
	var v T
	err := t.d.writeOne(ctx, func(q querier) error {
		var err error
		v, err = t.scanRecord(id, q.QueryRowContext(ctx, t.sql.consume, append([]any{id}, more...)...))
		return err
	})
	return v, err
}

// update loads the record keyed by id, locked, calls fn on it and saves
// the result, in one transaction: concurrent updates of one record run
// one after another. fn's error aborts it, saving nothing. idOf, if
// set, is the record's own ID, which fn mustn't change.
func (t *table[T]) update(ctx context.Context, id string, fn func(*T) error, idOf func(T) string) error {
	return t.d.write(ctx, func(q querier) error {
		cur, err := t.scanRecord(id, q.QueryRowContext(ctx, t.sql.getForUpdate, id))
		if err != nil {
			return err
		}
		if err := fn(&cur); err != nil {
			return err
		}
		if idOf != nil && idOf(cur) != id {
			return fmt.Errorf("sqlstore: an update changed %s record %q's ID", t.name, id)
		}
		vals, err := t.values(id, cur)
		if err != nil {
			return err
		}
		_, err = q.ExecContext(ctx, t.sql.update, append(vals, id)...)
		return err
	})
}

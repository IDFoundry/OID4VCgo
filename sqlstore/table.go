package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
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
	// extra are the values of the table's extra columns, in order.
	extra []any
}

// table is one of a DB's record tables: each row is a record of type T,
// keyed by id, with the owner, sweep_after and record columns every
// table has, and the table's own extra columns.
type table[T any] struct {
	d    *DB
	name string
	// extra names the table's own columns, written from row.extra.
	extra []string
	// encode and decode turn a record into its record column and back;
	// nil means the DB's own (encodeRecord, decodeRecord).
	encode func(id string, v T) ([]byte, error)
	decode func(id string, data []byte) (T, error)
	// rowOf is what the table keeps of v beside its encoding.
	rowOf func(v T) row
}

// Statement templates for any table: {T} is the table's name.
const (
	sqlByID         = " WHERE id = ?"
	sqlSelectRecord = "SELECT record FROM {T}" + sqlByID
	sqlSelectAll    = "SELECT id, record FROM {T} ORDER BY id"
	sqlDeleteByID   = "DELETE FROM {T}" + sqlByID
)

// stmt is template as the dialect's statement on t's table.
func (t *table[T]) stmt(template string) string {
	return t.d.q(strings.ReplaceAll(template, "{T}", "{"+t.name+"}"))
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

// columns lists the columns written on insert, after id.
func (t *table[T]) columns() []string {
	return append([]string{"owner", "sweep_after", "record"}, t.extra...)
}

// values are the column values for v keyed by id, in columns' order.
func (t *table[T]) values(id string, v T) ([]any, error) {
	data, err := t.encodeOf(id, v)
	if err != nil {
		return nil, err
	}
	r := t.rowOf(v)
	if len(r.extra) != len(t.extra) {
		return nil, fmt.Errorf("sqlstore: %s: %d extra values for %d columns", t.name, len(r.extra), len(t.extra))
	}
	return append([]any{r.owner, unixSeconds(r.sweepAfter), data}, r.extra...), nil
}

// insertQuery inserts a row, failing if its id is taken; with upsert,
// it replaces the row instead.
func (t *table[T]) insertQuery(upsert bool) string {
	cols := t.columns()
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(cols)+1), ", ")
	query := "INSERT INTO {" + t.name + "} (id, " + strings.Join(cols, ", ") + ") VALUES (" + marks + ")"
	if upsert {
		sets := make([]string, len(cols))
		for i, c := range cols {
			sets[i] = c + " = excluded." + c
		}
		query += " ON CONFLICT (id) DO UPDATE SET " + strings.Join(sets, ", ")
	}
	return t.d.q(query)
}

// insert saves v under id, which must be unused.
func (t *table[T]) insert(ctx context.Context, id string, v T) error {
	return t.save(ctx, id, v, false)
}

// put saves v under id, replacing any row there.
func (t *table[T]) put(ctx context.Context, id string, v T) error {
	return t.save(ctx, id, v, true)
}

func (t *table[T]) save(ctx context.Context, id string, v T, upsert bool) error {
	vals, err := t.values(id, v)
	if err != nil {
		return err
	}
	return t.d.writeOne(ctx, func(q querier) error {
		_, err := q.ExecContext(ctx, t.insertQuery(upsert), append([]any{id}, vals...)...)
		return err
	})
}

// get returns the record keyed by id, or errNoRow.
func (t *table[T]) get(ctx context.Context, id string) (T, error) {
	return t.getOn(ctx, t.d.db, id, false)
}

// getOn is get on q, locking the row for q's transaction when lock is
// set.
func (t *table[T]) getOn(ctx context.Context, q querier, id string, lock bool) (T, error) {
	query := t.stmt(sqlSelectRecord)
	if lock {
		query += t.d.forUpdate()
	}
	var data []byte
	if err := q.QueryRowContext(ctx, query, id).Scan(&data); err != nil {
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
	rows, err := t.d.db.QueryContext(ctx, t.stmt(sqlSelectAll))
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
		res, err := q.ExecContext(ctx, t.stmt(sqlDeleteByID), id)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return n > 0, err
}

// consume deletes the row keyed by id, and owner too when ownerMatch,
// returning its record: of concurrent calls, one gets it, and the
// others errNoRow.
func (t *table[T]) consume(ctx context.Context, id string, ownerMatch bool, owner string) (T, error) {
	query := sqlDeleteByID
	args := []any{id}
	if ownerMatch {
		query += " AND owner = ?"
		args = append(args, owner)
	}
	var data []byte
	err := t.d.writeOne(ctx, func(q querier) error {
		return q.QueryRowContext(ctx, t.stmt(query+" RETURNING record"), args...).Scan(&data)
	})
	if err != nil {
		var zero T
		if errors.Is(err, sql.ErrNoRows) {
			return zero, errNoRow
		}
		return zero, err
	}
	return t.decodeOf(id, data)
}

// update loads the record keyed by id, locked, calls fn on it and saves
// the result, in one transaction: concurrent updates of one record run
// one after another. fn's error aborts it, saving nothing. idOf, if
// set, is the record's own ID, which fn mustn't change.
func (t *table[T]) update(ctx context.Context, id string, fn func(*T) error, idOf func(T) string) error {
	return t.d.write(ctx, func(q querier) error {
		cur, err := t.getOn(ctx, q, id, true)
		if err != nil {
			return err
		}
		if err := fn(&cur); err != nil {
			return err
		}
		if idOf != nil && idOf(cur) != id {
			return fmt.Errorf("sqlstore: an update changed %s record %q's ID", t.name, id)
		}
		return t.replaceOn(ctx, q, id, cur)
	})
}

// replaceOn overwrites the row keyed by id with v, on q.
func (t *table[T]) replaceOn(ctx context.Context, q querier, id string, v T) error {
	vals, err := t.values(id, v)
	if err != nil {
		return err
	}
	cols := t.columns()
	sets := make([]string, len(cols))
	for i, c := range cols {
		sets[i] = c + " = ?"
	}
	_, err = q.ExecContext(ctx, t.stmt("UPDATE {T} SET "+strings.Join(sets, ", ")+sqlByID), append(vals, id)...)
	return err
}

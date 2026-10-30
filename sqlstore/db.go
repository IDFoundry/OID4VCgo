package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialect is the SQL database a DB talks to.
type Dialect int

const (
	_ Dialect = iota

	// Postgres is PostgreSQL, 13 or later, through any database/sql
	// driver (github.com/jackc/pgx/v5/stdlib, say). A transaction locks
	// the rows it changes with SELECT … FOR UPDATE.
	Postgres

	// SQLite is SQLite, 3.35 or later, through any database/sql driver
	// (modernc.org/sqlite, say, which needs no cgo). A transaction
	// starts with BEGIN IMMEDIATE, taking the database's write lock up
	// front, after setting the connection's busy timeout to 10 seconds.
	// Open it in WAL mode — see the package documentation.
	SQLite
)

// String names d.
func (d Dialect) String() string {
	switch d {
	case Postgres:
		return "postgres"
	case SQLite:
		return "sqlite"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

// Options configures a DB.
type Options struct {
	// Sealer, if set, seals every record the issuer and walletflow stores
	// write (an AEAD such as verifier.AESGCMSealer, with a key kept
	// outside the database), each bound to its table and key, so a copy
	// of the database reveals none of their contents and a record can't
	// be moved to another key. The columns a store looks records up or
	// sweeps them by stay readable: keys, Owners, the pre-authorized
	// code's Transaction Code hash and expiry times. The verifier's
	// TransactionStore is sealed by its own TransactionCodec instead.
	//
	// A DB with a Sealer refuses records written without one, and one
	// without a Sealer those written with one. KeyStore requires it.
	Sealer Sealer
}

// DB holds the issuer, verifier and walletflow stores' tables in one
// SQL database. Make one with New, create its tables with Migrate, and
// take its stores from its methods. It's safe for concurrent use.
type DB struct {
	db      *sql.DB
	dialect Dialect
	// sql is the dialect's statements.
	sql    *queries
	sealer Sealer

	// sqliteWrites serializes this DB's own SQLite transactions, which
	// would otherwise only wait on SQLite's busy handler for each other.
	// Other processes, and other DBs on the same file, still do.
	sqliteWrites sync.Mutex
}

// New returns a DB using db, a database of dialect. It doesn't touch the
// database: call Migrate, from a deployment step or at startup, before
// using its stores.
func New(db *sql.DB, dialect Dialect, opts Options) (*DB, error) {
	if db == nil {
		return nil, errors.New("sqlstore: nil *sql.DB")
	}
	if dialect != Postgres && dialect != SQLite {
		return nil, fmt.Errorf("sqlstore: unknown dialect %v", dialect)
	}
	q := &postgresQueries
	if dialect == SQLite {
		q = &sqliteQueries
	}
	return &DB{db: db, dialect: dialect, sql: q, sealer: opts.Sealer}, nil
}

// Dialect is the database's dialect.
func (d *DB) Dialect() Dialect { return d.dialect }

// querier is what a store runs its statements on: the *sql.DB itself,
// or a transaction's *sql.Tx or *sql.Conn.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// write runs fn in a transaction that holds the write lock on whatever
// rows fn locks (Postgres) or on the database (SQLite), committing it
// if fn returns nil and rolling it back otherwise.
func (d *DB) write(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.sqliteWrite(ctx, fn)
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// writeOne runs fn, which makes one change in one statement: on the
// database itself for Postgres, where a statement is atomic, and as
// write does for SQLite, which then waits its busy timeout for the
// write lock.
func (d *DB) writeOne(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.sqliteWrite(ctx, fn)
	}
	return fn(d.db)
}

// sqliteWrite is write for SQLite. database/sql's BeginTx can't ask for
// BEGIN IMMEDIATE, so this takes a connection and issues the
// transaction's statements itself.
func (d *DB) sqliteWrite(ctx context.Context, fn func(q querier) error) (err error) {
	d.sqliteWrites.Lock()
	defer d.sqliteWrites.Unlock()
	conn, err := d.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			// Never hand the pool a connection still in a transaction.
			if _, rbErr := conn.ExecContext(context.WithoutCancel(ctx), sqliteRollback); rbErr != nil && !noTransaction(rbErr) {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
		_ = conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, sqliteBusyTimeout); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, sqliteBegin); err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, sqliteCommit)
	return err
}

// noTransaction reports whether err is SQLite's answer to a ROLLBACK
// with no transaction open: BEGIN failed, or COMMIT already ended it.
func noTransaction(err error) bool {
	return strings.Contains(err.Error(), "no transaction is active")
}

// unixSeconds is t as a column a Sweep compares, or NULL for zero.
func unixSeconds(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

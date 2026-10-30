package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"regexp"
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
	// front. Open it with a busy timeout and in WAL mode — see the
	// package documentation.
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
	// TablePrefix is put before every table name, so several DBs — or
	// another application's tables — can share one database or schema:
	// lower-case letters, digits and underscores, starting with a letter,
	// at most 32 characters. Empty means "oid4vc_".
	TablePrefix string

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

	// SQLiteBusyTimeout is how long a SQLite transaction waits for
	// another connection's write lock before failing. Zero means 10
	// seconds. Ignored for Postgres.
	SQLiteBusyTimeout time.Duration
}

// DB holds the issuer, verifier and walletflow stores' tables in one
// SQL database. Make one with New, create its tables with Migrate, and
// take its stores from its methods. It's safe for concurrent use.
type DB struct {
	db      *sql.DB
	dialect Dialect
	prefix  string
	sealer  Sealer
	busy    time.Duration
	// busyPragma sets busy on a SQLite connection.
	busyPragma string

	// sqliteWrites serializes this DB's own SQLite transactions, which
	// would otherwise only wait on SQLite's busy handler for each other.
	// Other processes, and other DBs on the same file, still do.
	sqliteWrites sync.Mutex

	queries sync.Map // query template → the dialect's query
}

const defaultTablePrefix = "oid4vc_"

var tablePrefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

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
	prefix := opts.TablePrefix
	if prefix == "" {
		prefix = defaultTablePrefix
	}
	if !tablePrefixPattern.MatchString(prefix) {
		return nil, fmt.Errorf("sqlstore: table prefix %q must be lower-case letters, digits and underscores, starting with a letter, at most 32 characters", prefix)
	}
	busy := opts.SQLiteBusyTimeout
	if busy == 0 {
		busy = 10 * time.Second
	}
	if busy < 0 {
		return nil, errors.New("sqlstore: negative SQLiteBusyTimeout")
	}
	return &DB{db: db, dialect: dialect, prefix: prefix, sealer: opts.Sealer, busy: busy,
		busyPragma: "PRAGMA busy_timeout = " + strconv.FormatInt(busy.Milliseconds(), 10)}, nil
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

// q turns template into the dialect's query: each {name} becomes the
// prefixed table name, and each ? a Postgres $n placeholder.
func (d *DB) q(template string) string {
	if v, ok := d.queries.Load(template); ok {
		return v.(string)
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(template); i++ {
		switch c := template[i]; {
		case c == '{':
			end := strings.IndexByte(template[i:], '}')
			b.WriteString(d.prefix)
			b.WriteString(template[i+1 : i+end])
			i += end
		case c == '?' && d.dialect == Postgres:
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	query := b.String()
	d.queries.Store(template, query)
	return query
}

// forUpdate is what a SELECT that locks its rows for the rest of the
// transaction ends with: SQLite's BEGIN IMMEDIATE has already locked
// the whole database.
func (d *DB) forUpdate() string {
	if d.dialect == Postgres {
		return " FOR UPDATE"
	}
	return ""
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
			if _, rbErr := conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK"); rbErr != nil && !noTransaction(rbErr) {
				_ = conn.Raw(func(any) error { return driver.ErrBadConn })
			}
		}
		_ = conn.Close()
	}()
	if _, err := conn.ExecContext(ctx, d.busyPragma); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if err := fn(conn); err != nil {
		return err
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
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

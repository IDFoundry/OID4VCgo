package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Dialect is the SQL database a DB talks to.
type Dialect int

const (
	_ Dialect = iota

	// Postgres is PostgreSQL, 13 or later, through any database/sql
	// driver (github.com/jackc/pgx/v5/stdlib, say). A transaction runs
	// at READ COMMITTED, whatever the server's default, and locks the
	// rows it changes with SELECT … FOR UPDATE. A write of one statement
	// gets READ COMMITTED's outcome too: where a stricter default
	// isolation fails it with a serialization error (SQLSTATE 40001), it
	// runs again in a READ COMMITTED transaction.
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
	// Sealer, if set, seals every record the issuer, walletflow and
	// walletprovider stores write (an AEAD such as sealing.AESGCMSealer,
	// with a key kept outside the database), each bound to its table and
	// key, so a copy of the database reveals none of their contents and a
	// record can't be moved to another key. The columns a store looks
	// records up or sweeps them by stay readable: keys, Owners, the
	// pre-authorized code's Transaction Code hash, a wallet instance's key
	// thumbprint and revision, and expiry times. The verifier's
	// TransactionStore is sealed by its own TransactionCodec instead.
	//
	// A DB with a Sealer refuses records written without one, and one
	// without a Sealer those written with one. KeyStore requires it.
	Sealer Sealer
}

// DB holds the issuer, verifier, walletflow, statuslist and
// walletprovider stores' tables in one SQL database. Make one with New,
// create its tables with Migrate, and take its stores from its methods. It's safe for concurrent use.
type DB struct {
	db      *sql.DB
	dialect Dialect
	// sql is the dialect's statements.
	sql    *queries
	sealer Sealer

	// sqliteWrites serializes this DB's own SQLite transactions, which
	// would otherwise only wait on SQLite's busy handler for each other:
	// a write holds its one slot. Other processes, and other DBs on the
	// same file, still wait on the busy handler.
	sqliteWrites chan struct{}

	// pinIsolation is whether every Postgres write, single statements
	// included, runs in a READ COMMITTED transaction: Migrate or
	// CheckSchema found the database's default isolation level isn't
	// READ COMMITTED (see writeOne).
	pinIsolation atomic.Bool
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
	return &DB{db: db, dialect: dialect, sql: q, sealer: opts.Sealer, sqliteWrites: make(chan struct{}, 1)}, nil
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

// postgresTx is a Postgres write's transaction: READ COMMITTED, as the
// stores' locking assumes, whatever the server's
// default_transaction_isolation says. The SELECT … FOR UPDATE each
// takes makes a row's concurrent writers run one after another; at a
// stricter level, the later one would fail with a serialization error
// instead of seeing the earlier one's change.
var postgresTx = &sql.TxOptions{Isolation: sql.LevelReadCommitted}

// write runs fn in a transaction that holds the write lock on whatever
// rows fn locks (Postgres) or on the database (SQLite), committing it
// if fn returns nil and rolling it back otherwise.
func (d *DB) write(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.sqliteWrite(ctx, fn)
	}
	tx, err := d.db.BeginTx(ctx, postgresTx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// writeOne runs fn, which makes one change in one statement, with
// write's guarantees. On SQLite it is write, which waits its busy
// timeout for the write lock. On Postgres the statement runs on its
// own, in the implicit transaction PostgreSQL gives it, saving BEGIN
// and COMMIT's round trips: one statement is atomic at every isolation
// level, and at READ COMMITTED one that waits on a row a concurrent
// transaction changes re-checks its WHERE against the row as committed,
// so a lost compare-and-swap or consume gets its typed outcome. At
// REPEATABLE READ or SERIALIZABLE — a database's, role's or
// connection's default_transaction_isolation — it fails instead with a
// serialization error (SQLSTATE 40001), having changed nothing, and fn
// runs again in write's READ COMMITTED transaction, where it gets the
// outcome it would have had there all along. Once Migrate or
// CheckSchema has found the database's default isn't READ COMMITTED,
// every statement runs in write's transaction from the start
// (pinIsolation), which needs no rerun, so that holds too with a driver
// whose errors don't report their SQLSTATE. fn may run twice: it must
// set whatever it reports afresh each time.
func (d *DB) writeOne(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite || d.pinIsolation.Load() {
		return d.write(ctx, fn)
	}
	err := fn(d.db)
	if sqlState(err) == serializationFailure {
		return d.write(ctx, fn)
	}
	return err
}

// The SQLSTATE codes of PostgreSQL's errors the stores act on.
const (
	serializationFailure = "40001"
	deadlockDetected     = "40P01"
)

// sqlState is err's SQLSTATE, as a driver reports it — pgx's
// *pgconn.PgError and lib/pq's *pq.Error each have a SQLState method —
// or the empty string.
func sqlState(err error) string {
	var coded interface{ SQLState() string }
	if errors.As(err, &coded) {
		return coded.SQLState()
	}
	return ""
}

// checkIsolation sets pinIsolation unless the database's default
// isolation level, as a connection of d's pool reports it, is READ
// COMMITTED. Postgres only.
func (d *DB) checkIsolation(ctx context.Context) error {
	if d.dialect != Postgres {
		return nil
	}
	var level string
	if err := d.db.QueryRowContext(ctx, "SHOW default_transaction_isolation").Scan(&level); err != nil {
		return fmt.Errorf("read the default transaction isolation: %w", err)
	}
	d.pinIsolation.Store(!strings.EqualFold(level, "read committed"))
	return nil
}

// sqliteWrite is write for SQLite. database/sql's BeginTx can't ask for
// BEGIN IMMEDIATE, so this takes a connection and issues the
// transaction's statements itself.
func (d *DB) sqliteWrite(ctx context.Context, fn func(q querier) error) (err error) {
	select {
	case d.sqliteWrites <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-d.sqliteWrites }()
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

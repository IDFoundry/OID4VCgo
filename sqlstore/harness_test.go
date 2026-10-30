package sqlstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"

	"github.com/idfoundry/oid4vcgo/sqlstore"
)

// postgresDSNEnv names the environment variable holding a PostgreSQL
// DSN (a postgres:// URL) the tests run against too; without it they
// run against SQLite alone.
const postgresDSNEnv = "SQLSTORE_POSTGRES_DSN"

// postgresDSN is postgresDSNEnv's DSN, its search_path set to a schema
// of this test run's own (TestMain), or "".
var postgresDSN string

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	base := os.Getenv(postgresDSNEnv)
	if base == "" {
		return m.Run()
	}
	schema := "sqlstore_test_" + randomHex(6)
	admin, err := sql.Open("pgx", base)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open postgres:", err)
		return 1
	}
	defer admin.Close()
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		fmt.Fprintln(os.Stderr, "create schema:", err)
		return 1
	}
	defer func() { _, _ = admin.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE") }()
	u, err := url.Parse(base)
	if err != nil {
		fmt.Fprintln(os.Stderr, postgresDSNEnv+":", err)
		return 1
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	postgresDSN = u.String()
	return m.Run()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dialects are the databases the tests run against: SQLite always,
// PostgreSQL with postgresDSNEnv set.
func dialects() []sqlstore.Dialect {
	if postgresDSN != "" {
		return []sqlstore.Dialect{sqlstore.SQLite, sqlstore.Postgres}
	}
	return []sqlstore.Dialect{sqlstore.SQLite}
}

// forEachDialect runs fn as a subtest for each dialect, with an env.
func forEachDialect(t *testing.T, fn func(t *testing.T, e *env)) {
	t.Helper()
	for _, dialect := range dialects() {
		t.Run(dialect.String(), func(t *testing.T) {
			e := &env{t: t, dialect: dialect}
			t.Cleanup(e.closeAll)
			fn(t, e)
		})
	}
}

// env makes empty storages — a SQLite file, or a table prefix of their
// own in the test run's Postgres schema — and handles on them.
type env struct {
	t       *testing.T
	dialect sqlstore.Dialect
	opts    sqlstore.Options

	mu   sync.Mutex
	open []*sql.DB
}

// closeAll closes every handle e opened.
func (e *env) closeAll() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, db := range e.open {
		_ = db.Close()
	}
	e.open = nil
}

// storage makes a fresh, migrated storage, closing the handles on the
// ones before it (the contract suites use one at a time), and returns
// an opener of handles on it: each call opens a new *sql.DB, as another
// process would.
func (e *env) storage() func() *sqlstore.DB {
	e.t.Helper()
	e.closeAll()
	var dsn, driver string
	opts := e.opts
	switch e.dialect {
	case sqlstore.SQLite:
		driver = "sqlite"
		dsn = "file:" + filepath.Join(e.t.TempDir(), "store.db") + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	case sqlstore.Postgres:
		driver, dsn = "pgx", postgresDSN
		opts.TablePrefix = "t" + randomHex(4) + "_"
	}
	open := func() *sqlstore.DB {
		e.t.Helper()
		db, err := sql.Open(driver, dsn)
		if err != nil {
			e.t.Fatalf("open %s: %v", e.dialect, err)
		}
		// No idle connections kept: the contracts open many handles.
		db.SetMaxIdleConns(0)
		if e.dialect == sqlstore.Postgres {
			db.SetMaxOpenConns(4)
		}
		e.mu.Lock()
		e.open = append(e.open, db)
		e.mu.Unlock()
		d, err := sqlstore.New(db, e.dialect, opts)
		if err != nil {
			e.t.Fatalf("sqlstore.New: %v", err)
		}
		return d
	}
	first := open()
	if err := first.Migrate(context.Background()); err != nil {
		e.t.Fatalf("Migrate: %v", err)
	}
	var firstMu sync.Mutex
	return func() *sqlstore.DB {
		firstMu.Lock()
		defer firstMu.Unlock()
		if first != nil {
			d := first
			first = nil
			return d
		}
		return open()
	}
}

// db is a fresh, migrated storage's one handle.
func (e *env) db() *sqlstore.DB {
	e.t.Helper()
	return e.storage()()
}

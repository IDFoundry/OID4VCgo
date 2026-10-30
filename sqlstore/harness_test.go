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

// postgres is the test run's Postgres connection, and postgresRun the
// prefix of the schemas it creates (newPostgresSchema); nil without
// postgresDSNEnv.
var (
	postgres    *sql.DB
	postgresRun string
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	if os.Getenv(postgresDSNEnv) == "" {
		return m.Run()
	}
	db, err := sql.Open("pgx", os.Getenv(postgresDSNEnv))
	if err != nil {
		fmt.Fprintln(os.Stderr, "open postgres:", err)
		return 1
	}
	defer db.Close()
	postgres, postgresRun = db, "sqlstore_test_"+randomHex(4)+"_"
	defer dropPostgresSchemas()
	return m.Run()
}

// newPostgresSchema creates an empty schema and returns a DSN using it:
// the storages of one test run are kept apart by schema, as deployments
// sharing a database are.
func newPostgresSchema(t *testing.T) string {
	t.Helper()
	schema := postgresRun + randomHex(4)
	if _, err := postgres.ExecContext(context.Background(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	u, err := url.Parse(os.Getenv(postgresDSNEnv))
	if err != nil {
		t.Fatalf("%s: %v", postgresDSNEnv, err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	return u.String()
}

// dropPostgresSchemas drops every schema the test run created.
func dropPostgresSchemas() {
	ctx := context.Background()
	rows, err := postgres.QueryContext(ctx, "SELECT schema_name FROM information_schema.schemata WHERE starts_with(schema_name, $1)", postgresRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "list test schemas:", err)
		return
	}
	var schemas []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil {
			schemas = append(schemas, name)
		}
	}
	_ = rows.Close()
	for _, name := range schemas {
		if _, err := postgres.ExecContext(ctx, "DROP SCHEMA "+name+" CASCADE"); err != nil {
			fmt.Fprintln(os.Stderr, "drop test schema:", err)
		}
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// dialects are the databases the tests run against: SQLite always,
// PostgreSQL with postgresDSNEnv set.
func dialects() []sqlstore.Dialect {
	if postgres != nil {
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

// env makes empty storages — a SQLite file, or a Postgres schema of
// their own — and handles on them.
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
	driver, dsn := "sqlite", "file:"+filepath.Join(e.t.TempDir(), "store.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	if e.dialect == sqlstore.Postgres {
		driver, dsn = "pgx", newPostgresSchema(e.t)
	}
	opts := e.opts
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

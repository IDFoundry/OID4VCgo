//go:build conformance_production

package proddb

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the database/sql driver for PostgreSQL
	_ "modernc.org/sqlite"             // the database/sql driver for the SQLite file
)

// DB is an opened database.
type DB struct {
	*sql.DB

	// Postgres is true for a PostgreSQL database, false for a SQLite
	// file: the dialect to give each store.
	Postgres bool

	// Name names it in errors without its credentials.
	Name string
}

// Open opens the SQLite file path, in WAL mode with a busy timeout, as
// sqlstore's documentation says to open SQLite; or, when url is set in
// its place, that PostgreSQL database (a pgx connection URL), its
// connection pool sized to conns as DEPLOYING.md describes. Set one of
// path and url.
func Open(path, url string, conns int) (DB, error) {
	if (path == "") == (url == "") {
		return DB{}, fmt.Errorf("proddb: set one of a database path and a database URL")
	}
	if url == "" {
		sqlDB, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
		if err != nil {
			return DB{}, fmt.Errorf("open %s: %w", path, err)
		}
		return DB{DB: sqlDB, Name: path}, nil
	}
	sqlDB, err := sql.Open("pgx", url)
	if err != nil {
		return DB{}, fmt.Errorf("open the PostgreSQL database: %w", err)
	}
	sqlDB.SetMaxOpenConns(conns)
	sqlDB.SetMaxIdleConns(conns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)
	sqlDB.SetConnMaxIdleTime(5 * time.Minute)
	return DB{DB: sqlDB, Postgres: true, Name: "the PostgreSQL database"}, nil
}

// Sweeper is a store whose expired records Sweep deletes: sqlstore's
// and fapigo/sqlstore's DB.
type Sweeper interface {
	Sweep(ctx context.Context, now time.Time) (int64, error)
}

// SweepEvery runs every sweeper's Sweep each interval, for ever,
// logging each round as one line, "sweep: deleted N expired records"
// or "sweep: FAILED: ...", naming the sweepers that failed: an interop
// run reads them to check every instance swept, and none failed. Run
// it in a goroutine of its own.
func SweepEvery(interval time.Duration, sweepers map[string]Sweeper) {
	names := make([]string, 0, len(sweepers))
	for name := range sweepers {
		names = append(names, name)
	}
	sort.Strings(names)
	for range time.Tick(interval) {
		log.Print(sweepRound(interval, names, sweepers))
	}
}

// sweepRound runs one round of SweepEvery, returning its log line.
func sweepRound(timeout time.Duration, names []string, sweepers map[string]Sweeper) string {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var deleted int64
	var failed []string
	for _, name := range names {
		n, err := sweepers[name].Sweep(ctx, time.Now())
		deleted += n
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(failed) > 0 {
		return "sweep: FAILED: " + strings.Join(failed, "; ")
	}
	return fmt.Sprintf("sweep: deleted %d expired records", deleted)
}

package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// migrationFiles are the schema's migrations, each NNNN_name.sql, in
// order, written out once for each dialect: migrations/sqlite and
// migrations/postgres hold the same names. Each is written once its
// version has shipped and never edited: a change is a new migration.
//
//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFiles embed.FS

// migration is one schema version: its statements for each dialect,
// each run as one Exec.
type migration struct {
	version  int
	name     string
	sqlite   string
	postgres string
}

// migrations are migrationFiles, parsed, in version order.
var migrations = mustParseMigrations()

func mustParseMigrations() []migration {
	read := func(dialect string) map[string]string {
		entries, err := fs.ReadDir(migrationFiles, path.Join("migrations", dialect))
		if err != nil {
			panic(err)
		}
		out := map[string]string{}
		for _, e := range entries {
			data, err := migrationFiles.ReadFile(path.Join("migrations", dialect, e.Name()))
			if err != nil {
				panic(err)
			}
			out[e.Name()] = string(data)
		}
		return out
	}
	sqlite, postgres := read("sqlite"), read("postgres")
	var out []migration
	for name, sqliteSQL := range sqlite {
		postgresSQL, ok := postgres[name]
		if !ok {
			panic(fmt.Sprintf("sqlstore: migration %s has no postgres version", name))
		}
		version, err := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if err != nil {
			panic(fmt.Sprintf("sqlstore: migration %s: %v", name, err))
		}
		out = append(out, migration{version: version, name: name, sqlite: sqliteSQL, postgres: postgresSQL})
	}
	if len(postgres) != len(sqlite) {
		panic("sqlstore: the postgres migrations aren't the sqlite ones")
	}
	slices.SortFunc(out, func(a, b migration) int { return a.version - b.version })
	for i, m := range out {
		if m.version != i+1 {
			panic(fmt.Sprintf("sqlstore: migration %s: want version %d", m.name, i+1))
		}
	}
	return out
}

// SchemaVersion is the schema version this package's stores need: the
// latest migration.
func SchemaVersion() int { return len(migrations) }

// Migrate brings the database's tables up to SchemaVersion, applying
// each migration it hasn't yet in a transaction of its own. It's safe
// to run from several processes at once: they apply each migration
// once between them. It leaves alone versions newer than this package
// knows, so an older release still starts against a schema a newer one
// migrated.
//
// Nothing migrates implicitly: run it from a deployment step, or at
// startup before serving, as the database's schema owner. On
// PostgreSQL the tables are created in the connection's current schema
// (the first in its search_path).
func (d *DB) Migrate(ctx context.Context) error {
	for _, m := range migrations {
		if err := d.write(ctx, func(q querier) error { return d.migrate(ctx, q, m) }); err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	return nil
}

// migrate applies m on q, a transaction, unless it has been already.
func (d *DB) migrate(ctx context.Context, q querier, m migration) error {
	statements := m.sqlite
	if d.dialect == Postgres {
		statements = m.postgres
		// Serializes concurrent Migrates, before either creates a table.
		if _, err := q.ExecContext(ctx, postgresMigrationLock); err != nil {
			return err
		}
	}
	if _, err := q.ExecContext(ctx, d.sql.migrationsCreate); err != nil {
		return err
	}
	var one int
	switch err := q.QueryRowContext(ctx, d.sql.migrationApplied, m.version).Scan(&one); {
	case err == nil:
		return nil // already applied
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if _, err := q.ExecContext(ctx, statements); err != nil {
		return fmt.Errorf("%s: %w", m.name, err)
	}
	_, err := q.ExecContext(ctx, d.sql.migrationRecord, m.version, m.name, time.Now().Unix())
	return err
}

// CheckSchema returns an error unless every migration this package's
// stores need has been applied: call it at startup, where Migrate is
// run separately, to fail fast rather than on the first request.
func (d *DB) CheckSchema(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, d.sql.migrationVersions)
	if err != nil {
		return fmt.Errorf("sqlstore: check schema (has Migrate run?): %w", err)
	}
	defer func() { _ = rows.Close() }()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return fmt.Errorf("sqlstore: check schema: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("sqlstore: check schema: %w", err)
	}
	for _, m := range migrations {
		if !applied[m.version] {
			return fmt.Errorf("sqlstore: check schema: migration %s hasn't been applied: run Migrate", m.name)
		}
	}
	return nil
}

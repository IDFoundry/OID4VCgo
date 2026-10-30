package sqlstore

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// migrationFiles are the schema's migrations, each NNNN_name.sql, in
// order. Each is written once its version has shipped and never edited:
// a change is a new migration.
//
//go:embed migrations/*.sql
var migrationFiles embed.FS

// migration is one schema version.
type migration struct {
	version int
	name    string
	sql     string
}

// migrations are migrationFiles, parsed, in version order.
var migrations = mustParseMigrations()

func mustParseMigrations() []migration {
	entries, err := fs.ReadDir(migrationFiles, "migrations")
	if err != nil {
		panic(err)
	}
	var out []migration
	for _, e := range entries {
		version, err := strconv.Atoi(strings.SplitN(e.Name(), "_", 2)[0])
		if err != nil {
			panic(fmt.Sprintf("sqlstore: migration %s: %v", e.Name(), err))
		}
		data, err := migrationFiles.ReadFile(path.Join("migrations", e.Name()))
		if err != nil {
			panic(err)
		}
		out = append(out, migration{version: version, name: e.Name(), sql: string(data)})
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

// statements are m's statements for d's dialect and table prefix:
// {{key}} is a case-sensitive text column type, {{blob}} a binary one,
// and {name} the table or index name with the prefix.
func (d *DB) statements(m migration) []string {
	key, blob := "TEXT", "BLOB" // SQLite compares TEXT bytewise (BINARY)
	if d.dialect == Postgres {
		key, blob = `TEXT COLLATE "C"`, "BYTEA"
	}
	// Comments are whole lines starting with --; statements end with ;.
	var lines []string
	for _, line := range strings.Split(m.sql, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, "--") {
			lines = append(lines, line)
		}
	}
	text := strings.NewReplacer("{{key}}", key, "{{blob}}", blob).Replace(strings.Join(lines, "\n"))
	var out []string
	for _, stmt := range strings.Split(text, ";") {
		if stmt = strings.TrimSpace(stmt); stmt != "" {
			out = append(out, d.q(stmt))
		}
	}
	return out
}

// Migrate brings the database's tables up to SchemaVersion, applying
// each migration it hasn't yet in a transaction of its own. It's safe
// to run from several processes at once: they apply each migration
// once between them. It leaves alone versions newer than this package
// knows, so an older release still starts against a schema a newer one
// migrated.
//
// Nothing migrates implicitly: run it from a deployment step, or at
// startup before serving, as the database's schema owner.
func (d *DB) Migrate(ctx context.Context) error {
	for _, m := range migrations {
		err := d.write(ctx, func(q querier) error {
			if d.dialect == Postgres {
				// Serializes concurrent Migrates of this prefix, before
				// either creates a table.
				if _, err := q.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", d.migrationLockKey()); err != nil {
					return err
				}
			}
			if _, err := q.ExecContext(ctx, d.q("CREATE TABLE IF NOT EXISTS {schema_migrations} (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at BIGINT NOT NULL)")); err != nil {
				return err
			}
			var one int
			switch err := q.QueryRowContext(ctx, d.q("SELECT 1 FROM {schema_migrations} WHERE version = ?"), m.version).Scan(&one); {
			case err == nil:
				return nil // already applied
			case !errors.Is(err, sql.ErrNoRows):
				return err
			}
			for _, stmt := range d.statements(m) {
				if _, err := q.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("%s: %w", m.name, err)
				}
			}
			_, err := q.ExecContext(ctx, d.q("INSERT INTO {schema_migrations} (version, name, applied_at) VALUES (?, ?, ?)"), m.version, m.name, time.Now().Unix())
			return err
		})
		if err != nil {
			return fmt.Errorf("sqlstore: migrate: %w", err)
		}
	}
	return nil
}

// migrationLockKey is the Postgres advisory lock Migrate takes for d's
// table prefix.
func (d *DB) migrationLockKey() int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("oid4vcgo sqlstore migrate " + d.prefix))
	return int64(h.Sum64()) //nolint:gosec // a lock key: wrapping around is fine
}

// CheckSchema returns an error unless every migration this package's
// stores need has been applied: call it at startup, where Migrate is
// run separately, to fail fast rather than on the first request.
func (d *DB) CheckSchema(ctx context.Context) error {
	rows, err := d.db.QueryContext(ctx, d.q("SELECT version FROM {schema_migrations}"))
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

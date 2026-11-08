package sqlstore

import "context"

// MigrateTo applies the migrations up to version, and no later, as an
// older release's Migrate would have.
func MigrateTo(ctx context.Context, d *DB, version int) error {
	for _, m := range migrations[:version] {
		if err := d.write(ctx, func(q querier) error { return d.migrate(ctx, q, m) }); err != nil {
			return err
		}
	}
	return nil
}

// SetSweepBatch sets how many rows each of Sweep's writes deletes, and
// returns a func restoring it.
func SetSweepBatch(n int) (restore func()) {
	old := sweepBatch
	sweepBatch = n
	return func() { sweepBatch = old }
}

// PostgresMigrationLocks are the locks Migrate takes on the current
// schema, in order; PostgresLegacyMigrationLockExclusive is the one an
// earlier release's Migrate took.
var PostgresMigrationLocks = []string{postgresLegacyMigrationLock, postgresMigrationLock}

const PostgresLegacyMigrationLockExclusive = "SELECT pg_advisory_xact_lock(8028057987251922799)"

// PostgresSweepLock is the statement taking Sweep's lock on the
// current schema.
const PostgresSweepLock = postgresSweepLock

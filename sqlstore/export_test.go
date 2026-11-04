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

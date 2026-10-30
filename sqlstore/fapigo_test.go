package sqlstore_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	fapisqlstore "github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
)

// The tables, and their indexes, in the connection's current schema.
const (
	sqliteObjects   = "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'"
	postgresObjects = "SELECT tablename FROM pg_tables WHERE schemaname = current_schema() " +
		"UNION ALL SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()"
)

// A whole issuer deployment keeps the Authorization Server's stores
// (fapigo/sqlstore, with a second DB of its own prefix for the
// Credential Endpoint's DPoP nonces) and the Credential Issuer's (this
// package) in one database, through one *sql.DB and one Sealer: their
// migrations run side by side, even at once, their tables don't
// collide, and each one's sealed records round-trip.
func TestSharesADatabaseWithFAPIgoSQLStore(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		sqlDB := e.location()()
		// Connections switching a new SQLite file to WAL at once can
		// fail SQLITE_BUSY whatever the busy timeout: open it first, as
		// a deployment's earlier runs have.
		if err := sqlDB.PingContext(ctx); err != nil {
			t.Fatal(err)
		}
		sealer := testSealer(t) // a verifier.TransactionSealer, for both modules
		dialect, objects := fapisqlstore.SQLite, sqliteObjects
		if e.dialect == sqlstore.Postgres {
			dialect, objects = fapisqlstore.Postgres, postgresObjects
		}
		issuerDB, err := sqlstore.New(sqlDB, e.dialect, sqlstore.Options{Sealer: sealer})
		if err != nil {
			t.Fatal(err)
		}
		asDB, err := fapisqlstore.New(sqlDB, dialect, fapisqlstore.Options{Sealer: sealer})
		if err != nil {
			t.Fatal(err)
		}
		rsDB, err := fapisqlstore.New(sqlDB, dialect, fapisqlstore.Options{TablePrefix: "fapigo_rs_", Sealer: sealer})
		if err != nil {
			t.Fatal(err)
		}
		type migrator interface {
			Migrate(context.Context) error
			CheckSchema(context.Context) error
		}
		dbs := []migrator{issuerDB, asDB, rsDB}
		var wg sync.WaitGroup
		errs := make([]error, len(dbs))
		for i, d := range dbs {
			wg.Go(func() { errs[i] = d.Migrate(ctx) })
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatalf("Migrate at once: %v", err)
		}
		for _, d := range dbs {
			if err := d.Migrate(ctx); err != nil {
				t.Fatalf("Migrate again: %v", err)
			}
			if err := d.CheckSchema(ctx); err != nil {
				t.Fatalf("CheckSchema: %v", err)
			}
		}

		rows, err := sqlDB.QueryContext(ctx, objects)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				t.Fatal(err)
			}
			names[name] = true
			if !strings.HasPrefix(name, "oid4vc_") && !strings.HasPrefix(name, "fapigo_") {
				t.Errorf("%s: neither module's prefix", name)
			}
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"oid4vc_schema_migrations", "fapigo_schema_migrations", "fapigo_rs_schema_migrations", "oid4vc_issuer_nonces", "fapigo_authorization_codes", "fapigo_rs_dpop_nonces"} {
			if !names[name] {
				t.Errorf("no table %s among %v", name, names)
			}
		}

		// Each module's sealed records, under the one Sealer.
		now := time.Now()
		if err := issuerDB.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "n-1", Owner: "https://issuer.example", ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("issuer Nonces Issue: %v", err)
		}
		if _, err := issuerDB.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "n-1", Owner: "https://issuer.example"}); err != nil {
			t.Fatalf("issuer Nonces Consume: %v", err)
		}
		record := json.RawMessage(`{"version":1}`)
		if err := asDB.Sessions().Create(ctx, storage.NewSession{State: "s-1", Record: record, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("FAPIgo Sessions Create: %v", err)
		}
		if got, err := asDB.Sessions().Consume(ctx, storage.SessionConsumption{State: "s-1"}); err != nil || string(got.Record) != string(record) {
			t.Fatalf("FAPIgo Sessions Consume = %s, %v", got.Record, err)
		}
		var digest [32]byte
		_, _ = rand.Read(digest[:])
		if err := asDB.Replay().UseOnce(ctx, storage.ReplayUse{Namespace: "dpop", Digest: digest, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("FAPIgo Replay UseOnce: %v", err)
		}

		// The Credential Endpoint's DPoP nonces aren't the
		// Authorization Server's.
		if err := rsDB.Nonces().Issue(ctx, storage.NonceIssuance{Nonce: "dpop-1", ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatalf("resource server Nonces Issue: %v", err)
		}
		if _, err := asDB.Nonces().Lookup(ctx, storage.NonceLookup{Nonce: "dpop-1"}); err == nil {
			t.Error("the Authorization Server's Nonces found the resource server's nonce")
		}

		later := now.Add(time.Hour)
		if _, err := issuerDB.Sweep(ctx, later); err != nil {
			t.Fatalf("issuer Sweep: %v", err)
		}
		for _, d := range []*fapisqlstore.DB{asDB, rsDB} {
			if _, err := d.Sweep(ctx, later); err != nil {
				t.Fatalf("FAPIgo Sweep: %v", err)
			}
		}
	})
}

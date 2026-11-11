package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

func TestNewRefusesBadOptions(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for name, c := range map[string]struct {
		db      *sql.DB
		dialect sqlstore.Dialect
		opts    sqlstore.Options
	}{
		"nil db":     {nil, sqlstore.SQLite, sqlstore.Options{}},
		"no dialect": {db, 0, sqlstore.Options{}},
	} {
		if _, err := sqlstore.New(c.db, c.dialect, c.opts); err == nil {
			t.Errorf("%s: New = nil error, want an error", name)
		}
	}
}

func TestMigrate(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage() // migrated once already
		d := open()
		if err := d.CheckSchema(ctx); err != nil {
			t.Fatalf("CheckSchema after Migrate: %v", err)
		}
		// Again, and from several handles at once: each migration
		// applies once.
		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			h := open()
			wg.Go(func() { errs[i] = h.Migrate(ctx) })
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Errorf("concurrent Migrate: %v", err)
		}
	})
}

func TestCheckSchemaBeforeMigrate(t *testing.T) {
	d, _ := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), sqlstore.Options{})
	if err := d.CheckSchema(context.Background()); err == nil {
		t.Error("CheckSchema before Migrate = nil error, want an error")
	}
	if sqlstore.SchemaVersion() < 1 {
		t.Errorf("SchemaVersion() = %d", sqlstore.SchemaVersion())
	}
}

// On PostgreSQL, two schemas in one database are two separate sets of
// stores.
func TestSchemasKeepStoresApart(t *testing.T) {
	if postgres == nil {
		t.Skip(postgresDSNEnv + " isn't set")
	}
	ctx := context.Background()
	var dbs []*sqlstore.DB
	for range 2 {
		db, err := sql.Open("pgx", newPostgresSchema(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		d, err := sqlstore.New(db, sqlstore.Postgres, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		dbs = append(dbs, d)
	}
	if err := dbs[0].Notifications().Issue(ctx, "n", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	if _, err := dbs[1].Notifications().Get(ctx, "n"); !errors.Is(err, issuer.ErrNotificationIDUnknown) {
		t.Errorf("another schema's Get = %v, want ErrNotificationIDUnknown", err)
	}
	if _, err := dbs[0].Notifications().Get(ctx, "n"); err != nil {
		t.Errorf("Get in its own schema: %v", err)
	}
}

// A DB reads only records written as it would write them: sealed with
// its Sealer, or unsealed without one.
func TestSealingMismatchIsRefused(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	plain, _ := openSQLite(t, path, sqlstore.Options{})
	if err := plain.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	sealed, _ := openSQLite(t, path, sqlstore.Options{Sealer: testSealer(t)})
	otherKey, _ := openSQLite(t, path, sqlstore.Options{Sealer: testSealer(t)})
	if err := plain.Notifications().Issue(ctx, "plain", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := sealed.Notifications().Issue(ctx, "sealed", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		d  *sqlstore.DB
		id string
	}{
		"sealed read unsealed": {sealed, "plain"}, "unsealed read sealed": {plain, "sealed"}, "another key": {otherKey, "sealed"},
	} {
		_, err := c.d.Notifications().Get(ctx, c.id)
		if !errors.Is(err, sqlstore.ErrRecordFormat) || errors.Is(err, issuer.ErrNotificationIDUnknown) {
			t.Errorf("%s: %v, want ErrRecordFormat", name, err)
		}
	}
}

// Sweep deletes a table's expired rows in batches until none is left,
// and leaves the rows that haven't expired: 7 expired, in a batch of
// 4 and one of 3.
func TestSweepBatches(t *testing.T) {
	defer sqlstore.SetSweepBatch(3)()
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		for i := range 8 {
			exp := now.Add(-time.Duration(i+1) * time.Minute)
			if i == 7 {
				exp = now.Add(time.Minute)
			}
			if err := d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: fmt.Sprint("n", i), ExpiresAt: exp}); err != nil {
				t.Fatal(err)
			}
		}
		if n, err := d.Sweep(ctx, now); err != nil || n != 7 {
			t.Errorf("Sweep = %d, %v; want 7 deleted", n, err)
		}
		if n, err := d.Sweep(ctx, now.Add(2*time.Minute)); err != nil || n != 1 {
			t.Errorf("Sweep later = %d, %v; want 1 deleted", n, err)
		}
	})
}

// A Postgres Sweep that finds another sweeping the same schema stops,
// deleting nothing, with no error, and sweeps once that one is done; a
// Sweep of another schema of the same database doesn't stop it.
func TestSweepStepsAside(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		if e.dialect != sqlstore.Postgres {
			t.Skip("Sweep's lock is Postgres's")
		}
		ctx := context.Background()
		now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		// A migrated schema with one expired nonce, and its opener.
		schema := func() (*sqlstore.DB, func() *sql.DB) {
			open := e.location()
			d, err := sqlstore.New(open(), e.dialect, sqlstore.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := d.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if err := d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "old", ExpiresAt: now.Add(-time.Minute)}); err != nil {
				t.Fatal(err)
			}
			return d, open
		}
		d, open := schema()
		elsewhere, _ := schema()
		// Another instance's batch, holding the lock until it commits.
		other, err := open().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Rollback()
		var locked bool
		if err := other.QueryRowContext(ctx, sqlstore.PostgresSweepLock).Scan(&locked); err != nil || !locked {
			t.Fatalf("taking the sweep lock = %v, %v", locked, err)
		}
		// Another schema's sweep lock is its own.
		if n, err := elsewhere.Sweep(ctx, now); err != nil || n != 1 {
			t.Errorf("Sweep of another schema = %d, %v; want 1 deleted", n, err)
		}

		if n, err := d.Sweep(ctx, now); err != nil || n != 0 {
			t.Errorf("Sweep while another holds the lock = %d, %v; want none deleted, no error", n, err)
		}
		if err := other.Commit(); err != nil {
			t.Fatal(err)
		}
		if n, err := d.Sweep(ctx, now); err != nil || n != 1 {
			t.Errorf("Sweep after = %d, %v; want 1 deleted", n, err)
		}
	})
}

// TestMigrateLocksTheSchema: a Migrate waits for another of the same
// schema, not for one of another schema, and for an earlier release's,
// which held one lock for the whole database.
func TestMigrateLocksTheSchema(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		if e.dialect != sqlstore.Postgres {
			t.Skip("Migrate's locks are Postgres's")
		}
		ctx := context.Background()
		// A migrated schema: Migrate again takes the locks, then finds
		// every migration applied, quickly.
		fresh := func() (*sqlstore.DB, func() *sql.DB) {
			open := e.location()
			d, err := sqlstore.New(open(), e.dialect, sqlstore.Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := d.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			return d, open
		}
		// holding takes locks in a transaction of its own, open until
		// release ends it; waits reports whether a Migrate queues
		// behind it, from pg_locks, or else runs to the end.
		var holder int
		holding := func(open func() *sql.DB, locks ...string) (release func()) {
			tx, err := open().BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := tx.QueryRowContext(ctx, "SELECT pg_backend_pid()").Scan(&holder); err != nil {
				t.Fatal(err)
			}
			for _, lock := range locks {
				if _, err := tx.ExecContext(ctx, lock); err != nil {
					t.Fatal(err)
				}
			}
			return func() { _ = tx.Rollback() }
		}
		observer := e.location()()
		waits := func(d *sqlstore.DB) bool {
			t.Helper()
			running, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.Migrate(running) }()
			for {
				select {
				case err := <-done:
					if err != nil {
						t.Fatalf("Migrate = %v", err)
					}
					return false
				case <-time.After(10 * time.Millisecond):
				}
				var queued bool
				if err := observer.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_locks w
					JOIN pg_locks h USING (locktype, database, classid, objid, objsubid)
					WHERE w.locktype = 'advisory' AND NOT w.granted AND h.granted AND h.pid = $1)`, holder).Scan(&queued); err != nil {
					t.Fatal(err)
				}
				if queued {
					cancel()
					<-done
					return true
				}
			}
		}

		d, open := fresh()
		elsewhere, _ := fresh()
		later, _ := fresh()
		release := holding(open, sqlstore.PostgresMigrationLocks...) // another Migrate of the schema
		if !waits(d) {
			t.Error("Migrate didn't wait for another Migrate of its schema")
		}
		if waits(elsewhere) {
			t.Error("Migrate waited for a Migrate of another schema")
		}
		var free bool
		if err := observer.QueryRowContext(ctx, "SELECT pg_try_advisory_xact_lock(8028057987251922799)").Scan(&free); err != nil || free {
			t.Errorf("an earlier release's lock, during a Migrate = %v, %v; want held off", free, err)
		}
		release()
		if waits(d) {
			t.Error("Migrate waited once the other had ended")
		}

		// An earlier release's Migrate, of another schema.
		release = holding(open, sqlstore.PostgresLegacyMigrationLockExclusive)
		if !waits(later) {
			t.Error("Migrate didn't wait for an earlier release's Migrate")
		}
		release()
		if waits(later) {
			t.Error("Migrate waited once the earlier release's had ended")
		}
	})
}

func TestSweep(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
		past, future := now.Add(-time.Minute), now.Add(time.Minute)
		mustDo := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		mustDo(d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "old", ExpiresAt: past}))
		mustDo(d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "new", ExpiresAt: future}))
		mustDo(d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "now", ExpiresAt: now}))
		mustDo(d.PreAuthorizedCodes().Issue(ctx, "old", issuer.PreAuthorizedCodeRecord{ExpiresAt: past}))
		mustDo(d.PreAuthorizedCodes().Issue(ctx, "new", issuer.PreAuthorizedCodeRecord{ExpiresAt: future}))
		mustDo(d.CredentialOffers().Store(ctx, issuer.CredentialOfferRecord{Reference: "old", ExpiresAt: past}))
		mustDo(d.CredentialOffers().Store(ctx, issuer.CredentialOfferRecord{Reference: "new", ExpiresAt: future}))
		mustDo(d.Notifications().Issue(ctx, "old", issuer.NotificationRecord{ExpiresAt: past}))
		mustDo(d.Notifications().Issue(ctx, "forever", issuer.NotificationRecord{}))
		mustDo(d.DeferredTransactions().Create(ctx, "old", issuer.DeferredTransactionRecord{ExpiresAt: past}))
		mustDo(d.DeferredTransactions().Create(ctx, "new", issuer.DeferredTransactionRecord{ExpiresAt: future}))
		mustDo(d.DeferredTransactions().Create(ctx, "forever", issuer.DeferredTransactionRecord{}))
		mustDo(d.Transactions(verifier.TransactionCodec{}).Create(ctx, verifier.Transaction{ID: "kept", ExpiresAt: past, RetainUntil: future, Status: verifier.TransactionPending}))
		mustDo(d.Transactions(verifier.TransactionCodec{}).Create(ctx, verifier.Transaction{ID: "gone", KeyID: "k", ExpiresAt: past, RetainUntil: past, Status: verifier.TransactionPending}))
		mustDo(d.Authorizations().PutAuthorization(ctx, walletflow.PendingAuthorization{State: "old", ExpiresAt: past}))
		mustDo(d.Credentials().Put(ctx, walletflow.StoredCredential{ID: "c"}))

		// An expired nonce, pre-authorized code, Credential Offer,
		// notification_id, deferred transaction and verifier transaction.
		n, err := d.Sweep(ctx, now)
		if err != nil || n != 6 {
			t.Errorf("Sweep = %d, %v; want 6 deleted", n, err)
		}
		if _, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "old"}); !errors.Is(err, issuer.ErrNonceUnknown) {
			t.Errorf("an expired nonce survived the sweep: %v", err)
		}
		if _, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "new"}); err != nil {
			t.Errorf("an unexpired nonce was swept: %v", err)
		}
		// Expired before now, not at it.
		if _, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "now"}); err != nil {
			t.Errorf("a nonce expiring at the sweep's now was swept: %v", err)
		}
		if _, _, err := d.PreAuthorizedCodes().Consume(ctx, "old", "", 0, nil); !errors.Is(err, issuer.ErrPreAuthorizedCodeUnknown) {
			t.Errorf("an expired pre-authorized code survived the sweep: %v", err)
		}
		if _, _, err := d.PreAuthorizedCodes().Consume(ctx, "new", "", 0, nil); err != nil {
			t.Errorf("an unexpired pre-authorized code was swept: %v", err)
		}
		if _, err := d.CredentialOffers().Get(ctx, "old"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("an expired Credential Offer survived the sweep: %v", err)
		}
		if _, err := d.CredentialOffers().Get(ctx, "new"); err != nil {
			t.Errorf("an unexpired Credential Offer was swept: %v", err)
		}
		if _, err := d.Notifications().Get(ctx, "old"); !errors.Is(err, issuer.ErrNotificationIDUnknown) {
			t.Errorf("an expired notification_id survived the sweep: %v", err)
		}
		if _, err := d.Notifications().Get(ctx, "forever"); err != nil {
			t.Errorf("a notification_id with no expiry was swept: %v", err)
		}
		if _, err := d.DeferredTransactions().Get(ctx, "old"); !errors.Is(err, issuer.ErrDeferredTransactionUnknown) {
			t.Errorf("an expired deferred transaction survived the sweep: %v", err)
		}
		for _, id := range []string{"new", "forever"} {
			if _, err := d.DeferredTransactions().Get(ctx, id); err != nil {
				t.Errorf("deferred transaction %q was swept: %v", id, err)
			}
		}
		if _, err := d.Transactions(verifier.TransactionCodec{}).Get(ctx, "kept"); err != nil {
			t.Errorf("a transaction within its retention was swept: %v", err)
		}
		if _, err := d.Transactions(verifier.TransactionCodec{}).IDByKeyID(ctx, "k"); !errors.Is(err, verifier.ErrTransactionUnknown) {
			t.Errorf("a transaction past its retention survived the sweep: %v", err)
		}
		if _, err := d.Credentials().Get(ctx, "c"); err != nil {
			t.Errorf("a credential was swept: %v", err)
		}
		// walletflow forgets an expired authorization, with the keys it
		// names, itself: swept here, those keys would be orphaned.
		if _, err := d.Authorizations().GetAuthorization(ctx, "old"); err != nil {
			t.Errorf("an expired authorization was swept: %v", err)
		}
	})
}

// A SQLite database not in WAL mode is refused by Migrate and
// CheckSchema; the same file switched to WAL is migrated.
func TestMigrateRefusesSQLiteWithoutWAL(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	d, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(context.Context) error{"Migrate": d.Migrate, "CheckSchema": d.CheckSchema} {
		if err := run(ctx); err == nil || !strings.Contains(err.Error(), "not WAL") {
			t.Errorf("%s without WAL = %v, want it refused", name, err)
		}
	}
	if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
		t.Fatal(err)
	}
	if err := d.Migrate(ctx); err != nil {
		t.Errorf("Migrate in WAL mode: %v", err)
	}
	if err := d.CheckSchema(ctx); err != nil {
		t.Errorf("CheckSchema in WAL mode: %v", err)
	}
}

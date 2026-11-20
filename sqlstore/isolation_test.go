package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// isolationDB is a migrated PostgreSQL storage: a DB on it over a pool
// whose connections default to level, and a pool at the server's
// default, READ COMMITTED, for the writes a test races the DB's
// against. With checked, the DB has run CheckSchema, and so read that
// default.
func isolationDB(t *testing.T, level string, checked bool) (*sqlstore.DB, *sql.DB) {
	t.Helper()
	if postgres == nil {
		t.Skip("PostgreSQL only: " + postgresDSNEnv + " is unset")
	}
	ctx := context.Background()
	dsn := newPostgresSchema(t)
	other := openPostgres(t, dsn)
	migrating, err := sqlstore.New(other, sqlstore.Postgres, sqlstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := migrating.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if sqlstore.PinsIsolation(migrating) {
		t.Fatal("Migrate pinned READ COMMITTED on a READ COMMITTED database")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// The level's space as %20: pgx doesn't read a query's + as one.
	u.RawQuery += "&default_transaction_isolation=" + url.PathEscape(level)
	pool := openPostgres(t, u.String())
	var got string
	if err := pool.QueryRowContext(ctx, "SHOW default_transaction_isolation").Scan(&got); err != nil || got != level {
		t.Fatalf("default_transaction_isolation = %q, %v, want %q", got, err, level)
	}
	d, err := sqlstore.New(pool, sqlstore.Postgres, sqlstore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		if err := d.CheckSchema(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if pinned, want := sqlstore.PinsIsolation(d), checked && level != "read committed"; pinned != want {
		t.Fatalf("PinsIsolation = %v, want %v", pinned, want)
	}
	return d, other
}

// openPostgres opens dsn, closing it when t ends.
func openPostgres(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(16)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// raceLockedRow runs change, a statement on the row call's statement
// will wait on, in a transaction of its own on other; starts call;
// commits the transaction once a session waits for a lock; and returns
// call's error. call's statement then runs against a row changed since
// its snapshot: at REPEATABLE READ or SERIALIZABLE, a serialization
// failure.
func raceLockedRow(t *testing.T, other *sql.DB, change string, arg any, call func() error) error {
	t.Helper()
	ctx := context.Background()
	tx, err := other.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, change, arg); err != nil {
		t.Fatalf("%s: %v", change, err)
	}
	done := make(chan error, 1)
	go func() { done <- call() }()
	waitForLockWaiter(t, other)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return <-done
}

// waitForLockWaiter waits until a session of the database waits on a
// lock.
func waitForLockWaiter(t *testing.T, db *sql.DB) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		var n int
		if err := db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("no session waited on the row's lock")
}

// singleStatementRace is a store call whose one statement loses a race:
// change (with arg), committed while the call waits on the row it
// changes, makes the call's outcome check's.
type singleStatementRace struct {
	name   string
	setup  func(t *testing.T, d *sqlstore.DB)
	change string
	arg    any
	call   func(d *sqlstore.DB) error
	check  func(t *testing.T, err error)
}

// singleStatementRaces race each kind of single-statement write: a
// compare-and-swap UPDATE, an UPDATE whose trigger updates another
// row, a DELETE … RETURNING, and an INSERT … ON CONFLICT DO NOTHING.
func singleStatementRaces() []singleStatementRace {
	ctx := context.Background()
	const uri = "https://status.example/race"
	expires := time.Now().Add(time.Hour)
	want := func(target error) func(t *testing.T, err error) {
		return func(t *testing.T, err error) {
			t.Helper()
			if !errors.Is(err, target) {
				t.Fatalf("losing a race = %v, want %v", err, target)
			}
		}
	}
	return []singleStatementRace{{
		name: "instance compare-and-swap",
		setup: func(t *testing.T, d *sqlstore.DB) {
			t.Helper()
			if err := d.WalletProviderInstances().Create(ctx, testInstance("race")); err != nil {
				t.Fatal(err)
			}
		},
		change: "UPDATE oid4vc_walletprovider_instances SET revision = revision + 1 WHERE id = $1", arg: "race",
		call: func(d *sqlstore.DB) error {
			in := testInstance("race")
			in.Revision = 1
			return d.WalletProviderInstances().Update(ctx, in)
		},
		check: want(walletprovider.ErrConflict),
	}, {
		name: "status set",
		setup: func(t *testing.T, d *sqlstore.DB) {
			t.Helper()
			for idx := range uint64(2) {
				if err := d.StatusIndices().Reserve(ctx, uri, idx); err != nil {
					t.Fatal(err)
				}
			}
		},
		// The trigger raising the list's version locks its version row,
		// which the call's own trigger then waits on.
		change: "UPDATE oid4vc_status_indices SET status = 1 WHERE uri = $1 AND idx = 0", arg: uri,
		call: func(d *sqlstore.DB) error {
			if err := d.StatusIndices().SetStatus(ctx, uri, 1, statuslist.StatusInvalid); err != nil {
				return err
			}
			switch status, err := d.StatusIndices().Status(ctx, uri, 1); {
			case err != nil:
				return err
			case status != statuslist.StatusInvalid:
				return fmt.Errorf("index 1's status is %v, want INVALID", status)
			}
			return nil
		},
		check: func(t *testing.T, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("setting a status while another of the list's is set = %v, want nil", err)
			}
		},
	}, {
		name:   "status reserve",
		change: "INSERT INTO oid4vc_status_indices (uri, idx) VALUES ($1, 7)", arg: uri,
		call:  func(d *sqlstore.DB) error { return d.StatusIndices().Reserve(ctx, uri, 7) },
		check: want(statuslist.ErrIndexTaken),
	}, {
		name: "c_nonce consume",
		setup: func(t *testing.T, d *sqlstore.DB) {
			t.Helper()
			if err := d.Nonces().Issue(ctx, issuer.NonceIssuance{Nonce: "race", Owner: "o", ExpiresAt: expires}); err != nil {
				t.Fatal(err)
			}
		},
		change: "DELETE FROM oid4vc_issuer_nonces WHERE id = $1", arg: "race",
		call: func(d *sqlstore.DB) error {
			_, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "race", Owner: "o"})
			return err
		},
		check: want(issuer.ErrNonceUnknown),
	}, {
		name:   "c_nonce spend",
		change: "INSERT INTO oid4vc_issuer_nonces (id, owner, record) VALUES ($1, 'o', '\\x01')", arg: "spent",
		call: func(d *sqlstore.DB) error {
			return d.Nonces().Spend(ctx, issuer.NonceIssuance{Nonce: "spent", Owner: "o", ExpiresAt: expires})
		},
		check: want(issuer.ErrNonceUnknown),
	}, {
		name: "challenge consume",
		setup: func(t *testing.T, d *sqlstore.DB) {
			t.Helper()
			rec := walletprovider.ChallengeRecord{Value: "race", Purpose: walletprovider.PurposeRegistration, CreatedAt: time.Now(), ExpiresAt: expires}
			if err := d.WalletProviderChallenges().Create(ctx, rec); err != nil {
				t.Fatal(err)
			}
		},
		change: "DELETE FROM oid4vc_walletprovider_challenges WHERE id = $1", arg: "race",
		call: func(d *sqlstore.DB) error {
			_, err := d.WalletProviderChallenges().Consume(ctx, "race")
			return err
		},
		check: want(walletprovider.ErrNotFound),
	}}
}

// On a database whose default isolation is stricter than READ
// COMMITTED, a single-statement write that loses a race gets the
// store's own answer, as at READ COMMITTED, not a serialization
// failure: run again in a READ COMMITTED transaction, or, once
// CheckSchema has read the default, run in one from the start.
func TestPostgresSingleStatementWritesAreReadCommitted(t *testing.T) {
	for _, level := range []string{"serializable", "repeatable read"} {
		for _, checked := range []bool{false, true} {
			for _, race := range singleStatementRaces() {
				t.Run(fmt.Sprintf("%s/checked=%t/%s", level, checked, race.name), func(t *testing.T) {
					d, other := isolationDB(t, level, checked)
					if race.setup != nil {
						race.setup(t, d)
					}
					race.check(t, raceLockedRow(t, other, race.change, race.arg, func() error { return race.call(d) }))
				})
			}
		}
	}
}

// Concurrent status writes on one list all land under a SERIALIZABLE
// default, though each raises the list's one version row: revoking
// many of a list's Referenced Tokens at once doesn't mostly fail.
func TestPostgresConcurrentStatusWritesSerializable(t *testing.T) {
	for _, checked := range []bool{false, true} {
		t.Run(fmt.Sprintf("checked=%t", checked), func(t *testing.T) {
			ctx := context.Background()
			d, _ := isolationDB(t, "serializable", checked)
			const uri, n = "https://status.example/many", 64
			for idx := range uint64(n) {
				if err := d.StatusIndices().Reserve(ctx, uri, idx); err != nil {
					t.Fatal(err)
				}
			}
			errs := make([]error, n)
			var wg sync.WaitGroup
			for idx := range uint64(n) {
				wg.Go(func() { errs[idx] = d.StatusIndices().SetStatus(ctx, uri, idx, statuslist.StatusInvalid) })
			}
			wg.Wait()
			if err := errors.Join(errs...); err != nil {
				t.Fatalf("concurrent SetStatus: %v", err)
			}
			statuses, err := d.StatusIndices().Statuses(ctx, uri, n)
			if err != nil {
				t.Fatal(err)
			}
			for idx, status := range statuses {
				if statuslist.StatusType(status) != statuslist.StatusInvalid {
					t.Fatalf("index %d's status is %d, want INVALID", idx, status)
				}
			}
		})
	}
}

// CheckSchema reads the default isolation afresh: a database moved back
// to READ COMMITTED runs single statements on their own again.
func TestPostgresCheckSchemaReadsIsolation(t *testing.T) {
	d, _ := isolationDB(t, "read committed", true)
	if sqlstore.PinsIsolation(d) {
		t.Fatal("CheckSchema pinned READ COMMITTED on a READ COMMITTED database")
	}
}

package sqlstore_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
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
		"nil db":            {nil, sqlstore.SQLite, sqlstore.Options{}},
		"no dialect":        {db, 0, sqlstore.Options{}},
		"upper-case prefix": {db, sqlstore.SQLite, sqlstore.Options{TablePrefix: "Oid_"}},
		"quoting prefix":    {db, sqlstore.SQLite, sqlstore.Options{TablePrefix: `x"; DROP TABLE y; --`}},
		"digit first":       {db, sqlstore.SQLite, sqlstore.Options{TablePrefix: "1x"}},
		"negative timeout":  {db, sqlstore.SQLite, sqlstore.Options{SQLiteBusyTimeout: -time.Second}},
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

// Two prefixes in one database are two separate sets of stores.
func TestTablePrefixesKeepStoresApart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	a, _ := openSQLite(t, path, sqlstore.Options{TablePrefix: "a_"})
	b, _ := openSQLite(t, path, sqlstore.Options{TablePrefix: "b_"})
	for _, d := range []*sqlstore.DB{a, b} {
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Notifications().Issue(ctx, "n", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Notifications().Get(ctx, "n"); !errors.Is(err, issuer.ErrNotificationIDUnknown) {
		t.Errorf("another prefix's Get = %v, want ErrNotificationIDUnknown", err)
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
		mustDo(d.Notifications().Issue(ctx, "forever", issuer.NotificationRecord{}))
		mustDo(d.DeferredTransactions().Create(ctx, "old", issuer.DeferredTransactionRecord{ExpiresAt: past}))
		mustDo(d.Transactions(verifier.TransactionCodec{}).Create(ctx, verifier.Transaction{ID: "kept", ExpiresAt: past, RetainUntil: future, Status: verifier.TransactionPending}))
		mustDo(d.Transactions(verifier.TransactionCodec{}).Create(ctx, verifier.Transaction{ID: "gone", KeyID: "k", ExpiresAt: past, RetainUntil: past, Status: verifier.TransactionPending}))

		n, err := d.Sweep(ctx, now)
		if err != nil || n != 3 {
			t.Errorf("Sweep = %d, %v; want 3 deleted", n, err)
		}
		if _, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "old"}); !errors.Is(err, issuer.ErrNonceUnknown) {
			t.Errorf("an expired nonce survived the sweep: %v", err)
		}
		if _, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "new"}); err != nil {
			t.Errorf("an unexpired nonce was swept: %v", err)
		}
		if _, err := d.Notifications().Get(ctx, "forever"); err != nil {
			t.Errorf("a notification_id with no expiry was swept: %v", err)
		}
		if _, err := d.Transactions(verifier.TransactionCodec{}).Get(ctx, "kept"); err != nil {
			t.Errorf("a transaction within its retention was swept: %v", err)
		}
		if _, err := d.Transactions(verifier.TransactionCodec{}).IDByKeyID(ctx, "k"); !errors.Is(err, verifier.ErrTransactionUnknown) {
			t.Errorf("a transaction past its retention survived the sweep: %v", err)
		}
	})
}

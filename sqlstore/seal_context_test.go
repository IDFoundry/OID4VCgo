package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

func TestNewRefusesSealContextOptions(t *testing.T) {
	db, err := sql.Open("sqlite", "file::memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sealer := testSealer(t)
	for name, opts := range map[string]sqlstore.Options{
		"SealContext without a Sealer":             {SealContext: "tenant"},
		"ReadWithoutSealContext without a context": {Sealer: sealer, ReadWithoutSealContext: true},
	} {
		if _, err := sqlstore.New(db, sqlstore.SQLite, opts); err == nil {
			t.Errorf("%s: New = nil error, want an error", name)
		}
	}
}

// copyRow copies the row keyed by id of table from one database to
// another, column for column, as a database writer would.
func copyRow(t *testing.T, dialect sqlstore.Dialect, from, to *sql.DB, table, id string) {
	t.Helper()
	ctx := context.Background()
	mark := func(i int) string {
		if dialect == sqlstore.Postgres {
			return fmt.Sprintf("$%d", i)
		}
		return "?"
	}
	rows, err := from.QueryContext(ctx, "SELECT * FROM "+table+" WHERE id = "+mark(1), id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatalf("no row %q in %s", id, table)
	}
	values := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	if err := rows.Scan(dest...); err != nil {
		t.Fatal(err)
	}
	marks := make([]string, len(columns))
	for i := range marks {
		marks[i] = mark(i + 1)
	}
	if _, err := to.ExecContext(ctx, "INSERT INTO "+table+" ("+strings.Join(columns, ", ")+") VALUES ("+strings.Join(marks, ", ")+")", values...); err != nil {
		t.Fatal(err)
	}
}

// One user's wallet records, copied by a database writer into another
// user's schema or file, open there under one Sealer key unless the
// two DBs' SealContexts differ: then they're refused.
func TestSealContextKeepsTenantsApart(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		sealer := testSealer(t)
		for _, c := range []struct {
			name         string
			alice, bob   string
			wantRefusals bool
		}{
			{"no SealContexts", "", "", false},
			{"the same SealContext", "tenant", "tenant", false},
			{"a SealContext each", "alice", "bob", true},
		} {
			t.Run(c.name, func(t *testing.T) {
				e.opts = sqlstore.Options{Sealer: sealer, SealContext: c.alice}
				alice, aliceDB := e.raw()
				e.opts = sqlstore.Options{Sealer: sealer, SealContext: c.bob}
				bob, bobDB := e.raw()
				e.opts = sqlstore.Options{}

				aliceKeys, err := alice.Keys()
				if err != nil {
					t.Fatal(err)
				}
				key, err := aliceKeys.NewKey(ctx, walletflow.KeyPurposeHolder)
				if err != nil {
					t.Fatal(err)
				}
				cred := walletflow.StoredCredential{ID: "alicecred", CredentialIssuer: "https://issuer.example", ConfigurationID: "pid"}
				if err := alice.Credentials().Put(ctx, cred); err != nil {
					t.Fatal(err)
				}
				copyRow(t, e.dialect, aliceDB, bobDB, "oid4vc_wallet_keys", key.ID())
				copyRow(t, e.dialect, aliceDB, bobDB, "oid4vc_wallet_credentials", cred.ID)

				bobKeys, err := bob.Keys()
				if err != nil {
					t.Fatal(err)
				}
				gotKey, keyErr := bobKeys.Key(ctx, key.ID())
				_, credErr := bob.Credentials().Get(ctx, cred.ID)
				if c.wantRefusals {
					for what, err := range map[string]error{"key": keyErr, "credential": credErr} {
						if !errors.Is(err, sqlstore.ErrRecordFormat) {
							t.Errorf("Bob's DB reading Alice's %s = %v, want ErrRecordFormat", what, err)
						}
					}
					return
				}
				if keyErr != nil || credErr != nil {
					t.Fatalf("Bob's DB reading Alice's key, credential = %v, %v; want them opened", keyErr, credErr)
				}
				if !gotKey.Public().(*ecdsa.PublicKey).Equal(key.Public()) {
					t.Fatal("Bob's DB opened another key than Alice's")
				}
			})
		}
	})
}

// sealedFixture is a SQLite file, migrated, and opens DBs on it with a
// Sealer of one key.
type sealedFixture struct {
	t      *testing.T
	path   string
	sealer sqlstore.Sealer
}

func newSealedFixture(t *testing.T) *sealedFixture {
	t.Helper()
	f := &sealedFixture{t: t, path: filepath.Join(t.TempDir(), "store.db"), sealer: testSealer(t)}
	d, _ := openSQLite(t, f.path, sqlstore.Options{})
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *sealedFixture) open(opts sqlstore.Options) *sqlstore.DB {
	f.t.Helper()
	if opts.Sealer == nil && (opts.SealContext != "" || opts.ReadWithoutSealContext) {
		opts.Sealer = f.sealer
	}
	d, _ := openSQLite(f.t, f.path, opts)
	return d
}

// A DB reads a record sealed in a SealContext only in its own, and one
// sealed without, only without one or with ReadWithoutSealContext.
func TestSealContextRecordFormats(t *testing.T) {
	ctx := context.Background()
	f := newSealedFixture(t)
	inA := f.open(sqlstore.Options{SealContext: "a"})
	withoutContext := f.open(sqlstore.Options{Sealer: f.sealer})
	if err := inA.Notifications().Issue(ctx, "in-a", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	if err := withoutContext.Notifications().Issue(ctx, "without", issuer.NotificationRecord{}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		opts sqlstore.Options
		id   string
		ok   bool
	}{
		{"its own SealContext", sqlstore.Options{SealContext: "a"}, "in-a", true},
		{"another SealContext", sqlstore.Options{SealContext: "b"}, "in-a", false},
		{"no SealContext", sqlstore.Options{Sealer: f.sealer}, "in-a", false},
		{"no Sealer", sqlstore.Options{}, "in-a", false},
		{"a SealContext, reading one sealed without", sqlstore.Options{SealContext: "a"}, "without", false},
		{"ReadWithoutSealContext", sqlstore.Options{SealContext: "a", ReadWithoutSealContext: true}, "without", true},
		{"ReadWithoutSealContext, another SealContext", sqlstore.Options{SealContext: "b", ReadWithoutSealContext: true}, "in-a", false},
	} {
		_, err := f.open(c.opts).Notifications().Get(ctx, c.id)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: Get(%s) = %v, want it read", c.name, c.id, err)
		case !c.ok && (!errors.Is(err, sqlstore.ErrRecordFormat) || errors.Is(err, issuer.ErrNotificationIDUnknown)):
			t.Errorf("%s: Get(%s) = %v, want ErrRecordFormat", c.name, c.id, err)
		}
	}
}

// BindRecords moves a sealed database to a SealContext: a DB with it
// and ReadWithoutSealContext reads the records sealed before, and
// BindRecords seals each in it, a batch at a time, so a DB with it
// alone reads them and one without it doesn't. A run once they're
// bound binds nothing.
func TestBindRecords(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		sealer := testSealer(t)
		e.opts = sqlstore.Options{Sealer: sealer}
		before, raw := e.raw()
		e.opts = sqlstore.Options{}
		open := func(opts sqlstore.Options) *sqlstore.DB {
			t.Helper()
			opts.Sealer = sealer
			d, err := sqlstore.New(raw, e.dialect, opts)
			if err != nil {
				t.Fatal(err)
			}
			return d
		}

		// More notifications than one batch binds, a key and an instance.
		const notifications = 250
		for i := range notifications {
			if err := before.Notifications().Issue(ctx, fmt.Sprintf("n%03d", i), issuer.NotificationRecord{}); err != nil {
				t.Fatal(err)
			}
		}
		keys, err := before.Keys()
		if err != nil {
			t.Fatal(err)
		}
		key, err := keys.NewKey(ctx, walletflow.KeyPurposeHolder)
		if err != nil {
			t.Fatal(err)
		}
		if err := before.WalletProviderInstances().Create(ctx, testInstance("inst")); err != nil {
			t.Fatal(err)
		}
		read := func(d *sqlstore.DB) error {
			t.Helper()
			for _, id := range []string{"n000", "n123", fmt.Sprintf("n%03d", notifications-1)} {
				if _, err := d.Notifications().Get(ctx, id); err != nil {
					return err
				}
			}
			keys, err := d.Keys()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := keys.Key(ctx, key.ID()); err != nil {
				return err
			}
			_, err = d.WalletProviderInstances().Get(ctx, "inst")
			return err
		}

		migrating := open(sqlstore.Options{SealContext: "tenant", ReadWithoutSealContext: true})
		if err := read(migrating); err != nil {
			t.Fatalf("reading the records sealed before, with ReadWithoutSealContext: %v", err)
		}
		// One written meanwhile is sealed in the SealContext already.
		if err := migrating.Notifications().Issue(ctx, "during", issuer.NotificationRecord{}); err != nil {
			t.Fatal(err)
		}
		if _, err := before.BindRecords(ctx); err == nil {
			t.Error("BindRecords without a SealContext = nil error, want an error")
		}
		n, err := migrating.BindRecords(ctx)
		if want := int64(notifications + 2); n != want || err != nil {
			t.Fatalf("BindRecords = %d, %v; want %d, nil", n, err, want)
		}

		bound := open(sqlstore.Options{SealContext: "tenant"})
		if err := read(bound); err != nil {
			t.Fatalf("reading the bound records without ReadWithoutSealContext: %v", err)
		}
		if _, err := bound.Notifications().Get(ctx, "during"); err != nil {
			t.Fatal(err)
		}
		if err := read(before); !errors.Is(err, sqlstore.ErrRecordFormat) {
			t.Fatalf("a DB without the SealContext reading the bound records = %v, want ErrRecordFormat", err)
		}
		if err := read(open(sqlstore.Options{SealContext: "another"})); !errors.Is(err, sqlstore.ErrRecordFormat) {
			t.Fatalf("a DB with another SealContext reading the bound records = %v, want ErrRecordFormat", err)
		}
		if n, err := bound.BindRecords(ctx); n != 0 || err != nil {
			t.Fatalf("BindRecords once bound = %d, %v; want 0, nil", n, err)
		}
	})
}

// BindRecords stops at a record sealed without a SealContext that
// doesn't open: sealed under another key, say.
func TestBindRecordsRefusesUnreadableRecord(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		e.opts = sqlstore.Options{Sealer: testSealer(t)}
		otherKey, raw := e.raw()
		e.opts = sqlstore.Options{}
		if err := otherKey.Notifications().Issue(ctx, "n", issuer.NotificationRecord{}); err != nil {
			t.Fatal(err)
		}
		d, err := sqlstore.New(raw, e.dialect, sqlstore.Options{Sealer: testSealer(t), SealContext: "tenant", ReadWithoutSealContext: true})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.BindRecords(ctx); !errors.Is(err, sqlstore.ErrRecordFormat) {
			t.Fatalf("BindRecords over a record it can't open = %v, want ErrRecordFormat", err)
		}
	})
}

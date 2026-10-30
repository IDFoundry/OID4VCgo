package sqlstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"

	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/storetest"
)

// forEachSealing runs fn for each dialect, with the DB sealing its
// records and without.
func forEachSealing(t *testing.T, fn func(t *testing.T, e *env)) {
	t.Helper()
	forEachDialect(t, func(t *testing.T, e *env) {
		t.Run("Unsealed", func(t *testing.T) { fn(t, e) })
		t.Run("Sealed", func(t *testing.T) {
			e.opts.Sealer = testSealer(t)
			defer func() { e.opts.Sealer = nil }()
			fn(t, e)
		})
	})
}

func TestCredentialStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		storetest.TestCredentialStoreContract(t, func() walletflow.CredentialStore { return e.db().Credentials() })
		storetest.TestSharedCredentialStoreContract(t, func() func() walletflow.CredentialStore {
			open := e.storage()
			return func() walletflow.CredentialStore { return open().Credentials() }
		})
	})
}

func TestAuthorizationStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		storetest.TestAuthorizationStoreContract(t, func() walletflow.AuthorizationStore { return e.db().Authorizations() })
		storetest.TestSharedAuthorizationStoreContract(t, func() func() walletflow.AuthorizationStore {
			open := e.storage()
			return func() walletflow.AuthorizationStore { return open().Authorizations() }
		})
	})
}

func TestGrantStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		storetest.TestGrantStoreContract(t, func() walletflow.GrantStore { return e.db().Grants() })
		storetest.TestSharedGrantStoreContract(t, func() func() walletflow.GrantStore {
			open := e.storage()
			return func() walletflow.GrantStore { return open().Grants() }
		})
	})
}

func TestDeferredStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		storetest.TestDeferredStoreContract(t, func() walletflow.DeferredStore { return e.db().Deferred() })
	})
}

func TestKeyStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		e.opts.Sealer = testSealer(t)
		storetest.TestKeyStoreContract(t, func() walletflow.KeyStore {
			ks, err := e.db().Keys()
			if err != nil {
				t.Fatal(err)
			}
			return ks
		})
	})
}

func TestKeyStoreNeedsASealer(t *testing.T) {
	if _, err := newSQLiteDB(t, sqlstore.Options{}).Keys(); err == nil {
		t.Error("Keys() without a Sealer = nil error, want an error")
	}
}

func TestKeyStoreDeclaresDurableCustody(t *testing.T) {
	ks, err := newSQLiteDB(t, sqlstore.Options{Sealer: testSealer(t)}).Keys()
	if err != nil {
		t.Fatal(err)
	}
	var c keys.KeyCustodyAssurance = ks
	if !c.KeyCustody().Durable {
		t.Error("KeyCustody().Durable = false")
	}
}

// With a Sealer, no secret a record holds reaches the database in the
// clear: not a key, a refresh token, an access token, or a credential.
func TestSealedRecordsHideSecrets(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "store.db")
	d, raw := openSQLite(t, path, sqlstore.Options{Sealer: testSealer(t)})
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	const secret = "very-secret-value"
	if err := d.Grants().PutGrant(ctx, walletflow.RefreshGrant{ID: "g", RefreshToken: fapi.NewSecret(secret)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Deferred().PutDeferred(ctx, walletflow.PendingDeferred{ID: "p", AccessToken: fapi.NewSecret(secret)}); err != nil {
		t.Fatal(err)
	}
	if err := d.Credentials().Put(ctx, walletflow.StoredCredential{ID: "c", Credential: secret}); err != nil {
		t.Fatal(err)
	}
	ks, err := d.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.NewKey(ctx, walletflow.KeyPurposeHolder); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"wallet_grants", "wallet_deferred", "wallet_credentials", "wallet_keys"} {
		for _, record := range rawRecords(t, raw, "oid4vc_"+table) {
			if bytes.Contains(record, []byte(secret)) || bytes.Contains(record, []byte("pkcs8")) {
				t.Errorf("%s holds a record in the clear: %q", table, record)
			}
		}
	}
	got, err := d.Grants().GetGrant(ctx, "g")
	if err != nil || got.RefreshToken.Reveal() != secret {
		t.Errorf("GetGrant = %v, %v; want the refresh token back", got.RefreshToken.Reveal(), err)
	}
}

// A record can't be moved to another key: the Sealer binds each to its
// own.
func TestSealedRecordsAreBoundToTheirKey(t *testing.T) {
	ctx := context.Background()
	d, raw := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), sqlstore.Options{Sealer: testSealer(t)})
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := d.Grants().PutGrant(ctx, walletflow.RefreshGrant{ID: "a", RefreshToken: fapi.NewSecret("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "UPDATE oid4vc_wallet_grants SET id = 'b' WHERE id = 'a'"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Grants().GetGrant(ctx, "b"); err == nil {
		t.Error("GetGrant of a record moved to another ID = nil error, want it refused")
	}
}

func rawRecords(t *testing.T, raw *sql.DB, table string) [][]byte {
	t.Helper()
	rows, err := raw.Query("SELECT record FROM " + table)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	if len(out) == 0 {
		t.Fatalf("%s is empty", table)
	}
	return out
}

package sqlstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// newSQLiteDB is a migrated DB on a SQLite file of its own.
func newSQLiteDB(t *testing.T, opts sqlstore.Options) *sqlstore.DB {
	t.Helper()
	d, _ := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), opts)
	if err := d.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return d
}

// openSQLite opens a DB, not migrated, on the SQLite file at path.
func openSQLite(t *testing.T, path string, opts sqlstore.Options) (*sqlstore.DB, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := sqlstore.New(db, sqlstore.SQLite, opts)
	if err != nil {
		t.Fatal(err)
	}
	return d, db
}

// requireEqualJSON fails t unless got and want encode as the same JSON.
func requireEqualJSON(t *testing.T, what string, got, want any) {
	t.Helper()
	g, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	w, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(g) != string(w) {
		t.Errorf("%s:\n got %s\nwant %s", what, g, w)
	}
}

// testSealer is an AES-256-GCM sealer under a fresh random key.
func testSealer(t *testing.T) verifier.TransactionSealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := verifier.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

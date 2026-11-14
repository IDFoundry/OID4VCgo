//go:build conformance_production

package prodwallet

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	fapisqlstore "github.com/idfoundry/fapigo/sqlstore"
	_ "modernc.org/sqlite" // the database/sql driver for the SQLite file

	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
)

// Built reports whether Open works in this binary.
const Built = true

// sealerKeyFile and databaseFile are Open's files in its directory.
const (
	sealerKeyFile = "wallet-sealer.key"
	databaseFile  = "wallet.db"
)

// Open opens, creating them if need be, the stores in dir: the SQLite
// file and the key sealing its records, kept beside it (0600), as a
// wallet's are kept across restarts.
func Open(dir string) (*Stores, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := sealerKey(filepath.Join(dir, sealerKeyFile))
	if err != nil {
		return nil, err
	}
	sealer, err := sealing.AESGCMSealer(key)
	if err != nil {
		return nil, err
	}
	// WAL mode with a busy timeout, as sqlstore's documentation says to
	// open SQLite.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, databaseFile)+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	s, err := open(db, sealer)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func open(db *sql.DB, sealer sealing.Sealer) (*Stores, error) {
	d, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{Sealer: sealer})
	if err != nil {
		return nil, err
	}
	fd, err := fapisqlstore.New(db, fapisqlstore.SQLite, fapisqlstore.Options{Sealer: sealer})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, m := range []interface{ Migrate(context.Context) error }{d, fd} {
		if err := m.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("prodwallet: migrate: %w", err)
		}
	}
	ks, err := d.Keys()
	if err != nil {
		return nil, err
	}
	return &Stores{
		Keys: ks, Custody: ks.KeyCustody(), Credentials: d.Credentials(), Authorizations: d.Authorizations(),
		Grants: d.Grants(), Deferred: d.Deferred(), Sessions: fd.Sessions(), close: db.Close,
	}, nil
}

// sealerKey reads the 32-byte key in file, or makes one there.
func sealerKey(file string) ([]byte, error) {
	key, err := os.ReadFile(file) // #nosec G304 -- the harness's own directory
	switch {
	case err == nil:
		if len(key) != 32 {
			return nil, fmt.Errorf("prodwallet: %s holds %d bytes, want 32", file, len(key))
		}
		return key, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(file, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

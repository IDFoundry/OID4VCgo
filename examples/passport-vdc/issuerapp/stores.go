package issuerapp

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	fapisqlstore "github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
	"github.com/idfoundry/fapigo/storage/memstore"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	oid4vcgostorage "github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"

	_ "modernc.org/sqlite" // the "sqlite" database/sql driver, for OpenDatabase
)

// stores are the Authorization Server's, the Credential Endpoint's
// resource verifier's and the Credential Issuer's stores: in memory, or
// in Config.Database.
type stores struct {
	transactions storage.TransactionStore
	grants       storage.GrantStore
	replay       storage.ReplayStore
	revocation   storage.RevocationStore
	dpopNonces   storage.NonceStore // the Credential Endpoint's, never the server's

	nonces        issuer.NonceStore
	preAuthCodes  issuer.PreAuthorizedCodeStore
	deferred      issuer.DeferredTransactionStore
	notifications issuer.NotificationStore

	sweep func(ctx context.Context, now time.Time) error // nil in memory
}

func memoryStores() stores {
	return stores{
		transactions: memstore.NewTransactionStore(), grants: memstore.NewGrantStore(),
		replay: memstore.NewReplayStore(), revocation: memstore.NewRevocationStore(),
		dpopNonces:    memstore.NewNonceStore(),
		nonces:        oid4vcgostorage.NewNonceStore(),
		preAuthCodes:  oid4vcgostorage.NewPreAuthorizedCodeStore(),
		deferred:      oid4vcgostorage.NewDeferredTransactionStore(),
		notifications: oid4vcgostorage.NewNotificationStore(),
	}
}

// resourceTablePrefix keeps the Credential Endpoint's DPoP nonces
// apart from the Authorization Server's, which it must never accept
// (RFC 9449 §8, §9).
const resourceTablePrefix = "fapigo_rs_"

// databaseStores are the stores in db, a SQLite database, migrated:
// fapigo/sqlstore's for the Authorization Server and the resource
// verifier, oid4vcgo/sqlstore's for the Credential Issuer, all sealed by
// sealer.
func databaseStores(ctx context.Context, db *sql.DB, sealer sqlstore.Sealer) (stores, error) {
	issuerDB, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{Sealer: sealer})
	if err != nil {
		return stores{}, fmt.Errorf("issuerapp: database: %w", err)
	}
	asDB, err := fapisqlstore.New(db, fapisqlstore.SQLite, fapisqlstore.Options{Sealer: sealer})
	if err != nil {
		return stores{}, fmt.Errorf("issuerapp: database: %w", err)
	}
	rsDB, err := fapisqlstore.New(db, fapisqlstore.SQLite, fapisqlstore.Options{TablePrefix: resourceTablePrefix, Sealer: sealer})
	if err != nil {
		return stores{}, fmt.Errorf("issuerapp: database: %w", err)
	}
	for _, m := range []interface{ Migrate(context.Context) error }{issuerDB, asDB, rsDB} {
		if err := m.Migrate(ctx); err != nil {
			return stores{}, fmt.Errorf("issuerapp: database: %w", err)
		}
	}
	return stores{
		transactions: asDB.Transactions(), grants: asDB.Grants(), replay: asDB.Replay(), revocation: asDB.Revocation(),
		dpopNonces:    rsDB.Nonces(),
		nonces:        issuerDB.Nonces(),
		preAuthCodes:  issuerDB.PreAuthorizedCodes(),
		deferred:      issuerDB.DeferredTransactions(),
		notifications: issuerDB.Notifications(),
		sweep: func(ctx context.Context, now time.Time) error {
			_, issuerErr := issuerDB.Sweep(ctx, now)
			_, asErr := asDB.Sweep(ctx, now)
			_, rsErr := rsDB.Sweep(ctx, now)
			return errors.Join(issuerErr, asErr, rsErr)
		},
	}, nil
}

// OpenDatabase opens the SQLite database at path, creating it if need
// be, for Config.Database, and the sealer for Config.DatabaseSealer,
// under a key kept in keyPath (created, readable only by its owner, if
// there is none). A demo shortcut: a deployment keeps the key in a
// secret manager or KMS, never beside the database.
func OpenDatabase(path, keyPath string) (*sql.DB, sqlstore.Sealer, error) {
	key, err := os.ReadFile(keyPath) // #nosec G304 -- operator-supplied state directory
	if errors.Is(err, fs.ErrNotExist) {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err == nil {
			err = statefile.WriteAtomic(keyPath, key)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: database key: %w", err)
	}
	sealer, err := verifier.AESGCMSealer(key)
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: database key %s: %w", keyPath, err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, nil, fmt.Errorf("issuerapp: open database: %w", err)
	}
	return db, sealer, nil
}

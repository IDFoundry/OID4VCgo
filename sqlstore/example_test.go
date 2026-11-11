package sqlstore_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// secret stands in for a key from a secret manager.
func secret(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// One database for every role: a deployment step migrates it, each
// replica checks the schema at start, and takes its stores from the DB.
// Here SQLite in a temporary directory; a deployment of several
// replicas opens PostgreSQL (sql.Open("pgx", dsn), sqlstore.Postgres).
// DEPLOYING.md is the checklist this follows.
func Example() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "sqlstore-example")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	sqlDB, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "oid4vc.db")+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		panic(err)
	}
	defer func() { _ = sqlDB.Close() }()

	// The key sealing records at rest: from a secret manager or KMS,
	// never from the database.
	sealer, err := sealing.AESGCMSealer(secret(32))
	if err != nil {
		panic(err)
	}
	db, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{Sealer: sealer})
	if err != nil {
		panic(err)
	}
	if err := db.Migrate(ctx); err != nil { // the deployment step, once per release
		panic(err)
	}
	if err := db.CheckSchema(ctx); err != nil { // each replica, at start
		panic(err)
	}

	// The Credential Issuer's stores, with stateless c_nonces.
	_ = issuer.Dependencies{
		Nonces: db.Nonces(), NonceKeys: [][]byte{secret(issuer.MinNonceKeyBytes)},
		PreAuthorizedCodes: db.PreAuthorizedCodes(), DeferredTransactions: db.DeferredTransactions(),
		Notifications: db.Notifications(), CredentialOffers: db.CredentialOffers(),
	}
	// Its status lists: indices shared by every replica, and one replica
	// signing each list's token.
	alloc := &statuslist.Allocator{
		Lists: []statuslist.AllocatorList{{URI: "https://issuer.example.com/statuslists/1", Size: 1 << 20}},
		Store: db.StatusIndices(),
	}
	_ = &statuslist.Publisher{URI: alloc.Lists[0].URI, Statuses: alloc.Statuses(alloc.Lists[0].URI), Tokens: db.StatusListTokens()}

	// The Verifier's transactions, sealed by their codec.
	_ = db.Transactions(verifier.TransactionCodec{Sealer: sealer})

	// The Wallet Provider's stores.
	_ = walletprovider.Dependencies{
		Instances: db.WalletProviderInstances(), InstanceKeys: db.WalletProviderInstanceKeys(),
		Challenges: db.WalletProviderChallenges(), StatusIndices: db.StatusIndices(),
		StatusListTokens: db.StatusListTokens(),
	}

	// A batch of three credentials takes three indices at once.
	if _, err := alloc.AllocateN(ctx, 3); err != nil {
		panic(err)
	}
	fill, err := alloc.Fill(ctx)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%d of %d indices reserved\n", fill[0].Reserved, fill[0].Limit)

	// Every few minutes, from every instance: runs that meet take turns.
	if _, err := db.Sweep(ctx, time.Now()); err != nil {
		panic(err)
	}
	// Output: 3 of 524288 indices reserved
}

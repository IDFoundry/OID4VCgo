//go:build conformance_production

package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // the database/sql driver for the SQLite file

	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
)

// openStores opens path, a SQLite file, as sqlstore's Wallet Provider
// stores, every record sealed with a key made for this process
// (sealing.AESGCMSealer): the provider runs once per run, so its key
// needn't outlive it.
func openStores(path string) (stores, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return stores{}, err
	}
	sealer, err := sealing.AESGCMSealer(key)
	if err != nil {
		return stores{}, err
	}
	// WAL mode with a busy timeout, as sqlstore's documentation says to
	// open SQLite.
	sqlDB, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return stores{}, fmt.Errorf("open %s: %w", path, err)
	}
	db, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{Sealer: sealer})
	if err != nil {
		return stores{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := db.Migrate(ctx); err != nil {
		return stores{}, fmt.Errorf("migrate %s: %w", path, err)
	}
	return stores{
		instances: db.WalletProviderInstances(), instanceKeys: db.WalletProviderInstanceKeys(),
		challenges: db.WalletProviderChallenges(), indices: db.StatusIndices(), tokens: db.StatusListTokens(),
	}, nil
}

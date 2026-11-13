//go:build conformance_production

// The transactions engine's production store (Config.Production) is
// sqlstore's, a module of its own that this module doesn't require, so
// it builds only with the conformance_production tag, in a Go
// workspace holding this module and ./sqlstore:
//
//	go work init . ./sqlstore
//	go build -tags conformance_production ./cmd/conformance-verifier

package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // the database/sql driver for the SQLite file

	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// openProductionStore opens p's SQLite file as sqlstore's
// verifier.TransactionStore — durable, atomic per transaction — each
// transaction encoded by a verifier.TransactionCodec that seals its
// response decryption key and result with p's key
// (sealing.AESGCMSealer), as verifier.AssuranceProduction requires.
func openProductionStore(p ProductionConfig) (verifier.TransactionStore, error) {
	key, err := base64.StdEncoding.DecodeString(p.SealingKey)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	sealer, err := sealing.AESGCMSealer(key)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	// WAL mode with a busy timeout, as sqlstore's documentation says to
	// open SQLite.
	sqlDB, err := sql.Open("sqlite", "file:"+p.DatabasePath+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p.DatabasePath, err)
	}
	db, err := sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := db.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate %s: %w", p.DatabasePath, err)
	}
	return db.Transactions(verifier.TransactionCodec{Sealer: sealer}), nil
}

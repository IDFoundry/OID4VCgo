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
	"encoding/base64"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/proddb"
	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// productionConns sizes the PostgreSQL connection pool.
const productionConns = 8

// openProductionStore opens p's SQLite file or PostgreSQL database as
// sqlstore's verifier.TransactionStore — durable, atomic per
// transaction — each transaction encoded by a verifier.TransactionCodec
// that seals its response decryption key and result with p's key
// (sealing.AESGCMSealer), as verifier.AssuranceProduction requires;
// and, with p.SweepInterval, sweeps it that often.
func openProductionStore(p ProductionConfig) (verifier.TransactionStore, error) {
	key, err := base64.StdEncoding.DecodeString(p.SealingKey)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	sealer, err := sealing.AESGCMSealer(key)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	sqlDB, err := proddb.Open(p.DatabasePath, p.DatabaseURL, productionConns)
	if err != nil {
		return nil, err
	}
	dialect := sqlstore.SQLite
	if sqlDB.Postgres {
		dialect = sqlstore.Postgres
	}
	db, err := sqlstore.New(sqlDB.DB, dialect, sqlstore.Options{})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Every instance migrates as it starts: on PostgreSQL under an
	// advisory lock, so instances starting together take turns.
	if err := db.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate %s: %w", sqlDB.Name, err)
	}
	if p.SweepInterval != "" {
		interval, err := time.ParseDuration(p.SweepInterval)
		if err != nil {
			return nil, fmt.Errorf("config: production.sweep_interval: %w", err)
		}
		go proddb.SweepEvery(interval, map[string]proddb.Sweeper{"verifier": db})
	}
	return db.Transactions(verifier.TransactionCodec{Sealer: sealer}), nil
}

//go:build conformance_production

// The production setup (Config.Production) keeps its records in
// sqlstore and fapigo/sqlstore, modules of their own that this module
// doesn't require, so it builds only with the conformance_production
// tag, in a Go workspace holding this module and ./sqlstore:
//
//	go work init . ./sqlstore
//	go build -tags conformance_production ./cmd/conformance-issuer

package main

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	fapisqlstore "github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"
	_ "modernc.org/sqlite" // the database/sql driver for the SQLite file

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// productionNotificationLifetime bounds how long a notification_id
// stays usable: issuer.AssuranceProduction requires a bound with a
// Notification Endpoint.
const productionNotificationLifetime = 24 * time.Hour

// productionBackend is Config.Production's backend: one SQLite file
// holding sqlstore's issuer stores and fapigo/sqlstore's Authorization
// Server and Credential Endpoint stores, every record sealed with one
// key, as sqlstore's "A whole issuer deployment" wires them.
type productionBackend struct {
	cfg      Config
	issuerDB *sqlstore.DB
	// asDB holds the Authorization Server's stores, rsDB the
	// Credential Endpoint's DPoP nonces, never the server's.
	asDB, rsDB *fapisqlstore.DB
	// signingKeys signs the access tokens, loaded from the
	// configuration rather than made per process.
	signingKeys keys.KeyManager
	// statusCache is the one statuslist.Cache the Wallet Attestation
	// and Key Attestation status checks share.
	statusCache *statuslist.Cache
}

func newProductionBackend(cfg Config) (backend, error) {
	p := cfg.Production
	sealingKey, err := base64.StdEncoding.DecodeString(p.SealingKey)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	sealer, err := sealing.AESGCMSealer(sealingKey)
	if err != nil {
		return nil, fmt.Errorf("config: production.sealing_key: %w", err)
	}
	signingKey, err := conformancecert.ParseECPrivateKeyPEM(p.AccessTokenSigningKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("config: production.access_token_signing_key_pem: %w", err)
	}
	// One process, and the key loaded from its configuration: durable,
	// not shared across instances.
	signingKeys, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: signingKey},
	}, keys.DeclareCustody(keys.KeyCustody{Durable: true}))
	if err != nil {
		return nil, err
	}

	// WAL mode with a busy timeout, as sqlstore's documentation says to
	// open SQLite.
	sqlDB, err := sql.Open("sqlite", "file:"+p.DatabasePath+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", p.DatabasePath, err)
	}
	b := &productionBackend{cfg: cfg, signingKeys: signingKeys, statusCache: statuslist.NewCache(statuslist.CacheOptions{})}
	if b.issuerDB, err = sqlstore.New(sqlDB, sqlstore.SQLite, sqlstore.Options{Sealer: sealer}); err != nil {
		return nil, err
	}
	if b.asDB, err = fapisqlstore.New(sqlDB, fapisqlstore.SQLite, fapisqlstore.Options{Sealer: sealer}); err != nil {
		return nil, err
	}
	if b.rsDB, err = fapisqlstore.New(sqlDB, fapisqlstore.SQLite, fapisqlstore.Options{TablePrefix: "fapigo_rs_", Sealer: sealer}); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, db := range []interface{ Migrate(context.Context) error }{b.issuerDB, b.asDB, b.rsDB} {
		if err := db.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("migrate %s: %w", p.DatabasePath, err)
		}
	}
	return b, nil
}

// authorizationServer runs the Authorization Server under
// server.AssuranceProduction, one instance, with fapigo/sqlstore's
// stores, the configuration's access token signing key, an audit log,
// and Wallet Attestations' status checked.
func (b *productionBackend) authorizationServer(srvCfg *server.Config, deps *server.Dependencies, clients []storage.RegisteredClientConfig, _ storage.NonceStore) (storage.NonceStore, error) {
	srvCfg.Assurance = server.AssuranceProduction
	srvCfg.Deployment = server.DeploymentSingleInstance

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range clients {
		if err := b.asDB.Clients().Put(ctx, c); err != nil {
			return nil, err
		}
	}
	clientKeys, err := b.asDB.ClientKeys(nil)
	if err != nil {
		return nil, err
	}
	accessTokens, err := server.NewJWTAccessTokens(b.signingKeys, fapi.ES256)
	if err != nil {
		return nil, err
	}
	deps.Clients, deps.ClientKeys = b.asDB.Clients(), clientKeys
	deps.Transactions, deps.Grants = b.asDB.Transactions(), b.asDB.BatchingGrants()
	deps.Replay, deps.Revocation = b.asDB.Replay(), b.asDB.BatchingRevocation()
	deps.Keys, deps.AccessTokens = b.signingKeys, accessTokens
	deps.Audit = auditLog{}
	// The attestations the suite's emulated Wallet presents carry no
	// status claim; one that did would be checked.
	deps.ClientAttestationStatus = haip.WalletAttestationStatusList{Checker: b.statusChecker(attesterRoots(b.cfg))}

	var resourceNonces storage.NonceStore
	if b.cfg.DPoPNonces {
		deps.Nonces, resourceNonces = b.asDB.Nonces(), b.rsDB.Nonces()
	} else {
		deps.Nonces = server.NoDPoPNonces{}
	}
	return resourceNonces, nil
}

// issuer runs the Credential Issuer under issuer.AssuranceProduction and
// the HAIP profile, with sqlstore's sealed stores, an audit log, and key
// attestations' status checked.
func (b *productionBackend) issuer(cfg *issuer.Config, deps *issuer.Dependencies) error {
	cfg.Assurance = issuer.AssuranceProduction
	cfg.Profile = haip.IssuerProfile{}
	cfg.Limits.NotificationLifetime = productionNotificationLifetime

	deps.Nonces = b.issuerDB.Nonces()
	deps.Notifications = b.issuerDB.Notifications()
	deps.DeferredTransactions = b.issuerDB.DeferredTransactions()
	if deps.PreAuthorizedCodes != nil {
		deps.PreAuthorizedCodes, deps.CredentialOffers = b.issuerDB.PreAuthorizedCodes(), b.issuerDB.CredentialOffers()
	}
	deps.Clock = nil // the system clock
	deps.Audit = issuerAuditLog{}
	// As for Wallet Attestations: the suite's key attestations carry no
	// status claim.
	roots, err := keyAttestationRoots(*b.cfg.KeyAttestation)
	if err != nil {
		return err
	}
	deps.AttestationStatus = issuer.StatusListAttestationStatus{Checker: b.statusChecker(roots)}
	return nil
}

// statusIndices keeps Config.StatusLists' reservations and statuses in
// sqlstore, beside the issuer's other records.
func (b *productionBackend) statusIndices() statuslist.IndexStore { return b.issuerDB.StatusIndices() }

// statusChecker fetches the Status List Tokens an attestation's status
// claim names, signed under roots, through the shared cache: from
// public addresses only, the signers' certificate revocation unchecked.
func (b *productionBackend) statusChecker(roots *x509.CertPool) statuslist.Checker {
	return statuslist.Checker{
		Roots:   roots,
		Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		Cache:   b.statusCache,
	}
}

// auditLog is the Authorization Server's and the Credential Issuer's
// audit sink: each event, one line to the process's log.
type auditLog struct{}

// Record implements server.AuditSink.
func (auditLog) Record(_ context.Context, e server.AuditEvent) error {
	log.Printf("audit: authorization server event %d, client %q, outcome %d: %s", e.Type, e.ClientID, e.Outcome, e.Description)
	return nil
}

// issuerAuditLog is auditLog for issuer.AuditSink, whose Record takes
// the issuer's own AuditEvent.
type issuerAuditLog struct{}

// Record implements issuer.AuditSink.
func (issuerAuditLog) Record(_ context.Context, e issuer.AuditEvent) error {
	log.Printf("audit: credential issuer event %d, client %q, outcome %d: %s", e.Type, e.ClientID, e.Outcome, e.Description)
	return nil
}

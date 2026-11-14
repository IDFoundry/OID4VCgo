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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/keys"
	"github.com/idfoundry/fapigo/server"
	fapisqlstore "github.com/idfoundry/fapigo/sqlstore"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/proddb"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sealing"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// productionNotificationLifetime bounds how long a notification_id
// stays usable: issuer.AssuranceProduction requires a bound with a
// Notification Endpoint.
const productionNotificationLifetime = 24 * time.Hour

// productionConns sizes the PostgreSQL connection pool.
const productionConns = 16

// productionBackend is Config.Production's backend: one SQLite file or
// PostgreSQL database holding sqlstore's issuer stores and
// fapigo/sqlstore's Authorization Server and Credential Endpoint
// stores, every record sealed with one key, as sqlstore's "A whole
// issuer deployment" wires them.
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
	// and Key Attestation status checks share, and statusFetcher their
	// fetcher.
	statusCache   *statuslist.Cache
	statusFetcher statuslist.Fetcher
	// nonceKey is ProductionConfig.NonceKey, decoded, or nil.
	nonceKey []byte
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
	// The key loaded from the configuration: durable, and the same in
	// every instance when several share the database.
	signingKeys, err := keys.NewKeyManagerFromSigners([]keys.SignerSpec{
		{Purpose: keys.AccessTokenSigning, Algorithm: fapi.ES256, Signer: signingKey},
	}, keys.DeclareCustody(keys.KeyCustody{Durable: true, CrossInstanceConsistent: p.HorizontallyScaled}))
	if err != nil {
		return nil, err
	}

	sqlDB, err := proddb.Open(p.DatabasePath, p.DatabaseURL, productionConns)
	if err != nil {
		return nil, err
	}
	dialect, fapiDialect := sqlstore.SQLite, fapisqlstore.SQLite
	if sqlDB.Postgres {
		dialect, fapiDialect = sqlstore.Postgres, fapisqlstore.Postgres
	}
	statusFetcher, err := attestationStatusFetcher(*p)
	if err != nil {
		return nil, err
	}
	b := &productionBackend{cfg: cfg, signingKeys: signingKeys, statusCache: statuslist.NewCache(statuslist.CacheOptions{}), statusFetcher: statusFetcher}
	if p.NonceKey != "" {
		if b.nonceKey, err = base64.StdEncoding.DecodeString(p.NonceKey); err != nil {
			return nil, fmt.Errorf("config: production.nonce_key: %w", err)
		}
	}
	if b.issuerDB, err = sqlstore.New(sqlDB.DB, dialect, sqlstore.Options{Sealer: sealer}); err != nil {
		return nil, err
	}
	if b.asDB, err = fapisqlstore.New(sqlDB.DB, fapiDialect, fapisqlstore.Options{Sealer: sealer}); err != nil {
		return nil, err
	}
	if b.rsDB, err = fapisqlstore.New(sqlDB.DB, fapiDialect, fapisqlstore.Options{TablePrefix: "fapigo_rs_", Sealer: sealer}); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	// Every instance migrates as it starts: on PostgreSQL under an
	// advisory lock, so instances starting together take turns.
	for _, db := range []interface{ Migrate(context.Context) error }{b.issuerDB, b.asDB, b.rsDB} {
		if err := db.Migrate(ctx); err != nil {
			return nil, fmt.Errorf("migrate %s: %w", sqlDB.Name, err)
		}
	}
	if p.SweepInterval != "" {
		interval, err := time.ParseDuration(p.SweepInterval)
		if err != nil {
			return nil, fmt.Errorf("config: production.sweep_interval: %w", err)
		}
		go proddb.SweepEvery(interval, map[string]proddb.Sweeper{"issuer": b.issuerDB, "authorization server": b.asDB, "credential endpoint": b.rsDB})
	}
	return b, nil
}

// authorizationServer runs the Authorization Server under
// server.AssuranceProduction, one instance or one of several, with fapigo/sqlstore's
// stores, the configuration's access token signing key, an audit log,
// and Wallet Attestations' status checked.
func (b *productionBackend) authorizationServer(srvCfg *server.Config, deps *server.Dependencies, clients []storage.RegisteredClientConfig, _ storage.NonceStore) (storage.NonceStore, error) {
	srvCfg.Assurance = server.AssuranceProduction
	srvCfg.Deployment = server.DeploymentSingleInstance
	if b.cfg.Production.HorizontallyScaled {
		srvCfg.Deployment = server.DeploymentHorizontallyScaled
	}

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
	if b.nonceKey != nil {
		deps.NonceKeys = [][]byte{b.nonceKey}
	}
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
	status := issuer.StatusListAttestationStatus{Checker: b.statusChecker(roots)}
	deps.AttestationStatus = status
	if b.cfg.Production.AttestationStatusAllowLoopback {
		log.Print("WARNING: attestation status lists are fetched from loopback addresses, which issuer.New refuses under production assurance: the key attestation status check runs through a wrapper it can't inspect")
		deps.AttestationStatus = uninspectedAttestationStatus{status}
	}
	return nil
}

// uninspectedAttestationStatus runs a StatusListAttestationStatus's
// check, without its CheckConfiguration, which issuer.New would call
// and which refuses a Fetcher that may reach loopback under production
// assurance (ProductionConfig.AttestationStatusAllowLoopback).
type uninspectedAttestationStatus struct {
	inner issuer.StatusListAttestationStatus
}

// CheckAttestationStatus implements issuer.AttestationStatusChecker.
func (u uninspectedAttestationStatus) CheckAttestationStatus(ctx context.Context, a issuer.VerifiedKeyAttestation) error {
	return u.inner.CheckAttestationStatus(ctx, a)
}

// statusIndices keeps Config.StatusLists' reservations and statuses in
// sqlstore, beside the issuer's other records.
func (b *productionBackend) statusIndices() statuslist.IndexStore { return b.issuerDB.StatusIndices() }

// statusChecker fetches the Status List Tokens an attestation's status
// claim names, signed under roots, through the shared cache: from
// public addresses only, unless the configuration lets it reach
// loopback, over TLS chained to the system roots or the configuration's
// anchors, the signers' certificate revocation unchecked.
func (b *productionBackend) statusChecker(roots *x509.CertPool) statuslist.Checker {
	return statuslist.Checker{
		Fetcher: b.statusFetcher,
		Roots:   roots,
		Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		Cache:   b.statusCache,
	}
}

// attestationStatusFetcher is p's attestation status list fetcher.
func attestationStatusFetcher(p ProductionConfig) (statuslist.Fetcher, error) {
	f := statuslist.Fetcher{AllowLoopback: p.AttestationStatusAllowLoopback}
	if p.AttestationStatusTLSTrustAnchorsPEM != "" {
		tlsRoots := x509.NewCertPool()
		if !tlsRoots.AppendCertsFromPEM([]byte(p.AttestationStatusTLSTrustAnchorsPEM)) {
			return f, fmt.Errorf("config: production.attestation_status_tls_trust_anchors_pem holds no PEM certificates")
		}
		f.HTTP = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12}},
		}
	}
	return f, nil
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

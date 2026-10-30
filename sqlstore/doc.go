// Package sqlstore holds durable stores for the issuer, verifier and
// walletflow packages, in a PostgreSQL or SQLite database reached
// through database/sql. It is a module of its own, so the library takes
// no database driver: bring the driver you use.
//
// # Setup
//
// Open the database with your driver, wrap it with New, and create its
// tables with Migrate:
//
//	sqlDB, err := sql.Open("pgx", dsn) // github.com/jackc/pgx/v5/stdlib
//	db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
//	err = db.Migrate(ctx)
//
// Then take each store from the DB:
//
//   - issuer.Dependencies: Nonces, PreAuthorizedCodes,
//     DeferredTransactions, Notifications and CredentialOffers. Each
//     declares issuer.StoreCapabilities Durable and AtomicConsume, as
//     AssuranceProduction requires.
//   - verifier.NewTransactions's store: Transactions, with the
//     verifier.TransactionCodec that encodes, and seals, each
//     transaction. It declares Durable and AtomicUpdate.
//   - walletflow.Dependencies: Credentials, Authorizations, Grants,
//     Deferred and, with a Sealer, Keys. Authorizations and Grants
//     report Durable, Keys declares durable custody.
//
// The Authorization Server's stores, and the Credential Endpoint's DPoP
// replay and nonce stores, are FAPIgo's: see A whole issuer deployment.
//
// For SQLite, with a driver such as modernc.org/sqlite (pure Go, no
// cgo), open the file in WAL mode with a busy timeout, so readers don't
// wait on writers and a connection waits its turn for the write lock
// instead of failing:
//
//	sql.Open("sqlite", "file:wallet.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
//
// The stores set a 10-second busy timeout themselves on each connection
// they write on (PRAGMA busy_timeout = 10000), so the DSN's matters for
// reads.
//
// # Tables and isolation
//
// The tables have fixed names, all starting oid4vc_ (oid4vc_issuer_nonces,
// oid4vc_schema_migrations, ...), and every statement the stores run is
// a constant, one set per dialect. To keep deployments, or tenants,
// sharing a PostgreSQL database apart, give each a schema of its own and
// point its connections at it with search_path — in a pgx DSN,
// postgres://…/db?search_path=tenant_a, or
// options=-csearch_path=tenant_a in a key/value one — or a role whose
// default search_path is that schema. Migrate creates the tables in the
// connection's current schema. On SQLite, use a file each.
//
// # A whole issuer deployment
//
// A Credential Issuer also runs an Authorization Server
// (fapigo/server), and its Credential Endpoint checks access tokens
// with fapigo/serverresource: their stores are FAPIgo's interfaces,
// which github.com/idfoundry/fapigo/sqlstore implements. The two
// modules share one database and one *sql.DB:
//
//	sqlDB, err := sql.Open("pgx", dsn)
//	sealer, err := verifier.AESGCMSealer(key)
//	issuerDB, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
//	asDB, err := fapisqlstore.New(sqlDB, fapisqlstore.Postgres, fapisqlstore.Options{Sealer: sealer})
//	rsDB, err := fapisqlstore.New(sqlDB, fapisqlstore.Postgres, fapisqlstore.Options{TablePrefix: "fapigo_rs_", Sealer: sealer})
//	// Migrate (or CheckSchema) each of issuerDB, asDB and rsDB.
//
//	asDeps := server.Dependencies{
//		Clients: asDB.Clients(), Transactions: asDB.Transactions(), Grants: asDB.Grants(),
//		Replay: asDB.Replay(), Nonces: asDB.Nonces(), Revocation: asDB.Revocation(),
//		// ...
//	}
//	tokens, err := serverresource.NewVerifier(asCfg, asDeps, serverresource.Options{
//		ResourceURLs: resourceURLs,
//		Nonces:       rsDB.Nonces(), // the Credential Endpoint's DPoP nonces, never the server's
//	})
//	issuerDeps := issuer.Dependencies{
//		Nonces: issuerDB.Nonces(), PreAuthorizedCodes: issuerDB.PreAuthorizedCodes(),
//		DeferredTransactions: issuerDB.DeferredTransactions(), Notifications: issuerDB.Notifications(),
//		CredentialOffers: issuerDB.CredentialOffers(),
//		// ...
//	}
//
// They keep apart:
//
//   - Tables: this package's all start oid4vc_, FAPIgo's with its
//     TablePrefix (fapigo_ by default). Never give FAPIgo's a prefix
//     starting oid4vc_: its schema_migrations table could then be this
//     package's.
//   - Migrations: each module migrates only its own tables, records its
//     version in its own schema_migrations table and, on Postgres, takes
//     an advisory lock key of its own, so they migrate in either order,
//     or at once.
//   - Isolation: a Postgres schema (search_path), or a SQLite file,
//     holds both, as it holds either alone. On SQLite, which FAPIgo's
//     stores don't declare CrossInstanceConsistent, a production
//     server.Config sets Deployment to server.DeploymentSingleInstance.
//   - Sealing: fapigo/sqlstore's Sealer has this package's method set,
//     so one sealer value serves both, and the verifier's
//     TransactionCodec too. Each module binds its records to additional
//     data of its own, so a record one sealed never opens as the
//     other's.
//
// Sweep each DB: neither sweeps the other's tables.
//
// # Migrations
//
// The schema is versioned, its migrations embedded in the package.
// Nothing migrates implicitly: Migrate applies the ones the database
// lacks, each in a transaction, once between any number of processes
// running it at once (a Postgres advisory lock; SQLite's write lock).
// Run it from a deployment step with a role that may create tables, or
// at startup; CheckSchema, at startup, fails fast where the schema is
// behind.
//
// # Atomicity
//
// Every consume-once operation is one statement or one transaction: a
// c_nonce, an authorization in progress and a deferred transaction's
// Invalidate are one DELETE (… RETURNING); a pre-authorized code's
// Consume, and every Update, reads the row with SELECT … FOR UPDATE on
// Postgres, or after BEGIN IMMEDIATE on SQLite, and writes it in the
// same transaction. So the guarantees hold across every process sharing
// the database, not just within one. Update callbacks are called once.
// A store that couldn't answer (the database unreachable, a timeout, a
// cancelled context) returns that error, never the interface's
// not-found error, which the issuer and verifier answer as the
// Wallet's fault.
//
// IDs are case-sensitive: Postgres compares them with the "C"
// collation, SQLite bytewise.
//
// # Secrets at rest
//
// The stores keep only what the library hands them: the issuer gives a
// PreAuthorizedCodeStore the hash of each code and a keyed hash of its
// Transaction Code, never either itself, and the verifier the hash of
// each response_code. Give Options a Sealer — verifier.AESGCMSealer,
// with a 32-byte key kept outside the database, in a secret manager or
// KMS — and every issuer and walletflow record is sealed too, bound to
// its table and key: a deferred transaction's issued Credentials, a
// wallet's credentials, refresh tokens and access tokens. The columns
// the stores look records up and sweep them by stay readable: keys,
// Owners, the Transaction Code hash and expiry times. The verifier's
// transactions are sealed by their TransactionCodec's own Sealer
// instead, which may be the same one. KeyStore refuses to work without
// a Sealer.
//
// A DB reads only records written as it would write them, sealed under
// its key or not sealed at all (ErrRecordFormat otherwise): to start
// sealing, or change the key, start from empty tables, or keep the old
// DB for reading until its records have expired. Changing the key
// makes every record sealed under the old one unreadable, a wallet's
// keys and credentials included.
//
// # Sweeping
//
// The stores never delete an expired record themselves: the issuer,
// verifier and wallet answer one as unknown once it has expired. Call
// Sweep periodically to delete them, so the tables, and the personal
// data in them, don't grow without bound.
//
// # Production
//
//   - Use one schema (PostgreSQL) or file (SQLite) per deployment, and
//     the same one in every process that shares its records. Credential
//     Issuers may share the issuer tables: every record keeps its Owner.
//   - Don't share a wallet's tables between users: walletflow's
//     ResumeIssuance finds an authorization by its state alone.
//   - Back up the database with the Sealer's key kept apart from it.
package sqlstore

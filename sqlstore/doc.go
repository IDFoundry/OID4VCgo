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
// The issuer's DPoP replay and DPoP nonce stores aren't here, and
// neither are FAPIgo's Authorization Server stores.
//
// For SQLite, with a driver such as modernc.org/sqlite (pure Go, no
// cgo), open the file in WAL mode with a busy timeout, so readers don't
// wait on writers and a connection waits its turn for the write lock
// instead of failing:
//
//	sql.Open("sqlite", "file:wallet.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
//
// # Migrations
//
// The schema is versioned, its migrations embedded in the package.
// Nothing migrates implicitly: Migrate applies the ones the database
// lacks, each in a transaction, once between any number of processes
// running it at once (a Postgres advisory lock; SQLite's write lock).
// Run it from a deployment step with a role that may create tables, or
// at startup; CheckSchema, at startup, fails fast where the schema is
// behind. Options.TablePrefix ("oid4vc_" by default) prefixes every
// table, so several DBs can share a database.
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
//   - Use one Options.TablePrefix per deployment, and the same one in
//     every process that shares its records. Credential Issuers may
//     share the issuer tables: every record keeps its Owner.
//   - Don't share a wallet's tables between users: walletflow's
//     ResumeIssuance finds an authorization by its state alone.
//   - Back up the database with the Sealer's key kept apart from it.
package sqlstore

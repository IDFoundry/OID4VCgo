// Package sqlstore holds durable stores for the issuer, verifier,
// walletflow, statuslist and walletprovider packages, in a PostgreSQL
// or SQLite database reached through database/sql. It is a module of its own, so the library takes
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
//     AssuranceProduction requires. Nonces is an issuer.NonceSpender
//     too, for Dependencies.NonceKeys: its Spend is one INSERT … ON
//     CONFLICT DO NOTHING on the nonce, the primary key.
//   - verifier.NewTransactions's store: Transactions, with the
//     verifier.TransactionCodec that encodes each transaction, and
//     seals its secret fields with its Sealer, or the DB's when it has
//     none. It declares Durable and AtomicUpdate, and whether it seals
//     (verifier.SealingStore), as AssuranceProduction requires.
//   - walletflow.Dependencies: Credentials, Authorizations, Grants,
//     Deferred and, with a Sealer, Keys. Authorizations and Grants
//     report Durable, Keys declares durable custody.
//   - statuslist.Allocator's Store: StatusIndices, which records the
//     Status List indices handed out to Referenced Tokens, and each
//     one's status, durably and shared between every process using
//     the database, so no index is handed out twice. Its Reserve is one
//     INSERT on the (uri, idx) primary key; its Delete deletes a
//     retired list's rows in bounded batches, then the list's count.
//   - statuslist.Publisher.Tokens and identifierlist.Publisher.Tokens:
//     StatusListTokens, through which the replicas serving a list share
//     its token, so one signs it at a time. A trigger raises a list's
//     version as StatusIndices changes one of its statuses; Claim, the
//     lease on signing a token, is one INSERT … ON CONFLICT DO UPDATE
//     … WHERE the lease is free. Each token is kept with its signer
//     (migration 0012), so a replica with another certificate signs its
//     own rather than serve it.
//   - walletprovider.Dependencies: WalletProviderInstances,
//     WalletProviderInstanceKeys and WalletProviderChallenges, with
//     StatusIndices as its StatusIndices and StatusListTokens as its
//     StatusListTokens. An instance's Create is one
//     INSERT on the id primary key and the UNIQUE key_thumbprint
//     column, so one registration key registers one instance across
//     every process; its Update is one UPDATE … WHERE id = ? AND
//     revision = ?, a compare-and-swap. An instance key's Create is one
//     INSERT on its thumbprint, the primary key, so one key belongs to
//     one instance; its Update is one UPDATE … WHERE id = ? AND
//     revision = ? AND instance_id = ?, which, as Create does, stores
//     its RetainUntil as sweep_after; its List walks one instance's
//     keys on an (instance_id, id) index. A challenge's Consume is one
//     DELETE … RETURNING.
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
// reads. Migrate and CheckSchema refuse a database that isn't in WAL
// mode: without it, most reads made under concurrent requests fail. An
// in-memory database can't be, so in tests use a file under t.TempDir().
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
//	statuses := &statuslist.Allocator{Lists: lists, Store: issuerDB.StatusIndices()}
//
// A Credential Endpoint that runs apart from the Authorization Server
// can't use the server's Dependencies: it takes its stores from
// fapisqlstore.ResourceServer(asDB, rsDB), which gives it the server's
// revocations, replay records and access tokens, and its own DPoP
// nonces.
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
//     other's. AES-GCM with random nonces allows about 2^32 seals per
//     key, which a busy issuer reaches in weeks: rotate before then
//     with fapigo/sqlstore's RotatingSealer (see Secrets at rest).
//   - The Credential Endpoint, run apart from the Authorization
//     Server, gets a database role of its own: SELECT on FAPIgo's
//     access_tokens, revocations and schema_migrations, SELECT and
//     INSERT on replay, and full access to its own prefix's tables.
//
// Sweep each DB: neither sweeps the other's tables. Only the
// Authorization Server's DB sweeps the tables it shares with the
// Credential Endpoint.
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
// c_nonce, an authorization in progress, a Wallet Provider's challenge
// and a deferred transaction's Invalidate are one DELETE (… RETURNING); a pre-authorized code's
// Consume, and every Update, reads the row with SELECT … FOR UPDATE on
// Postgres, in a READ COMMITTED transaction whatever the server's
// default isolation, or after BEGIN IMMEDIATE on SQLite, and writes it
// in the same transaction. So the guarantees hold across every process
// sharing the database, not just within one. Update callbacks are
// called once. A Wallet Provider instance's Update takes no callback:
// it's one UPDATE comparing the instance's revision, refused with
// walletprovider.ErrConflict if another Update came first.
// A store that couldn't answer (the database unreachable, a timeout, a
// cancelled context) returns that error, never the interface's
// not-found error, which the issuer and verifier answer as the
// Wallet's fault.
//
// IDs are case-sensitive: Postgres compares them with the "C"
// collation, SQLite bytewise. An ID that isn't valid UTF-8, or holds a
// NUL byte, which PostgreSQL's text columns can't hold, is never
// stored, on either dialect: a lookup, consume or delete by one finds
// nothing, as for any unknown ID, and a write refuses it. A Wallet's
// JWE kid, request_uri or c_nonce is the Wallet's to choose, so this
// keeps such a value an unknown one rather than the store's failure.
// StatusIndices treats a Status List uri the same way, and an index
// above math.MaxInt64, which a BIGINT can't hold, too: Reserve refuses
// it, and SetStatus and Status report it not reserved.
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
// transactions aren't sealed whole: their TransactionCodec's own
// Sealer, or the DB's when it has none, seals only each one's response
// decryption key and verified claims, bound to its Owner, same-device
// flag, browser binding hash, origin and query, which stay readable:
// changing one leaves the record unreadable. Its status, expiry and
// response_code hash are unprotected, so the database must be trusted
// for their integrity.
// A Wallet Provider's instances, instance keys and challenges are
// sealed too, though they hold nothing secret — an instance's public
// keys, its registration evidence's summary, its App Attest key and
// counter, and the operator's Reason for suspending or revoking it; an
// instance key's key, status list index and evidence's summary — so a
// database writer can't alter one unnoticed; an instance's key
// thumbprint and revision columns, and an instance key's instance_id
// and revision, stay readable. Unsealed, a record still names its own ID, thumbprint
// or challenge value, so one moved to another row is refused, and an
// instance key's record names its instance, so List refuses one moved
// to another instance.
// KeyStore refuses to work without a Sealer. StatusIndices' rows aren't
// sealed: a Status List publishes every status, and the indices, which
// Referenced Tokens carry, aren't secret either.
//
// Sealing keeps a record's contents from whoever can read the
// database, and makes one altered, or moved to another row or table,
// unreadable (ErrRecordFormat). It doesn't stop whoever can write the
// database from deleting a record, or putting back an older copy of
// one sealed under the same key. The readable columns aren't sealed: a
// pre-authorized code's Transaction Code hash column is checked
// against its sealed record before the code is accepted, refused as
// ErrRecordFormat if they differ, but its count of wrong Transaction
// Codes isn't sealed, so a database writer can reset it.
//
// A DB reads only records written as it would write them, sealed under
// its key or not sealed at all (ErrRecordFormat otherwise): to start
// sealing, start from empty tables. To change the key, wrap the new
// Sealer and the previous one with fapigo/sqlstore's RotatingSealer,
// which takes this package's Sealer: it seals with the new key and
// opens with either. There is no pass here that re-seals records under
// the new key, so keep the previous one for as long as records it
// sealed exist. Issuer records expire and are swept, but a wallet's
// credentials, refresh grants and keys never expire: while a wallet
// keeps any sealed under the previous key, dropping that key makes
// them unreadable, the keys and credentials lost.
//
// # Sweeping
//
// The stores never delete an expired record themselves: the issuer and
// verifier answer one as unknown once it has expired. Call Sweep
// periodically to delete them, so the tables, and the personal data in
// them, don't grow without bound. Sweep leaves the wallet's tables
// alone: walletflow forgets an expired authorization in progress,
// deleting the keys it names with it, which Sweep couldn't — but only
// when Wallet.KeysInUse lists the authorizations, or ResumeIssuance is
// called for that one. A wallet should call KeysInUse periodically, or
// the authorizations it abandoned, and their keys, stay.
//
// Sweep deletes each table's expired rows in batches of about 10,000,
// each its own transaction, so a sweep after a long pause neither holds
// one transaction across millions of rows nor, on SQLite, keeps other
// writers waiting for all of it. Run it from one process: running it
// from several at once is safe, but they only delete the same rows.
//
// Sweep deletes a Wallet Provider's challenges after their ExpiresAt,
// and its instance keys after their RetainUntil. One without, written
// before RetainUntil existed, is kept until its key next moves or
// walletprovider's Provider.SweepStatusLists gives it one, which it
// finds with InstanceKeyStore.ListUnretained. It
// leaves the instances alone: they never expire, and nothing here
// deletes one.
//
// Sweep leaves StatusIndices' table alone: an index once handed out is
// never handed out again while its list is in use, since a Referenced
// Token naming it may still be presented. The table grows by one row
// per token issued, bounded by the lists' sizes and fill limit, until
// the issuer retires a list for good and deletes it
// (StatusIndexStore.Delete): a Wallet Provider's
// Provider.SweepStatusLists does, for the lists of periods it no longer
// serves. Its single list from before periods (v0.67.0 and before)
// isn't one of them: delete it once yourself.
//
// # Production
//
//   - Use one schema (PostgreSQL) or file (SQLite) per deployment, and
//     the same one in every process that shares its records. Credential
//     Issuers may share the issuer tables: every record keeps its Owner
//     but a Credential Offer, which has none and is found by its
//     reference alone.
//   - Don't share a wallet's tables between users: walletflow's
//     ResumeIssuance finds an authorization by its state alone.
//   - SQLite takes one writer at a time: use it for a single process,
//     such as a wallet or a single-instance server, not for a
//     deployment scaled out across machines.
//   - On PostgreSQL, size each process's pool (sql.DB's
//     SetMaxOpenConns) so the pools of every replica, and FAPIgo's if
//     separate, stay below the server's max_connections, or put a
//     pooler such as PgBouncer between them. The stores hold nothing
//     on a connection between transactions (Migrate's advisory lock is
//     a transaction's), so transaction pooling serves them; with
//     PgBouncer, set max_prepared_statements for pgx's prepared
//     statements.
//   - Back up the database with the Sealer's key kept apart from it.
package sqlstore

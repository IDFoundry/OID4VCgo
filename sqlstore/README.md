# sqlstore

Durable stores for OID4VCgo's `issuer`, `verifier`, `walletflow` and
`statuslist` packages, in PostgreSQL or SQLite through `database/sql`. It's a Go
module of its own, `github.com/idfoundry/oid4vcgo/sqlstore`, so the
library itself takes no database driver.

The package documentation ([doc.go](doc.go)) is the reference: setup,
migrations, atomicity, sealing and sweeping. This page is the short
version.

## Setup

```go
import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib" // or _ "modernc.org/sqlite"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
)

sqlDB, err := sql.Open("pgx", os.Getenv("DATABASE_URL"))
// A 32-byte key from your secret manager or KMS, never from the database.
sealer, err := verifier.AESGCMSealer(sealingKey)
db, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
if err := db.Migrate(ctx); err != nil { … } // or CheckSchema, if a deployment step migrates

deps := issuer.Dependencies{
	Nonces:               db.Nonces(),
	PreAuthorizedCodes:   db.PreAuthorizedCodes(),
	DeferredTransactions: db.DeferredTransactions(),
	Notifications:        db.Notifications(),
	CredentialOffers:     db.CredentialOffers(),
	// …
}
txs, err := verifier.NewTransactions(v, db.Transactions(verifier.TransactionCodec{Sealer: sealer}), cfg)
```

walletflow's stores are `db.Credentials()`, `db.Authorizations()`,
`db.Grants()`, `db.Deferred()` and, with a Sealer, `db.Keys()`.

A `statuslist.Allocator`'s `Store` is `db.StatusIndices()`: the Status
List indices handed out, and their statuses, kept durably and shared
between processes, so no index is handed out twice. `Reserve` is one
`INSERT` on the `(uri, idx)` primary key.

```go
alloc := &statuslist.Allocator{
	Lists: []statuslist.AllocatorList{{URI: "https://issuer.example/statuslists/1", Size: 1 << 16}},
	Store: db.StatusIndices(),
}
```

SQLite (for example [modernc.org/sqlite](https://pkg.go.dev/modernc.org/sqlite),
pure Go, no cgo) needs WAL mode and a busy timeout:

```go
sql.Open("sqlite", "file:store.db?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
```

`Migrate` and `CheckSchema` refuse a database not in WAL mode, an
in-memory one among them: in tests, use a file under `t.TempDir()`.

## A whole issuer deployment

A Credential Issuer also runs a `fapigo/server` Authorization Server and
checks access tokens with `fapigo/serverresource`, whose stores are
FAPIgo's: [`github.com/idfoundry/fapigo/sqlstore`](https://pkg.go.dev/github.com/idfoundry/fapigo/sqlstore)
implements them. Both modules share one database, one `*sql.DB` and one
sealer:

```go
issuerDB, err := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
asDB, err := fapisqlstore.New(sqlDB, fapisqlstore.Postgres, fapisqlstore.Options{Sealer: sealer})
// The Credential Endpoint's DPoP nonces, never the Authorization Server's:
rsDB, err := fapisqlstore.New(sqlDB, fapisqlstore.Postgres, fapisqlstore.Options{TablePrefix: "fapigo_rs_", Sealer: sealer})
// Migrate each; take server.Dependencies' stores from asDB,
// serverresource.Options.Nonces from rsDB, issuer.Dependencies' from issuerDB.
```

A Credential Endpoint running apart from the Authorization Server takes
its stores from `fapisqlstore.ResourceServer(asDB, rsDB)`: the server's
revocations, replay records and access tokens, and its own DPoP nonces.

Their tables don't collide (`oid4vc_…` here, FAPIgo's `TablePrefix`,
`fapigo_` by default — never one starting `oid4vc_`), each migrates its
own tables under its own version table and Postgres advisory lock, one
schema or SQLite file holds both, and one sealer serves both, each
binding its records to additional data of its own. Sweep each. See
[doc.go](doc.go)'s "A whole issuer deployment".

## Running it

- **Migrations** are embedded and versioned. `Migrate` applies the
  missing ones and is safe to run from several processes at once; nothing
  migrates implicitly.
- **Isolation**: table names are fixed (`oid4vc_issuer_nonces`, …),
  and every statement is a per-dialect constant. Deployments or tenants
  sharing a PostgreSQL database each get a schema, selected with
  `search_path` (`postgres://…/db?search_path=tenant_a` with pgx);
  on SQLite, a file each.
- **Sweeping**: stores never delete expired records. Call
  `db.Sweep(ctx, time.Now())` every few minutes. It sweeps the issuer
  and verifier tables, never the wallet's. walletflow forgets an expired
  authorization, with its keys, when `Wallet.KeysInUse` lists the
  authorizations or `ResumeIssuance` is called for it: a wallet should
  call `KeysInUse` periodically, or abandoned authorizations stay.
  Status List indices are never swept or freed: an index once handed
  out is never reused.
- **Sealing**: with `Options.Sealer` every issuer and walletflow record
  is sealed, bound to its table and key. Keys, Owners, hashes and expiry
  times stay readable, for lookups and sweeping. A verifier transaction
  isn't sealed whole: its `TransactionCodec`, with its own Sealer or the
  DB's, seals only the response decryption key and the verified claims,
  bound to the owner, same-device flag, browser binding hash, origin and
  query, which stay readable. Its status, expiry and response_code hash
  are unprotected, so the database must be trusted for their integrity. To change the key, use fapigo/sqlstore's `RotatingSealer`,
  and keep the previous key while records it sealed exist: a wallet's
  credentials and keys never expire.
- **Sharing**: Credential Issuers may share the issuer tables (every
  record but a Credential Offer, found by its reference alone, keeps
  its Owner). A wallet's tables belong to one user.

## Tests

The tests run every contract suite — `issuer/issuertest`,
`verifier/verifiertest` and `walletflow/storetest`, the shared-store
ones with a separate `*sql.DB` per goroutine — against SQLite, and
against PostgreSQL too when `SQLSTORE_POSTGRES_DSN` is set:

```sh
docker run --rm -d --name sqlstore-pg -p 55432:5432 -e POSTGRES_PASSWORD=x postgres:17-alpine
SQLSTORE_POSTGRES_DSN='postgres://postgres:x@127.0.0.1:55432/postgres?sslmode=disable' go test -race ./...
docker stop sqlstore-pg
```

Each run works in a schema of its own, dropped when it ends.

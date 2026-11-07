# Deploying OID4VCgo

What a production deployment that runs several replicas on PostgreSQL
configures, role by role: the Credential Issuer, the Verifier and the
Wallet Provider. Each item names the field, the scheduled job or the
migration, and where its reference documentation is. The package
documentation stays the reference; this page is the checklist.

[`examples/passport-vdc`](examples/passport-vdc) runs every role as one
process and isn't a deployment template: its README's "One process
each, not a deployment template" says what it does differently.

## Every role: the database

- [ ] **One `sqlstore.DB` per process** over one `*sql.DB`
  (`sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: …})`).
- [ ] **Migrate first, then roll out.** Run `db.Migrate(ctx)` once, from
  one process (a deployment step, say), before the first replica of a
  new release starts: one `Migrate` applies every pending migration in
  order (on PostgreSQL under an advisory lock, so two at once wait).
  Replicas then call `db.CheckSchema(ctx)` at start, which fails while
  the schema is behind. Each release's [UPGRADING.md](UPGRADING.md)
  entry says what its migrations lock, and for how long.
- [ ] **Seal records at rest.** `Options.Sealer` encrypts every issuer,
  verifier transaction, walletflow and Wallet Provider record
  (`verifier.AESGCMSealer` makes one from a 32-byte key; the verifier's
  `TransactionCodec` takes the same Sealer). Keep the key in a secret
  manager or KMS, never in the database. An AES-GCM key seals about
  2^32 records safely: rotate before then with fapigo/sqlstore's
  `RotatingSealer` (the new key seals, every listed key opens). A
  record sealed under an old key needs it until the record is written
  again or deleted, and some are kept for long — a Wallet Provider's
  registered instances never expire — so keep each retired key in the
  `RotatingSealer` until no record needs it.
  sqlstore's doc ("Secrets at rest") has the details.
- [ ] **Size the connection pool.** `sqlDB.SetMaxOpenConns(n)` with `n`
  × replicas below the server's `max_connections` (less what other
  clients use), or put PgBouncer in transaction mode in front: the
  stores hold nothing on a connection between transactions (with pgx,
  set PgBouncer's `max_prepared_statements`). sqlstore's doc
  ("Production") covers it.
- [ ] **Sweep from one process.** `db.Sweep(ctx, time.Now())` deletes,
  in bounded batches, what has expired: the issuer's nonces,
  pre-authorized codes, credential offers, deferred transactions and
  notifications, the verifier's transactions, the Wallet Provider's
  challenges, and its instance keys past their `RetainUntil`. Run it
  periodically (every few minutes) from one process; a second one
  running at the same time is safe but wasted.
- [ ] **Rate-limit unauthenticated endpoints** in front of the
  service: the Nonce Endpoint and the Credential Offer endpoints, the
  Wallet Provider's challenge and registration endpoints
  (`walletprovider.ChallengePath`, `InstancesPath`). Each writes a
  row, and each sealed row spends the Sealer key's budget.

## Credential Issuer

- [ ] **Stores:** `issuer.Dependencies{Nonces: db.Nonces(),
  PreAuthorizedCodes: db.PreAuthorizedCodes(), DeferredTransactions:
  db.DeferredTransactions(), Notifications: db.Notifications(),
  CredentialOffers: db.CredentialOffers(), …}`.
- [ ] **`Config.Assurance = issuer.AssuranceProduction`**, so `New`
  refuses the settings production must not run with.
- [ ] **Stateless c_nonces: `Dependencies.NonceKeys`.** With it, the
  Nonce Endpoint writes nothing: a c_nonce is an HMAC under
  `NonceKeys[0]`, and only spending one at the Credential Endpoint
  writes a row. Recommended for every deployment, and especially with
  a Sealer (an anonymous request then seals nothing). Each key is at
  least `issuer.MinNonceKeyBytes` random bytes from your secret
  manager, the same on every replica. **Rotate in two phases**, so no
  replica sees a c_nonce under a key it doesn't hold: first deploy
  `[old, new]` everywhere (new accepted, not yet used), then `[new,
  old]` (new used), then, after `Config.NonceLifetime`, `[new]`.
  Enable `NonceKeys` itself the same way: every replica must have it
  before any issues a stateless c_nonce, as a replica without it
  refuses one.
- [ ] **Status lists: one `statuslist.Allocator` per process**, with
  `Store: db.StatusIndices()` and several `Lists` (each `Size` indices,
  filled to `FillLimit`, half by default): add lists before they fill,
  as an issuance fails once every list is full. Watch
  `Allocator.Fill` from monitoring, and alert while the free indices
  of the lists not yet full still cover a few days of issuance. Size each list for
  relying parties' token limit (1 MiB by default,
  `statuslist.DefaultMaxTokenBytes`): 2^20 to 2^22 one-bit entries.
  Allocate a batch's indices at once with `CredentialRequest.PerBatch`
  and `Allocator.AllocateN`.
- [ ] **Publish with `statuslist.Publisher`, sharing tokens:**
  `Publisher.Tokens = db.StatusListTokens()` (and
  `identifierlist.Publisher.Tokens`), so one replica signs each list's
  token after a status changes and the others serve it within
  `TokensCheck` (5 s by default). Without it every replica signs its
  own, and a revocation reaches another replica's readers only after
  that replica's `CacheFor`. A replica waits on another's lease to sign
  only for a bounded time, then signs its own, so one that can't sign
  doesn't hold the others back.
- [ ] **Key Attestation and Wallet Attestation status:** under
  `AssuranceProduction` the issuer checks attestations' status
  (`AttestationStatus`); give it a `statuslist.Checker` with a shared
  `statuslist.Cache` (below).

```go
db, _ := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
if err := db.CheckSchema(ctx); err != nil { … } // migrated by the deployment step

alloc := &statuslist.Allocator{Lists: lists, Store: db.StatusIndices()} // one per process
pub := &statuslist.Publisher{URI: lists[0].URI, Signer: key, Chain: chain,
	Statuses: …, Tokens: db.StatusListTokens()}

iss, err := issuer.New(cfg, issuer.Dependencies{
	Nonces: db.Nonces(), NonceKeys: nonceKeys,
	PreAuthorizedCodes: db.PreAuthorizedCodes(), DeferredTransactions: db.DeferredTransactions(),
	Notifications: db.Notifications(), CredentialOffers: db.CredentialOffers(),
	// …
})
go everyFewMinutes(func() { db.Sweep(ctx, time.Now()) }) // from one process only
```

## Verifier

- [ ] **Transactions:** `verifier.NewTransactions(v,
  db.Transactions(verifier.TransactionCodec{Sealer: sealer}), cfg)`, so
  a wallet's response can reach any replica.
- [ ] **Certificate revocation:** a `certrevocation.Refresher` per
  process (`certrevocation.NewRefresher`), run in the background with
  `Run(ctx)` after one `Refresh(ctx)` before serving, and its
  `Checker()` as every chain's `Revocation`. The Refresher fetches off
  the request path, conditionally, with jitter; a verifier that
  fetches CRLs on the request path stalls presentations whenever a list
  expires.
- [ ] **Status checks: one `statuslist.Cache` per process**, shared by
  every `statuslist.Checker` (`Checker.Cache`). Size `CacheOptions`:
  `MaxEntries` (256 by default) above the number of list URIs your
  verifiers read within the tokens' lifetime — one Wallet Provider's
  live attestations alone can name 128 (64 lists in each of the current
  and previous periods) — and `MaxBytes` (64
  MiB by default) for their decompressed size: a 2^24-entry one-bit
  list takes about 2 to 3 MiB. A `CacheOptions.Store` that keeps lists
  across restarts needs a `StoreKey` (at least 32 random bytes, kept
  apart from the store, the same on every process sharing it), or a
  kept token is reused only within `MaxAge` of its iat.

```go
crls, _ := certrevocation.NewRefresher(certrevocation.RefresherConfig{URLs: crlURLs, Issuers: cas})
if err := crls.Refresh(ctx); err != nil { … } // before serving
go crls.Run(ctx)

cache := statuslist.NewCache(statuslist.CacheOptions{MaxEntries: 1024})
checker := statuslist.Checker{Fetcher: fetcher, Roots: roots, Cache: cache}
txs, _ := verifier.NewTransactions(v, db.Transactions(verifier.TransactionCodec{Sealer: sealer}), cfg)
```

## Wallet Provider

- [ ] **Stores:** `walletprovider.Dependencies{Instances:
  db.WalletProviderInstances(), InstanceKeys:
  db.WalletProviderInstanceKeys(), Challenges:
  db.WalletProviderChallenges(), StatusIndices: db.StatusIndices(),
  StatusListTokens: db.StatusListTokens(), …}`. `StatusListTokens`
  makes one replica sign each of its status lists' tokens, as for an
  issuer's Publisher.
- [ ] **Capacity: `Config.StatusListSize`.** A period's lists hold 64
  × `StatusListSize`/2 instance keys used in it, and every issuance
  uses a new one: the default (2^16) holds about 2.1M a week. Size it
  for your fleet's issuances and refreshes per period — 2^19 or more
  for millions of wallets — and at most 2^22 unless the issuers
  checking the lists raise their token limit. The
  `walletprovider.Config.StatusListSize` doc has the formula. Watch
  `Provider.StatusListFill` from monitoring: alert when its `Free`
  won't last until its `End` at the current rate, and raise
  `StatusListSize` for the next period.
- [ ] **Run `SweepStatusLists` daily, from one process:** it deletes
  retired periods' list indices and gives instance keys recorded
  before retention existed their `RetainUntil`. `db.Sweep` then
  deletes keys past it.
- [ ] **`Config.InstanceKeyRetention`:** at least as long as an
  issuance may go unused and still be refreshed (90 days by default).
- [ ] **Evidence verifiers:** Android Key Attestation
  (`walletprovider/androidkey`) is available. **Apple App Attest isn't
  yet** (`walletprovider/appattest` is pending, and the Swift library
  has no Wallet Provider client): see the `walletprovider` package
  documentation for what an iOS deployment can do meanwhile.

```go
p, err := walletprovider.New(cfg, walletprovider.Dependencies{
	Signer: key, Chain: chain,
	Instances: db.WalletProviderInstances(), InstanceKeys: db.WalletProviderInstanceKeys(),
	Challenges: db.WalletProviderChallenges(), StatusIndices: db.StatusIndices(),
	StatusListTokens: db.StatusListTokens(),
	Evidence: []walletprovider.EvidenceVerifier{androidVerifier},
})
mux.Handle("/", p.Handler())                    // behind rate limiting
mux.Handle("/statuslists/", p.StatusLists())
go daily(func() { p.SweepStatusLists(ctx) })   // from one process only
```

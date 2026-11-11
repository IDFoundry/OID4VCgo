# Deploying OID4VCgo

What a production deployment that runs several replicas on PostgreSQL
configures, role by role: the Credential Issuer, the Verifier and the
Wallet Provider. Each item names the field, the scheduled job or the
migration, and where its reference documentation is. The package
documentation stays the reference; this page is the checklist. The
snippets below are sketches; sqlstore's `Example` (one database's
stores handed to every role, run by `go test`) and walletprovider's
`ExampleNew` are the same wiring as code that compiles.

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
  (`sealing.AESGCMSealer` makes one from a 32-byte key; the verifier's
  `TransactionCodec` takes the same Sealer). Keep the key in a secret
  manager or KMS, never in the database. An AES-GCM key seals about
  2^32 records safely: rotate before then with fapigo/sqlstore's
  `RotatingSealer`, which seals with its first sealer and opens with
  any. **Rotate in two phases**, so no replica reads a record sealed
  under a key it doesn't hold: first deploy `RotatingSealer(old, new)`
  everywhere (new opened, not yet used), then `RotatingSealer(new,
  old)` (new used). A record sealed under the old key needs it until
  the record is written again or deleted, and some are kept for long —
  a Wallet Provider's registered instances, a wallet's credentials and
  keys never expire — so keep the old key in the `RotatingSealer`
  until no record needs it.
  sqlstore's doc ("Secrets at rest") has the details.
- [ ] **Size the connection pool.** On every replica set
  `sqlDB.SetMaxOpenConns(n)` and `sqlDB.SetMaxIdleConns(n)` to the same
  `n`, with `SetConnMaxLifetime(30 * time.Minute)` and
  `SetConnMaxIdleTime(5 * time.Minute)`: `database/sql` keeps only 2
  idle connections by default, so under load most connections close
  as they're handed back and are opened again, which FAPIgo measured
  as cutting logins from 214 to 47 a second. Keep `n` × replicas, plus
  headroom, below the server's `max_connections` (less what other
  clients use), or put PgBouncer in transaction mode in front: the
  stores hold nothing on a connection between transactions (with pgx,
  set PgBouncer's `max_prepared_statements`, or
  `default_query_exec_mode=exec` in the DSN). When OID4VCgo's and
  FAPIgo's stores share one `*sql.DB`, as in sqlstore's doc, one pool
  serves both; count each separate pool otherwise. sqlstore's
  doc ("Production") and FAPIgo sqlstore's ("Performance and
  scaling") cover it.
- [ ] **Sweep from every instance.** `db.Sweep(ctx, time.Now())` deletes,
  in bounded batches, what has expired: the issuer's nonces,
  pre-authorized codes, credential offers, deferred transactions and
  notifications, the verifier's transactions, the Wallet Provider's
  challenges, and its instance keys past their `RetainUntil`. Run it
  periodically (every few minutes) from every instance, so no one
  process has to: on PostgreSQL, a run that finds another sweeping the
  same schema stops at once.
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
- [ ] **Audit: `Dependencies.Audit`**, an `issuer.AuditSink` recording
  the outcome of every pre-authorized code exchange, Credential Request
  and deferred credential, to a log kept apart from the service.
  Required under `AssuranceProduction`. Recording is best-effort: a
  sink that fails doesn't fail the request, so alert on its own
  failures.
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
  and `Allocator.AllocateN`. Keep list URIs short (a Wallet Provider's
  `Config.StatusListBaseURI` too): every reserved index's row holds
  its list's URI, about 2 bytes per character with its index, so a
  25-character URI in place of a 51-character one makes the status
  index table about a quarter smaller.
- [ ] **Publish with `statuslist.Publisher`, sharing tokens:**
  `Publisher.Tokens = db.StatusListTokens()` (and
  `identifierlist.Publisher.Tokens`), so one replica signs each list's
  token after a status changes and the others serve it within
  `TokensCheck` (5 s by default). Without it every replica signs its
  own, and a revocation reaches another replica's readers only after
  that replica's `CacheFor`. A replica waits on another's lease to sign
  only for a bounded time, then signs its own, so one that can't sign
  doesn't hold the others back.
- [ ] **Key Attestation and Wallet Attestation status:** the issuer
  checks key attestations' status (`Dependencies.AttestationStatus`,
  `issuer.StatusListAttestationStatus`; required under
  `AssuranceProduction` with an `AttestationVerifier`), and the
  Authorization Server Wallet Attestations' (fapigo's
  `server.Dependencies.ClientAttestationStatus`,
  `haip.WalletAttestationStatusList`). Give both a `statuslist.Checker`
  sharing one `statuslist.Cache` (below).
- [ ] **Authorization Server stores:** a Credential Issuer's
  Authorization Server keeps its grants and tokens in fapigo/sqlstore,
  on the same `*sql.DB` (see [sqlstore/README.md](sqlstore/README.md)'s
  "A whole issuer deployment").

```go
db, _ := sqlstore.New(sqlDB, sqlstore.Postgres, sqlstore.Options{Sealer: sealer})
if err := db.CheckSchema(ctx); err != nil { … } // migrated by the deployment step

alloc := &statuslist.Allocator{Lists: lists, Store: db.StatusIndices()} // one per process
for _, l := range lists { // a Publisher for each list, served at its URI
	pub := &statuslist.Publisher{URI: l.URI, Signer: key, Chain: chain,
		Statuses: alloc.Statuses(l.URI), Tokens: db.StatusListTokens()}
	mux.Handle(pathOf(l.URI), pub)
}

iss, err := issuer.New(cfg, issuer.Dependencies{
	Nonces: db.Nonces(), NonceKeys: nonceKeys,
	PreAuthorizedCodes: db.PreAuthorizedCodes(), DeferredTransactions: db.DeferredTransactions(),
	Notifications: db.Notifications(), CredentialOffers: db.CredentialOffers(),
	Audit: auditSink, // to your security log
	// …
})
go everyFewMinutes(func() { db.Sweep(ctx, time.Now()) }) // on every instance
```

## Verifier

- [ ] **Transactions:** `verifier.NewTransactions(v,
  db.Transactions(verifier.TransactionCodec{Sealer: sealer}), cfg)`, so
  a wallet's response can reach any replica.
- [ ] **Rate-limit the response endpoints** per client, and per
  request where the post names it: the `direct_post` response URI
  (`HandleResponse`, `HandleUnencryptedError`), and the pages' Digital
  Credentials API posts (`HandleDCAPIResponse`,
  `HandleMdocDCAPIResponse`, by their request ID). An answer is
  unauthenticated — anyone holding the request's public key can
  encrypt one — and each costs an ECDH and a decryption, then
  verification of up to `MaxPresentationsPerQuery` presentations for
  each Credential Query, each with its issuer's certificate chain and
  revocation check, before it's refused; a refused answer leaves the
  request open for the next. Bound each post's body too
  (`MaxMdocDCAPIResponseBytes` for an org-iso-mdoc answer). A refusal
  that repeats the request's `LastError` isn't written again, but a
  different one is, and every one reaches `OnRefused`.
- [ ] **Certificate revocation:** a `certrevocation.Refresher` per
  process (`certrevocation.NewRefresher`), run in the background with
  `Run(ctx)` after one `Refresh(ctx)` before serving, and its
  `Checker()` as every chain's `Revocation`. The Refresher fetches off
  the request path, conditionally, with jitter; a verifier that
  fetches CRLs on the request path stalls presentations whenever a list
  expires.
- [ ] **Status checks: one `statuslist.Cache` per process**, shared by
  every `statuslist.Checker` (`Checker.Cache`; a `verifier.StatusPolicy`
  without one is refused under `AssuranceProduction`). Size `CacheOptions`:
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
crls, _ := certrevocation.NewRefresher(certrevocation.RefresherConfig{
	URLs: crlURLs, Issuers: cas,
	// The lists accepted before this process started, so a restart
	// can't be rolled back to an older one; persist each list accepted.
	Floors:   loadCRLs(),
	OnAccept: func(url string, list *x509.RevocationList) { saveCRL(url, list) },
	// Run reports failures nowhere else: log them, and alert before a
	// list's nextUpdate passes.
	OnError: func(url string, err error) { log.Printf("CRL refresh %s: %v", url, err) },
})
if err := crls.Refresh(ctx); err != nil { … } // before serving
go crls.Run(ctx)

cache := statuslist.NewCache(statuslist.CacheOptions{MaxEntries: 1024})
checker := statuslist.Checker{Fetcher: fetcher, Roots: roots, Cache: cache,
	// Required under production: the list signers' certificates too.
	Options: statuslist.VerifyOptions{Revocation: crls.Checker()}}
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
- [ ] **Per-instance bounds: `Config.MaxInstanceKeysPerPeriod`** (128
  by default) caps the status list indices one instance's keys take
  in a period, so one instance can't fill the lists for every other:
  size it for one wallet's issuances and refreshes per period. It
  doesn't limit request rates: also **rate-limit
  `WalletAttestationPath` and `KeyAttestationPath`** per client in
  front of the service, as the unauthenticated endpoints are. Each
  signed request consumes a challenge and writes the instance's
  record. Don't key the limit on the signed request's `sub` before
  `Handler` has verified it: anyone can name another instance there.
- [ ] **Seal the provider's records: `Config.RequireSealedStore`.**
  With the `DB`'s `Options.Sealer` set, sqlstore's Wallet Provider
  stores seal each instance's record; set `RequireSealedStore` so `New`
  refuses to start when they don't (a missing Sealer), rather than
  keep instances unsealed.
- [ ] **Android revocation:** keep `androidkey.Verifier.Revocation` a
  `StatusSource` (Google's list, refreshed daily). Android instances
  are judged again before each attestation from the facts kept at
  registration (`androidkey.EvidenceVerifier` is an
  `EvidenceRechecker`), so a revoked attestation key or a tightened
  `Verifier` stops new attestations at once. When Google's list names
  a certificate of an instance's chain `REVOKED`, the provider revokes
  the instance itself, so the attestations it already holds read
  `INVALID`; `SUSPENDED` suspends it (`Resume` it once Google lifts the
  suspension). A root removed from `Roots` or a tightened policy only
  refuses: to make such instances' attestations `INVALID` too, revoke
  them with `p.RevokeWhere(ctx, match, reason)`, `match` calling the
  adapter's `Recheck` or reading `androidkey.InstanceFacts` (a
  certificate serial, a patch level).
- [ ] **Hear of recheck refusals: `Config.OnRecheckRefused`.** It's
  called with each refusal and the instance as stored afterwards
  (revoked, suspended or still active): alert on it, and revoke from
  your own logic the instances a policy refusal leaves active. It runs
  on the request's path, so hand slow work to another goroutine.
- [ ] **Run `SweepStatusLists` daily** (from any instance, or several:
  runs at once are safe): it deletes
  retired periods' list indices and gives instance keys recorded
  before retention existed their `RetainUntil`. `db.Sweep` then
  deletes keys past it.
- [ ] **`Config.InstanceKeyRetention`:** at least as long as an
  issuance may go unused and still be refreshed (90 days by default).
- [ ] **Evidence verifiers:** Android Key Attestation
  (`walletprovider/androidkey`) and Apple App Attest
  (`walletprovider/appattest`). For App Attest, list each app's App ID
  (team ID and bundle ID) in `appattest.Verifier.Apps`, and leave
  `AllowDevelopment` unset in production, so only released builds
  register. App Attest proves the app, not where its keys are: claim
  `key_storage` for iOS keys only by a `KeyStorageRule` naming
  `KeyBindingAppAssertion`, and only if you rely on your app keeping
  them in the Secure Enclave. The Swift library's `HttpWalletProvider`
  is the iOS client of the protocol
  ([mobile/WALLET_PROVIDER.md](mobile/WALLET_PROVIDER.md)).

```go
p, err := walletprovider.New(cfg, walletprovider.Dependencies{
	Signer: key, Chain: chain,
	Instances: db.WalletProviderInstances(), InstanceKeys: db.WalletProviderInstanceKeys(),
	Challenges: db.WalletProviderChallenges(), StatusIndices: db.StatusIndices(),
	StatusListTokens: db.StatusListTokens(),
	Evidence: []walletprovider.EvidenceVerifier{androidVerifier},
})
mux.Handle("/", p.Handler()) // behind rate limiting
// StatusListBaseURI is https://<host>/statuslists: StatusLists serves
// /{start}/{n} under it, so strip the base path.
mux.Handle("/statuslists/", http.StripPrefix("/statuslists", p.StatusLists()))
go daily(func() { p.SweepStatusLists(ctx) })
```

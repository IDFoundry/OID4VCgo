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
  `TransactionCodec` takes the same Sealer). A wallet on a server
  needs it too: outside `Development`, `walletflow.New` refuses its
  stores unsealed, unless `Config.UnsealedStores`. Keep the key in a
  secret manager or KMS, never in the database. An AES-GCM key seals about
  2^32 records safely: rotate before then with fapigo/sqlstore's
  `RotatingSealer`, which seals with its first sealer and opens with
  any. **Rotate in two phases**, so no replica reads a record sealed
  under a key it doesn't hold: first deploy `RotatingSealer(old, new)`
  everywhere (new opened, not yet used), then `RotatingSealer(new,
  old)` (new used). A record sealed under the old key needs it until
  the record is written again or deleted, and some are kept for long —
  a Wallet Provider's registered instances, a wallet's credentials and
  keys never expire — so keep the old key in the `RotatingSealer`
  until no record needs it. **Several tenants under one key** (a
  schema or SQLite file each, as a server keeping many users' wallets
  does): give each tenant's `DB` its own `Options.SealContext`, a
  stable tenant ID, never the schema's or file's name, or each tenant
  a key of its own. Without one, a record copied into the same table
  of another tenant's schema opens there: a database writer can move
  one user's holder keys, credentials and refresh tokens into another
  user's wallet. To add a `SealContext` to a sealed database, deploy
  it with `Options.ReadWithoutSealContext`, run `db.BindRecords(ctx)`,
  then deploy without it.
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
  row, and each sealed row spends the Sealer key's budget. Parsing a
  body, up to `MaxRequestBytes` (256 KiB) and refused at 128 + 64 ×
  `Policy.MaxKeys` JSON tokens, costs about 2 ms of CPU for one of
  that size holding one string, and under 0.5 ms for one padded with
  small tokens or members, before the challenge is looked up. The
  Verifier's request_uri (`RequestObjectHandler`) too: each fetch
  reads a row, and every request_uri POST signs a Request Object (a
  billed call with a KMS-backed signer), as does every GET of a
  request whose sealed record an earlier release wrote.
- [ ] **Server timeouts.** The handlers bound each body's size, not
  how long it takes to arrive, and Go's `http.Server` has no read or
  write timeout by default: a client trickling a body holds a
  goroutine, a connection and, on a Verifier, a slot of the response
  handlers' concurrency cap below, for as long as it likes. Set
  `ReadHeaderTimeout` (10 s, say), `ReadTimeout` (30 s; or a shorter
  per-handler read deadline with `http.ResponseController`),
  `WriteTimeout` (long enough for the outbound fetches a request may
  make before it's answered: status lists, CRLs, metadata), `IdleTimeout`
  and `MaxHeaderBytes` (64 KiB leaves room for a Client Attestation
  with its certificate chain and a DPoP proof). Or terminate at a proxy
  that buffers each request body before forwarding it. Either way,
  apply a concurrency cap to requests whose body has been read, so slow
  senders don't hold its slots.

## Credential Issuer

- [ ] **Stores:** `issuer.Dependencies{Nonces: db.Nonces(),
  PreAuthorizedCodes: db.PreAuthorizedCodes(), DeferredTransactions:
  db.DeferredTransactions(), Notifications: db.Notifications(),
  CredentialOffers: db.CredentialOffers(), …}`, on a `DB` with a
  Sealer: under `AssuranceProduction` the stores holding holders' data
  (all but `Nonces`) must seal it (`sealing.Store`).
- [ ] **`Config.Assurance = issuer.AssuranceProduction`**, so `New`
  refuses the settings production must not run with.
- [ ] **Deploying as HAIP: `Config.Profile = haip.IssuerProfile{}`.**
  Production assurance enforces what binds every deployment, not HAIP
  1.0: it takes a key-bound configuration without a Nonce Endpoint
  (each jwt proof is then good for any number of Credentials within
  `Limits.MaxProofAge`), a configuration without a `scope`, a proof
  type that doesn't accept ES256, and pre-authorized codes redeemed
  with `issuer.AnonymousPreAuthorizedCode{}`, which authenticates no
  client. With the profile, `New` also runs `haip.ValidateIssuerConfig`,
  at either assurance level, and refuses each of those (HAIP 1.0 §4.1,
  §7, §4.4.1), and a scope that configurations of different Credential
  Types, or with different key attestation requirements, share (§4.3,
  §4.5.1). A HAIP deployment sets it. Its errors start
  `issuer: profile: haip:` and name what to change: `endpoints.nonce`,
  a configuration's `scope` or `proof_signing_alg_values_supported`, or
  `pre_authorized_code_client_authentication`. Take the proof types
  from `haip.RecommendedIssuerConfig` (jwt proofs carrying a key
  attestation) and the Authorization Server's settings from
  `haip.RecommendedAuthorizationServerConfig`.
- [ ] **Lifetimes within production's bounds.** Under
  `AssuranceProduction`, `New` refuses a
  `Limits.CredentialOfferLifetime` over
  `issuer.MaxProductionCredentialOfferLifetime` (a week, the longest a
  pre-authorized code lives) and a `Limits.DeferredTransactionLifetime`
  over `issuer.MaxProductionDeferredTransactionLifetime` (30 days).
  With `Dependencies.AccessTokens` set, it refuses a
  `Limits.AccessTokenLifetime` over
  `issuer.MaxProductionAccessTokenLifetime` (10 minutes): an access
  token `ExchangePreAuthorizedCode` mints names no grant, so revoking
  the grant leaves it usable until it expires. There's no opt-out: to
  issue longer-lived tokens, redeem codes with
  `RedeemPreAuthorizedCode` and issue each token with fapigo's
  `server.Server.IssueAccessToken` under the grant's `GrantID`, so
  that revoking the grant ends it.
- [ ] **Access tokens for this Credential Issuer alone.** List
  `Config.Issuer` in the Authorization Server's `server.Config.Resources`,
  and set `serverresource.Options.Resource` to it, so the Credential
  Endpoint takes only tokens whose `aud` names it
  (`AuthorizedRequest.Audience`, required under `AssuranceProduction`).
  At the consent step, grant `Issuer.AuthorizationResources` as
  `GrantedAuthorization.Resources` and deny the request when it fails;
  at the pre-authorized Token Endpoint, pass the request's resources as
  `ExchangePreAuthorizedCodeRequest.Resources` and issue the token with
  `RedeemedPreAuthorizedCode.Resource` alone, and its refresh token
  with it as `server.IssueRefreshTokenRequest.Resources`. List an
  Authorization Server in `Config.AcceptedAccessTokenAudiences` only
  when it serves this Credential Issuer alone. Without these, on an
  Authorization Server shared with other Credential Issuers, one
  issuer's token can be taken by another for its own holder of the
  same subject value.
- [ ] **A shared Authorization Server has an identifier of its own.**
  A token issued without a resource is addressed to the Authorization
  Server, and a Credential Issuer whose `Config.Issuer` is the
  Authorization Server's identifier takes every such token for its
  own, whichever Credential Issuer's grant it came from. On an
  Authorization Server serving several Credential Issuers, give it an
  identifier none of them has, listed in each one's
  `Config.AuthorizationServers`. If one must keep sharing it, confine
  every wallet client to the Credential Issuers with FAPIgo's
  `storage.RegisteredClientConfig.AllowedResources` (and
  `server.Config.AutomaticRegistration.AllowedResources`), listing
  each: the Authorization Server then issues no token addressed to
  itself, and every Wallet must name its Credential Issuer as its
  `resource` (`invalid_target` otherwise), the co-hosted one's
  included, though its metadata lists no `authorization_servers`.
  `issuer.New` can't tell an Authorization Server serving others, so
  it checks neither.
- [ ] **Grants from before v0.82.0.** Their refresh tokens carry no
  resource, so each refreshes into a token addressed to the
  Authorization Server. That's still accepted by a Credential Issuer
  that is the Authorization Server's only one, and shares its
  identifier or lists it in `Config.AcceptedAccessTokenAudiences`.
  Otherwise, where the Authorization Server has an identifier of its
  own, the Credential Issuers refuse those tokens and the Wallet must
  authorize again; revoke the grants to have it learn so at the Token
  Endpoint.
  Where a Credential Issuer shares the identifier of an Authorization
  Server serving others, end them before the upgrade serves anyone:
  `AllowedResources` refuses their refresh with `invalid_target`, or
  revoke them.
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
  manager, the same on every replica: make one with `openssl rand 32`,
  or use the text of `openssl rand -hex 32` or `-base64 32` as its
  bytes. Never a password: `issuer.New` refuses, under
  `AssuranceProduction`, a key that plainly isn't random, such as a
  repeated character or word. **Rotate in two phases**, so no
  replica sees a c_nonce under a key it doesn't hold: first deploy
  `[old, new]` everywhere (new accepted, not yet used), then `[new,
  old]` (new used), then, after `Config.NonceLifetime`, `[new]`.
  Enable `NonceKeys` itself the same way: every replica must have it
  before any issues a stateless c_nonce, as a replica without it
  refuses one. **Keep the clocks within 5 minutes of each other**, on
  every replica and every instance running `db.Sweep` (NTP, with an
  alert on clock offset): a spent c_nonce's row is kept 5 minutes past
  the nonce's expiry, so a `db.Sweep` on a clock further ahead of a
  replica's deletes it while that replica still takes the c_nonce as
  unexpired, and it accepts it again.
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
  doesn't hold the others back. An identifier list keeps no version in
  the store, so its tokens are ordered by when they were signed: keep
  the replicas' clocks synchronised, or one whose clock runs ahead can
  hold a revocation `Invalidate` was called for back by up to
  `CacheFor` plus the skew.
- [ ] **Key Attestations bound to their Wallet Provider by anchor:**
  where `X5CAttestationVerifier.Roots` certify several Wallet
  Providers, as a shared trust list does, set
  `IssuerBinding: issuer.AttestationIssuerBoundToAnchor` with each
  provider's `Anchors` (and fapigo's `AttesterIssuerBoundToAnchor` for
  Wallet Attestations). `AttestationIssuerInCertificate` binds the
  `iss` to a URI in the certificate, which any provider's CA can write
  unless it carries `uniformResourceIdentifier` name constraints:
  `dNSName` constraints don't apply to URIs (RFC 5280 §4.2.1.10).
  Keep those roots and anchors apart from
  `X5CProofBindingKeyResolver.Roots`, which certify keys Wallets hold:
  `New` refuses any they may share unless the verifier's `LeafPolicy`
  requires what only a Wallet Provider's signing certificates carry
  (an extended key usage or a certificate policy), as a Wallet could
  otherwise sign its own key attestations.
- [ ] **Key Attestation and Wallet Attestation status:** the issuer
  checks key attestations' status (`Dependencies.AttestationStatus`,
  `issuer.StatusListAttestationStatus`; required under
  `AssuranceProduction` with an `AttestationVerifier`), and the
  Authorization Server Wallet Attestations' (fapigo's
  `server.Dependencies.ClientAttestationStatus`,
  `haip.WalletAttestationStatusList`). Give both a `statuslist.Checker`
  sharing one `statuslist.Cache` (below).
- [ ] **A status checker that checks its own configuration:**
  `issuer.New` checks the issuer's checker, and fapigo's `server.New`
  the Authorization Server's, through its `CheckConfiguration`
  (`server.ClientAttestationStatusAssurance`). Under
  `AssuranceProduction`, `haip.WalletAttestationStatusList`'s refuses
  a `Fetcher` that may reach loopback or private addresses, no
  `Options.Revocation` (the list signers' certificates unchecked) and
  no `Cache` (the list fetched again on every attestation-authenticated
  request). A checker of your own must implement that method under
  production, and a wrapper around `WalletAttestationStatusList` that
  fetches some other way must override it.
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
- [ ] **An explicit `TransactionsConfig.Scope` for each policy** where
  several `Transactions` share one store: each reads only the
  transactions of its own scope. The scope derived when `Scope` is
  unset tells apart only Verifiers that differ in client_id,
  `ResponseURI` or `RequestURIBase`, so one Verifier's Digital
  Credentials API `Transactions` with different `Verify` or `Accept`
  policies (`RequestURIBase` unset in each) share one, and any of them
  can complete or read another's request under its own policy:
  `AssuranceProduction` refuses such a `Transactions` without a
  `Scope`. Keep each `Scope` the same on every replica.
- [ ] **Rate-limit the response endpoints** per client, and per
  request where the post names it: the `direct_post` response URI
  (`HandleResponse`, `HandleUnencryptedError`), and the pages' Digital
  Credentials API posts (`HandleDCAPIResponse`,
  `HandleMdocDCAPIResponse`, by their request ID). An answer is
  unauthenticated — anyone holding the request's public key can
  encrypt one — and a refused answer leaves the request open for the
  next. Each answer costs an ECDH, a decryption and parsing up to
  1 MiB of JSON (one pass refusing it at 131,072 values and member
  names, and its `vp_token` at its first member that isn't one of the
  request's Credential Queries or its 33rd presentation for one; a
  Digital Credentials API post's object at 1,024: 10 to 12 ms of CPU
  for a mebibyte, whether of one string or of small tokens, and 22 ms
  for the costliest shape, about 65,000 distinct names in one object;
  a 2 MiB post, 4 to 5 ms), then, for up to `MaxPresentationsPerQuery`
  presentations per Credential Query (more than one only under
  `multiple`): a hash identifying the credential (an SD-JWT's
  Issuer-signed header and payload, an mdoc's Mobile Security Object),
  so that one presented twice refuses the answer at the second copy,
  unverified; the issuer signature, checked once, with the presented
  leaf certificate's key through a built-in resolver, whatever curve
  the sender gave that key (a P-521 check costs about 30 times a P-256
  one); path building over the issuer's presented certificate chain
  (anchored at one of its top two certificates and checked from there
  down: a crafted one costs at most two signature checks per configured
  root sharing a name with its top, plus about two where a root anchors
  it, however long it is; a genuine one, replayed, a check per
  certificate, at most eight); the SD-JWT disclosures the signed payload
  references; the KB-JWT or mdoc device signature; and a revocation
  check per path. With the built-in `X5CIssuerKeyResolver` and
  `X5ChainIssuerKeyResolver` as the request's `IssuerKeys` and
  `MdocIssuerKeys`, each distinct chain is verified once per answer. A
  presentation discarded because one of those checks failed (its issuer
  signature, validity or digests, a chain no root anchors, its holder
  binding) counts toward `MaxFailedPresentationsPerResponse` (4) across
  the answer's Credential Queries, and once that many have, the answer
  is refused at the next presentation, unverified. Presentations that
  verify aren't counted, nor are ones discarded for what they say (not
  answering the query, unrequested claims) or whose trusted issuer is
  refused (revocation, leaf policy, `IssuerAuthorized`); a resolver of
  your own, even one dispatching to the built-in ones, gets neither the
  leaf-key check nor the per-answer chain memo, and its refusals aren't
  counted. Measured on a development machine where one P-521 signature
  check costs 2.1 ms of CPU and one P-256 check 0.07 ms, through
  `HandleResponse` under `multiple`: an honest one-presentation answer
  costs 0.8 ms on a P-256 issuer PKI and 11 ms on a P-521 one; 32
  self-made P-521 leaves under signatures that don't verify, refused
  after the fourth, 9–10 ms whatever the issuer PKI; 32 crafted chains,
  2 ms (P-256) or 20 ms (P-521); 32 copies of a genuine credential with
  a KB-JWT that doesn't verify, refused at the second copy, 2 ms or
  13 ms; one genuine issuer JWT padded with a mebibyte of disclosure
  parts, 17–28 ms. Not capped: presentations of distinct genuine
  credentials that verify, or are discarded for what they say or their
  issuer's revocation. Each costs its issuer signature at its issuer's
  curve, its chain once per answer, and, unless refused before it, its
  KB-JWT; up to 32 of them per Credential Query cost what an honest
  answer presenting that many does, and sending them takes that many
  credentials of the sender's own (and their holder keys, unless
  revoked). An org-iso-mdoc answer over the
  Digital Credentials API (ISO/IEC TS 18013-7 Annex C:
  `HandleMdocDCAPIResponse`, or `mdocdcapi.VerifyResponse` and
  `VerifyResponseDocuments` directly) is covered the same way, through
  `verifier.ResponseIssuerChains`: each document's `IssuerAuth` checked
  with its `x5chain` leaf's key first, each distinct chain verified once
  per answer, refused once `MaxFailedIssuerChainsPerResponse` distinct
  chains haven't verified; and the first document that fails
  refuses the whole answer, so at most one chain that doesn't verify is
  checked per answer. So limit by concurrency as
  well as by rate: cap the response
  handlers' in-flight requests per instance (a semaphore, or your
  proxy's connection limit) so that a burst queues or is refused
  rather than taking every core. Bound each post's body too
  (`MaxMdocDCAPIResponseBytes` for an org-iso-mdoc answer). A refusal
  that repeats the request's `LastError` isn't written again, but a
  different one is, and every one reaches `OnRefused`.
- [ ] **Issuer key resolvers that verify chains:** `IssuerKeys` an
  `X5CIssuerKeyResolver` and `MdocIssuerKeys` an
  `X5ChainIssuerKeyResolver`, or resolvers of your own that wrap them
  and `Unwrap` to them (`SDJWTVCIssuerKeyResolverWrapper`,
  `MdocIssuerKeyResolverWrapper`), so that each credential has the
  `IssuerAnchor` that verified it. `AssuranceProduction` refuses any
  other; only where SD-JWT VC issuers' keys are trusted without
  certificates (issuer metadata's JWKS, DIDs) set
  `AllowUnanchoredSDJWTVCIssuers`, and have `IssuerAuthorized` identify
  issuers by what your resolver checked, not by `IssuerChain`.
- [ ] **Which issuer may issue which type:** a root in your issuer
  roots vouches for who signed a credential, not for what it may
  issue, and any root can certify a leaf with any name, or copy another
  root's name and key identifier into what it signs. Where your roots
  are several providers' (a PID provider's and a loyalty club's, say),
  pick one:
  - per-type roots: `X5CIssuerKeyResolver.RootsByVCT` and
    `X5ChainIssuerKeyResolver.RootsByDocType` (`WithIssuerRootsByDocType`
    on a proximity reader), each type held to its own providers'
    anchors. With `Roots` set too, a type `RootsByVCT` doesn't name
    falls back to them: `X5CIssuerKeyResolver.FallbackTypes`, run on
    your queries at startup or in a test, reports which of their
    `vct_values` do;
  - `IssuerAuthorized` (`WithIssuerAuthorization`) deciding by
    `IssuerAuthorization.IssuerAnchor`, the root that verified the
    chain, compared by key with the anchors you assign to each type
    (`verifier.AnchorIs`, `verifier.AnchorHasKeyIdentifier`) and
    refusing a nil one, never by `Issuer` or the chain's names and
    authority key identifiers;
  - per query, `trusted_authorities` with an `aki` entry naming the
    type's CAs, checked by `dcql.AKITrustedAuthoritiesChecker` with
    `Roots` or `Anchors`.

  `AnyIssuerForAnyType` (`WithAnyIssuerForAnyType`) is right only
  where every root is trusted for every type you request. Name
  constraints don't change this for an https `iss`: a member CA your
  trust list confines to its own domain with `dNSName` constraints can
  still certify another member's URI, since only
  `uniformResourceIdentifier` constraints apply to URIs (RFC 5280
  §4.2.1.10), so `RequireIssuerName` tells such members apart only
  under URI constraints, or for `dns:` issuers.

  A wallet (walletflow) has the same choice for what it receives: with
  one pool of every provider's roots in `Config.IssuerRoots`, any of
  them can issue a credential of another's type, which the wallet
  stores, shows and offers as that type. `Config.IssuerRootsByVCT` and
  `MdocIssuerRootsByDocType` (`issuers.rootsByVCT` and
  `issuers.mdocRootsByDocType` in the Swift and Kotlin libraries) hold
  each type to its own providers' anchors, an SD-JWT VC's `aka_vcts`
  types too, on receipt and in `CheckStatus`. A Verifier still decides
  for itself.
- [ ] **Certificate revocation:** a `certrevocation.Refresher` per
  process (`certrevocation.NewRefresher`), run in the background with
  `Run(ctx)` after one `Refresh(ctx)` before serving, and its
  `Checker()` as every chain's `Revocation`. The Refresher fetches off
  the request path, conditionally, with jitter; a verifier that
  fetches CRLs on the request path stalls presentations whenever a list
  expires. It reads at most `MaxBytes` of a list, 1 MiB by default,
  hundreds of times an IACA's or an issuer CA's: raise it for a CA
  whose lists are larger.
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
	// Leave Issuer, IssuerKey and UnboundSigner unset: a StatusPolicy
	// binds each list's signer to its own credential's issuer.
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
- [ ] **`Config.Assurance = walletprovider.AssuranceProduction`**, so
  `New` refuses what production mustn't run with:
  - `walletprovidertest.FakeVerifier`, whose evidence anyone can
    write: a provider built with it registers anyone and attests any
    key, at whatever security level it was set to report;
  - stores that don't seal their records (below);
  - the evidence verifiers' development settings, which each verifier
    refuses through its `CheckConfiguration`
    (`walletprovider.ConfigurationCheck`): App Attest's
    `AllowDevelopment`, and an Android `StatusSource` with
    `AllowLoopback`. A verifier of your own that wraps one should
    forward the method, or embed the wrapped verifier.

  It takes `androidkey.EvidenceVerifier.AllowUncheckedLegacyEvidence`,
  whose upgrade window (below) production needs too.
- [ ] **Capacity: `Config.StatusListSize`.** A period's lists hold 64
  × `StatusListSize`/2 instance keys used in it, and every issuance
  uses a new one: the default (2^20) holds about 33.5M a week. Size it
  for your fleet's issuances and refreshes per period, with a margin
  of several times (5M wallets refreshing twice a week use about 10M),
  and at most 2^22 unless the issuers checking the lists raise their
  token limit. The `walletprovider.Config.StatusListSize` doc has the
  formula. At 2^20, a list packs to 256 KiB, so its token stays under
  a Relying Party's default 1 MiB limit whatever its statuses; an
  issuer's `statuslist.Cache` keeps each decoded (256 KiB), so the
  provider's 128 lists an attestation can name take half its default
  64 MiB `MaxBytes`; and sqlstore keeps a row per index handed out,
  not per index. Once a period's lists are full, a recorded instance
  key last used in the previous period keeps its index there, without
  counting against `MaxInstanceKeysPerPeriod`, so wallets that renewed
  in the previous period keep their Wallet Attestations through that
  one full period, but every new instance key, and so every new
  issuance, is refused (HTTP 500) until the period ends. A key whose
  index is older is refused too: lists filled again in the next period
  refuse established wallets from then on, so treat a full period as
  an incident, not a state to ride out.
- [ ] **Recently registered instances: `Config.RecentInstanceStatusLists`**
  (16 of the 64 lists, a quarter, by default). The keys of an instance
  registered in the current or previous period take indices from these
  lists alone; other instances' keys from any list, these chosen in
  proportion to their share while they're no fuller than the rest, so
  they hold established wallets' keys about as densely as the rest,
  without taking the room recent instances need while the rest have
  it. Each instance costs only one piece of
  registration evidence, and its recorded keys move to each new
  period's lists without any, so this keeps instances registered in a
  burst from filling the lists the wallets registered before need.
  Once the share is full, a recent instance's new instance key is
  refused (HTTP 500 `server_error`) until the next period, logged as
  "the status lists of the current period that recently registered
  instances take indices from are full"; nothing is revoked or
  forgotten. A burst that fills it refuses new wallets' first keys for
  two periods, not one: its instances are still recent in the next
  period, and their recorded keys move there without evidence, filling
  the share again.
  - **Size for the share too.** Recent instances' keys have about a
    quarter of the capacity (8.4M at 2^20). When established keys are
    used early in a period and recent ones late, the established ones
    take part of the share first, so where r of a period's keys are
    recent instances', they all fit only while the period uses no more
    than 1/(1+3r) of the capacity.
  - **Count Android re-registrations as recent.** An Android wallet
    registers again, as a new instance, when its Remote Key
    Provisioning certificates expire (`registration_expired`), every
    few weeks, so a third or more of its keys may be a recent
    instance's: at r = 1/3, the share binds at about half the capacity
    (16.7M at 2^20).
  - Raise it for a launch that registers most of your fleet in a week
    or two; `MaxStatusListsPerPeriod` turns it off.
  - **What a key's list tells an issuer.** A key on list 16 or later
    tells it its instance was registered before the previous period.
    One on lists 0 to 15 is a recent or an established instance's:
    about four times as likely a recent one's as a key across all
    lists is (where 5 % of a period's keys are recent instances', 20 %
    of those on lists 0 to 15 are), and certainly one once recent
    instances' keys alone fill the share.
  - **What a suspension or revocation tells an issuer.** `Suspend`,
    `Resume` and `Revoke` change the status of every one of the
    instance's keys at once, and status changes are rare, so an issuer
    holding two of its issuances, or issuers pooling theirs, see
    exactly those indices change between two fetches of the lists and
    link them: to one instance, and everything those keys do from then
    on. A suspension later lifted leaves them linked all the same.
    Spreading the writes over the lists' TTL wouldn't hide them, as an
    issuer may fetch the lists as often as it likes.
- [ ] **Alert on the status lists filling.** Watch
  `Provider.StatusListFill` from monitoring, every few minutes:
  - when its `Free` won't last until its `End` at the current rate;
  - when `Free`, or `RecentInstanceFree`, falls fast early in a period,
    far faster than in the same hours of the last period: many
    instances renewing, or registering, at once;
  - on the log line above: recently registered instances refused.

  The response: raise `StatusListSize`, which takes effect at once,
  for the current period's lists too (roll it out to every replica
  quickly, see UPGRADING.md), then look into the recent registrations
  and revoke what you find (`Provider.RevokeWhere`).

  These raise an attacker's cost and stop sudden bursts; they don't
  make filling the lists impossible. At 2^20, filling a period's lists
  takes about 33M instance keys, each recorded once with its own
  hardware-backed key attestation, and at least three quarters of them
  used by instances registered before the previous period, whether
  recorded then or moved without evidence, as recorded keys move to
  each new period's lists. But
  Android exposes no device identity, so the provider can't tell one
  device registering many instances from many devices, and a patient,
  well-funded attacker who registers instances over several periods
  can still fill a period.
- [ ] **Per-instance bounds: `Config.MaxInstanceKeysPerPeriod`** (128
  by default) caps the status list indices one instance's keys take
  in a period, so one instance can't fill the lists for every other:
  size it for one wallet's issuances and refreshes per period. It
  bounds one instance, not an attacker with many: each instance costs
  only one piece of registration evidence, so size `StatusListSize`
  with a margin, as above, and keep `RecentInstanceStatusLists`. It
  doesn't limit request rates: also **rate-limit
  `WalletAttestationPath` and `KeyAttestationPath`** per client in
  front of the service, as the unauthenticated endpoints are. Each
  signed request consumes a challenge and writes the instance's
  record. Don't key the limit on the signed request's `sub` before
  `Handler` has verified it: anyone can name another instance there.
  `Suspend`, `Resume` and `Revoke` write the instance's record too,
  retrying for up to 10 seconds while its own requests beat them, so a
  thief's traffic can't hold off a revocation; their `ErrConflict` past
  that is transient: call again.
- [ ] **Seal the provider's records.** With the `DB`'s
  `Options.Sealer` set, sqlstore's Wallet Provider stores seal each
  instance's record. Under `AssuranceProduction`, `New` refuses to
  start when they don't (a missing Sealer), rather than keep instances
  unsealed. `Config.UnsealedStores` accepts stores that don't, where
  they're as protected as the provider's signing key (an in-memory
  store is); `Config.RequireSealedStore` refuses them at any level,
  `UnsealedStores` or not.
- [ ] **Android revocation:** keep `androidkey.Verifier.Revocation` a
  `StatusSource` (Google's list, refreshed daily, ahead of its
  `MaxAge`, in the background). While Google can't be reached, the
  last list is used for `StatusSource.Grace` past `MaxAge` (12 hours by
  default; a certificate Google lists meanwhile is found only once a
  fetch succeeds); after that, Android registrations and attestations
  are answered HTTP 503 `server_error` with a `Retry-After`
  (`walletprovider.ErrUnavailable`), which wallets retry, not
  `evidence_rejected`. Alert on 503s and on `ErrStatusUnavailable` in
  the provider's log. Android instances
  are judged again before each attestation from the facts kept at
  registration (`androidkey.EvidenceVerifier` is an
  `EvidenceRechecker`), so a revoked attestation key or a tightened
  `Verifier` stops new attestations at once. When Google's list names
  a certificate of an instance's chain `REVOKED`, the provider revokes
  the instance itself, so the attestations it already holds read
  `INVALID`; `SUSPENDED` suspends it (`Resume` it once Google lifts the
  suspension). Should a status write fail part-way (a store failure),
  the instance is still refused, and its `KeyStatusesFor` isn't yet
  its `State`: `OnRecheckRefused` hears of it, the request fails as the
  provider's own failure, and the next request sets the rest before it's
  refused. Don't wait for one: `Revoke` (or `Suspend`) the instance
  `OnRecheckRefused` names, or run
  `p.RevokeWhere(ctx, func(in walletprovider.Instance) bool { return in.State == walletprovider.StateRevoked }, "")`,
  which finishes every pending revocation. Google's verdict is
  consulted first, and wins even when a root removed from `Roots`, a
  tightened `Verifier` or a tightened
  `Policy` would refuse the instance too — whether it names the
  registration's chain, or the chain of the instance key the request
  names, which under Remote Key Provisioning can have intermediates of
  its own. A root removed or a tightened
  policy alone only refuses: to make such instances' attestations
  `INVALID` too, revoke them with `p.RevokeWhere(ctx, match, reason)`,
  `match` calling the adapter's `Recheck` or reading
  `androidkey.InstanceFacts` (a certificate serial, a patch level).
  It goes on past an instance it fails to revoke, and its error, a
  `*walletprovider.RevokeWhereError`, names each one: run it again,
  which finishes them too.
  Keep a verifier in `Dependencies.Evidence` for every `Kind` your
  instances registered with, under that Kind: an instance whose Kind
  no verifier has is refused by policy (`OnRecheckRefused` hears of
  it), and `androidkey.EvidenceVerifier` served under another Kind
  than `androidkey.EvidenceKind` refuses every registration and fails
  every recheck as a misconfiguration (`ErrConfig`).
- [ ] **Expect Android instances to re-attest.** The recheck also
  judges each kept certificate's validity period, as `Verify` judges a
  chain's, so an instance whose registration chain has a certificate
  past its `NotAfter` gets nothing more until it registers again, and
  an instance key whose own chain has expired until the wallet attests
  a new instance key (the instance itself stays usable for that).
  Attestation certificates Remote Key Provisioning issues live for
  weeks, so on most current devices this is routine, not an incident:
  the refusal is HTTP 403 `registration_expired` or
  `instance_key_expired` (`walletprovider.ErrRegistrationExpired`,
  `ErrInstanceKeyExpired`), which tells the wallet what to send fresh
  evidence for; it wraps `androidkey.ErrCertificateValidity` and
  `walletprovider.ErrEvidenceExpired`, reaches `OnRecheckRefused`, and
  neither revokes nor suspends the instance. `androidkey.Facts.Expiry`
  says when an instance's (`InstanceFacts`) or instance key's
  (`InstanceKeyFacts`) chain expires.
- [ ] **Records from before an upgrade: `AllowUncheckedLegacyEvidence`.**
  An Android instance registered with v0.75.3 or before has no facts,
  an instance key recorded with v0.80.0 or before has none, and facts
  saved by v0.80.0 or before hold no validity periods: none can be
  judged in full, and `androidkey.EvidenceVerifier` refuses them
  (`androidkey.ErrLegacyFacts`; `registration_expired` or
  `instance_key_expired`), so their wallets
  must register again, or attest a new instance key. To give wallets
  in the field time to, set `AllowUncheckedLegacyEvidence` for an
  upgrade window: such records are then accepted, their expiry
  unchecked, and whatever facts they hold still judged (root, status
  list, policy). Before ending the window, find the instances still
  affected (a `match` that records them and returns false only lists
  them), and revoke them if you'd rather their live attestations read
  `INVALID`:

  ```go
  legacy := func(in walletprovider.Instance) bool {
  	f, ok, err := androidkey.InstanceFacts(in)
  	return in.Evidence.Kind == androidkey.EvidenceKind && err == nil && (!ok || !f.ValidityRecorded())
  }
  // An instance's own facts only: an instance key recorded with
  // v0.80.0 or before is refused on its own, and the wallet attests a
  // new one.
  n, err := p.RevokeWhere(ctx, legacy, "registered before evidence facts were kept in full")
  ```

  Leave the option unset outside the window; set it in development,
  where a provider's stores may outlive its upgrades.
  `AssuranceProduction` takes it, for the window.
- [ ] **Hear of recheck refusals: `Config.OnRecheckRefused`.** It's
  called with each refusal and the instance as stored afterwards
  (revoked, suspended or still active), the provider's own `Policy`
  refusals among them: alert on it, and revoke from your own logic the
  instances a policy refusal leaves active. It's called even when
  revoking or suspending the instance failed: alert when its
  `KeyStatusesFor` isn't its `State`, and `Revoke` or `Suspend` it. It runs
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
  register (`AssuranceProduction` refuses it). Both are rechecked
  before each Wallet and Key Attestation:
  unsetting `AllowDevelopment` at a production cutover, or removing an
  app from `Apps`, refuses the instances registered before it at their
  next request (a policy refusal: they stay active, and
  `OnRecheckRefused` hears of it; revoke them with `RevokeWhere` to
  make their attestations `INVALID`). App Attest proves the app, not where its keys are: claim
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

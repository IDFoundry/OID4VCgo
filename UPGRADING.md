# Upgrading

What to change when upgrading OID4VCgo, release by release. Each entry
covers the breaking changes a caller has to act on; CHANGELOG.md lists
everything else. A release that pins a new FAPIgo release passes on
that release's own breaking changes: see FAPIgo's UPGRADING.md for
them.

## v0.68.0 → next

### Status lists (`statuslist`)

- **`IndexStore` gains `Delete(ctx, uri)`**, which forgets every
  reservation of a list its caller no longer allocates from. A custom
  store must implement it; `statuslisttest.TestIndexStoreContract`
  checks one. `MemoryIndexStore` and sqlstore's `StatusIndices` do.
- An `Allocator` now validates its settings once, and stops counting a
  list's reserved indices once it finds the list full: keep one for the
  process, as one built per call starts afresh each time. Don't copy
  one once used, and use another for another `Store`; a change to
  `Lists`, `Bits` or `FillLimit` is still picked up.

### Issuer (`issuer`)

- **`CredentialRequest.PerCredential` now runs for every Credential of
  a batch before the first is signed**, not between signings; a hook
  that relied on the earlier Credentials being signed already must
  change. The new `PerBatch` (also on `DeferredIssuance`) is called
  once with the whole batch: with `statuslist.Allocator.AllocateN` it
  reserves a batch's status indices in one round trip.

### Wallet Provider (`walletprovider`)

- **Run `SweepStatusLists` periodically** (daily, say, from one
  process; running it concurrently or again is safe). It deletes the
  reserved indices of the periods' lists no longer served, which
  nothing else deletes.
- **Instance keys are kept for `Config.InstanceKeyRetention`** after
  the start of the last period they were used in: zero means 90 days,
  or three `StatusListPeriod`s when longer. A store may then delete
  one (`InstanceKey.RetainUntil`). Size it for the longest an issuance
  may go unused and still be refreshed: after deletion a Wallet
  Attestation for the key needs fresh evidence, which Android Key
  Attestation can't give for an existing key, and a Key Attestation
  naming it is refused with `unknown_instance_key`; the credential
  must be issued again.
- A custom `InstanceKeyStore` may delete records past their
  `RetainUntil`; one that never does is still correct.
- **Keys recorded before retention get a `RetainUntil`** from
  `SweepStatusLists`, when the store implements the new
  `UnretainedInstanceKeyLister` (sqlstore's and the memory store do):
  a key on a period's list counts from that period's start, and one on
  the single list from v0.67.0 and before from the current period's.
- **Delete the single status list from v0.67.0 and before** (your old
  `Config.StatusListURI`) once, with `IndexStore.Delete`: it hasn't
  been served or changed since v0.68.0, and nothing else deletes it.

### sqlstore (next after v0.8.0)

- **Run `Migrate` again for migration 0009**, which indexes
  `oid4vc_walletprovider_instance_keys`' `sweep_after` for `DB.Sweep`.
  `DB.Sweep` now deletes instance keys past their `RetainUntil`, which
  `SweepStatusLists` gives keys recorded before this release.
- `StatusIndices().Delete` deletes a list's rows in batches; an
  interrupted one finishes when called again.
- **Run `Migrate` again for migration 0010**, which keeps each status
  list's count of reserved indices in 32 rows
  (`oid4vc_status_list_count_shards`), so concurrent `Reserve`s in one
  list no longer wait for each other. On Postgres it locks
  `oid4vc_status_indices` against reservations while it moves the
  counts, which takes a moment. `oid4vc_status_list_counts` becomes a
  view summing them: an older release still running beside this one
  counts correctly, but its `StatusIndices().Delete` fails, leaving the
  list for this release's to finish.
- **Run `Migrate` again for migration 0011**, which adds
  `oid4vc_status_list_versions` and `oid4vc_status_list_tokens`. A
  trigger raises a list's version whenever one of its statuses changes,
  whichever release changes it. To have one replica sign each Status
  List token and the others serve it, set `statuslist.Publisher.Tokens`
  (and `identifierlist.Publisher.Tokens`) to `db.StatusListTokens()`;
  without it each replica signs its own, as before.

### Status list caching (`statuslist.Cache`)

- **Failures are kept for `CacheOptions.MaxFailureAge`**, 30 seconds by
  default. While a failed fetch is kept, checks of the same uri fail
  with its error and don't fetch again. While a token a check refused
  is kept, the checks verify that token again and don't fetch it. So
  once a status list server recovers, or reissues a list checks
  refused, checks can take up to `MaxFailureAge` to see it. Set it
  shorter for a quicker retry, or call `Purge`.

## v0.67.0 → v0.68.0

### Wallet Provider (`walletprovider`)

Status lists now rotate by period, so a provider's capacity is the
instance keys used in a period, not every one ever recorded.

- **`Config.StatusListURI` is `Config.StatusListBaseURI`**: the lists
  are under it, at `{base}/{start}/{n}`, so it has no query and doesn't
  end in `/`. With `Handler` at the provider's URL it's that URL
  followed by `StatusPath`, as `StatusListURI` was.
- **`Config.StatusListPeriod`** is new: how long one period's lists
  hand out indices, by default `DefaultStatusListPeriod` (7 days); a
  whole number of seconds, at least `WalletAttestationTTL` and
  `KeyAttestationTTL`, and at most a year. Changing it later stops
  serving the old period's lists at once: the attestations naming
  them fail status checks until they expire.
- **`Config.StatusListSize` is per list**, and a period has up to
  `MaxStatusListsPerPeriod` (64) lists, of which half of each is
  handed out: size it for the instance keys used in a period. When
  they're all used, an attestation for a new key, or for one moving
  to the period, fails until the next period.
- **`Provider.StatusList()` is `Provider.StatusLists()`**, an
  `http.Handler` serving `GET /{start}/{n}` relative to
  `StatusListBaseURI`. `Handler` serves it under `StatusPath`;
  `GET StatusPath` itself is now `404`.
- **Custom `InstanceKeyStore`s implement `Update`**, a compare-and-swap
  on the new `InstanceKey.Revision`, like `InstanceStore.Update`, and
  `Create` stores Revision 1. `InstanceKey` also gains `PreviousStatus`;
  store it. `walletprovidertest.TestInstanceKeyStoreContract` checks
  both. sqlstore's needs its migration 0008 (below).
- **Attestations issued before the upgrade fail status checks** until
  they expire (within their TTL, a day at most): they name the old
  single list, which is no longer served. Each recorded instance key
  moves to the current period's lists at its next attestation, and a
  suspended or revoked instance still gets none.

### sqlstore (v0.7.1 and v0.8.0)

- **Run `Migrate`.** Migration 0007 keeps a count of each status
  list's reserved indices and adds a partial index over the indices
  with a status, so `StatusIndices().Reserved` and `Statuses` no longer
  read every row of a list. `CheckSchema` fails until it has run. A
  release before it still runs against the migrated schema, so migrate
  first, then roll out. On PostgreSQL the index build blocks writes to
  `oid4vc_status_indices` while it runs: about two seconds for a list
  of eight million indices.
- **Run `Migrate` again for migration 0008**, from the release after
  v0.7.1. It adds a `revision` column to
  `oid4vc_walletprovider_instance_keys`, which
  `WalletProviderInstanceKeys().Update` compares and increments; a row
  from before is at revision 1. `CheckSchema` fails until it has run.
  A release before it still runs against the migrated schema, so
  migrate first, then roll out.

## v0.66.0 → v0.67.0

### Wallet (`walletflow`)

- **`WalletProvider.KeyAttestation` takes the issuance's instance
  key:** `KeyAttestation(ctx, instanceKey crypto.PublicKey, keys
  []*ecdsa.PublicKey, nonce string)`. `instanceKey` is the key
  `WalletAttestation` was asked to attest first for the same issuance.
  Pass it to your provider (`walletprovider.KeyAttestationRequest.InstanceKey`,
  `instance_key` on `POST /v1/key-attestation`), so the Key Attestation
  carries that key's status.
- An issuance that redeems a pre-authorized code without client
  authentication (or refreshes a grant that has none) has no instance
  key of its own. For a Key Attestation it now makes one, has
  `WalletAttestation` attest it, and deletes it when the issuance ends.
  This needs `Config.ClientID`. Without one, the credential request
  fails with `ErrProofUnsupported`.
- `walletflowtest.Provider` gives a Key Attestation only for an
  instance key it gave a Wallet Attestation for.

### Mobile (ABI 15; the Swift and Kotlin libraries)

- **`ABIVersion` is 15.** The Swift and Kotlin libraries refuse a
  framework built for another version: upgrade them together.
- **A `WalletProvider` of your own receives the instance key.**
  Swift: `keyAttestation(instanceKey:keys:nonce:)`. Kotlin:
  `KeyAttestationRequest.instanceKey` (a `KeyEvidence`), or
  `keyAttestation(instanceKey, keys, nonce)` for a provider that takes
  JWKs alone. Gomobile: `KeyAttestation(instanceKeyJWK, keysJWK,
  nonce)`. Send it to your backend as the Key Attestation's
  `instance_key`.

## v0.65.1 → v0.66.0

### Wallet Provider (`walletprovider`)

An instance is now one installation with a stable *registration key*,
and a Wallet Attestation's `cnf` is a per-issuance *instance key*
with its own status list index, so issuers can't link one issuance to
another (HAIP 1.0 §4.4.1).

- **`RegisterRequest.InstanceKey` is `RegistrationKey`**, with
  evidence over a challenge for the new `PurposeRegistration`
  (`"registration"`). `PurposeInstance` (`"instance"`) now binds an
  instance key's evidence. The registration key signs every request
  (`SignRequest`, `Client`'s `registrationKey` argument) and is never
  an instance key.
- **`Instance.Status` is gone**, and registering reserves no status
  index. Each instance key (`InstanceKey`) gets one when it's recorded.
- **`Dependencies.InstanceKeys` is required**: an `InstanceKeyStore`
  (`MemoryInstanceKeyStore` for tests;
  `walletprovidertest.TestInstanceKeyStoreContract` checks your own;
  sqlstore's is `DB.WalletProviderInstanceKeys`, from its migration
  0006, so run `Migrate`).
- **`WalletAttestationRequest` takes `InstanceKey`**, and, the first
  time an instance asks for that key, `Challenge` (`PurposeInstance`)
  and `Evidence` for it. A key already recorded for the instance needs
  neither. A key recorded for another instance, or the instance's
  registration key, is refused with `ErrInstanceKeyRegistered`.
- **`KeyAttestationRequest` takes `InstanceKey`**, the issuance's
  recorded instance key, whose status the Key Attestation carries; an
  unrecorded key is refused with the new `ErrUnknownInstanceKey`.
- **`Suspend`, `Resume` and `Revoke` set the status of every one of
  the instance's instance keys.**
- **Size `Config.StatusListSize` for issuances**, not instances: each
  new instance key uses an index for good.
- **The `/v1/` protocol changed** (mobile/WALLET_PROVIDER.md):
  `POST /v1/instances` takes `registration_key` over a `registration`
  challenge; `POST /v1/wallet-attestation` takes `instance_key`, and
  `challenge` and `evidence` for a new one; `POST /v1/key-attestation`
  takes `instance_key`; and a Key Attestation for an unrecorded
  instance key is `400 unknown_instance_key`. No released client spoke
  the old protocol.
- **Instances stored before** were registered with what is now an
  instance key, and carry a status index nothing will set any more:
  register them again.

## v0.64.0 → v0.65.0

### Credential status (`walletflow`)

- **`CheckStatus` checks a held credential's issuer certificate
  again.** Besides its status and identifier lists, it now verifies
  each live copy's signing chain (an SD-JWT VC's `x5c`, an mdoc's
  IssuerAuth `x5chain`) under the issuer roots and leaf policy
  configured now and against `Config.IssuerRevocation`, with the CRLs
  held then. A copy whose signer, or a CA above it, has been revoked
  since, or whose chain no longer verifies under the roots, is marked
  with the new `CredentialCopy.IssuerUntrusted` and isn't chosen for a
  presentation ahead of one without it; once no copy is left that
  isn't, the credential is `StatusInvalid`. This isn't final, unlike a
  list's revocation: the next check decides it again, so a CRL that no
  longer lists the certificate makes the credential valid again.
- **A credential with no status or identifier list is checked too**
  when it carries a chain and the Wallet has roots for it: `CheckStatus`
  used to return it unchanged, with an empty `Status`, and now records
  one (`StatusValid` when its chain passes). Only a credential with
  nothing to check — no list and no chain, or no roots configured for
  it — is returned as it is.
- **No current CRL is `StatusUnknown`, not an error.** A chain whose
  revocation `certrevocation.CRLs` can't decide for want of a current
  CRL (`certrevocation.ErrNoCurrentCRL`) — the issuer's under
  `IssuerRevocation`, or a status list signer's under
  `StatusRevocation`, which used to fail `CheckStatus` — now records
  `StatusUnknown`. Refresh the lists and check again. A Checker's other
  failures to decide are still errors.
- **`CredentialStatus.Reason`** says why a status is what it is:
  `ReasonStatusList`, `ReasonIdentifierList`,
  `ReasonIssuerCertificateRevoked`, `ReasonIssuerUntrusted`,
  `ReasonNoCurrentCRL` or `ReasonUnrecognizedStatus`; `""` for
  `StatusValid` and for a status recorded before. A `CredentialStore`
  of your own must keep it and `CredentialCopy.IssuerUntrusted`, as
  `storetest.TestCredentialStoreContract` now checks; one that stores
  the record as JSON, sqlstore's among them, already does.

## v0.63.0 → v0.64.0

### Status lists (`statuslist`, `identifierlist`, `walletflow`)

- **A wallet keeps the status lists it fetched.** `walletflow`'s
  `CheckStatus` now checks through a `statuslist.Cache`
  (`Dependencies.StatusCache`, or one of the Wallet's own), so a status
  changed at its issuer is seen once the kept list expires: at the
  earliest of its exp, its iat plus ttl, and 5 minutes
  (`statuslist.DefaultCacheMaxAge`) after it was fetched. Each check
  still verifies the kept list for its own credential. To see a change
  sooner, pass a Cache with a shorter `MaxAge`, or call its `Purge`.
  The mobile Wallet and proximity reader share one Cache per process.
  `statuslist.Checker` and `identifierlist.Checker` cache nothing
  unless given a `Cache`.
- **A Fetcher reuses its transport.** A `statuslist.Fetcher` copies
  its `HTTP.Transport` (or `http.DefaultTransport`) once per address
  policy and reuses the copy, keeping connections alive between
  fetches, where it copied it on every fetch. Changes made to that
  Transport after its first fetch are no longer seen: configure it
  before use, as `http.Transport` asks.

### Verifier (`verifier`)

- **A `TransactionStore` keeps `Transaction.MdocEncryptionInfo`**, set
  for the new org-iso-mdoc requests (`Transactions.BeginMdocDCAPI`). A
  store built on `TransactionCodec`, sqlstore's among them, already
  does; a store of your own must persist the field too.
  `verifiertest.TestTransactionStoreContract` checks it, and
  `BeginMdocDCAPI` refuses a store that drops it. `TransactionCodec`'s
  records keep their version and seal: those written before still
  open. An earlier release can't read an org-iso-mdoc request's record
  (an unknown field), so finish upgrading every instance sharing a
  store before beginning one.
- **`verifier.Reason` has a new value**, `ReasonMdocDCAPIResponse`, for
  an org-iso-mdoc response that didn't decrypt or verify: a `switch`
  over the reasons handles it.

### mdoc curves (`credential/mdoc`, `proximity`, `mdocdcapi`, `verifier`, `wallet`, `issuer`, `statuslist`, `identifierlist`)

ISO/IEC 18013-5 has an mdoc reader support every curve it lists. Of
those, P-384 and P-521 are now supported alongside P-256 and Ed25519,
with ES384 (`oid4vci.COSEES384`, COSE -35) and ES512
(`oid4vci.COSEES512`, -36). Material that was refused with an error
naming its curve is now accepted:

- **Verifiers and readers** verify an IssuerAuth, device signature or
  reader authentication signed on P-384 or P-521, with the algorithm of
  the verified key's curve; a COSE_Key with crv 2 (P-384) or 3 (P-521)
  is a device key. A header marked with RFC 9864's ESP384 (-51) or
  ESP512 (-52) verifies as ES384 or ES512, as ESP256 (-9) does as
  ES256. Device MAC works on any of the three curves, with the device
  key and the reader's ephemeral key on the same one.
- **A proximity reader** accepts an EDeviceKey on P-384 or P-521 and
  generates its EReaderKey on the same curve; ephemeral keys on two
  curves are refused. A holder still generates its own on P-256.
- **Status and identifier lists:** a CWT token signed by a P-384 or
  P-521 key verifies, and `statuslist.Publisher` and
  `identifierlist.Publisher` sign with one. JWT tokens stay ES256 or
  EdDSA: a `statuslist.Publisher` whose signer is on P-384 or P-521
  must set `DefaultForm` to `FormCWT`, or it signs nothing, and answers
  a request for the JWT form alone 406 Not Acceptable.
- **An issuer** may set `MdocSigner.Alg` to ES384 or ES512 with a
  P-384 or P-521 signer. `New` now refuses an `MdocSigner` whose `Alg`
  isn't its signer's key's, which before failed each issuance instead.
- **A wallet**'s `VPFormats` matches an mdoc signed on P-384 or P-521
  against `issuerauth_alg_values` listing -35 or -51, or -36 or -52.

The brainpool curves and Ed448, which Go's standard library doesn't
implement, are still refused.

## v0.62.0 → v0.63.0

### Issuer (`issuer`)

- **A wrapped X5C verifier keeps its production checks.** New ran
  `X5CAttestationVerifier`'s and `X5CProofBindingKeyResolver`'s checks
  only when the dependency was one of those types itself. They're now
  each type's `CheckConfiguration` method (`ConfigurationCheck`), which
  New calls on any `AttestationVerifier` or `ProofBindingKeys`
  implementing it, so a type of your own embedding one is held to
  them: under `AssuranceProduction`, a `Revocation` choice
  (`certrevocation.NoCheck{}` to decline) and an explicit
  `IssuerBinding`. A wrapper holding one in a named field should
  implement `CheckConfiguration` by calling the field's.
- **`locations` is required with `authorization_servers`.** With
  `Config.AuthorizationServers` set, an access token's
  `openid_credential` authorization detail grants a configuration only
  when its `locations` lists `Config.Issuer` (OpenID4VCI 1.0 §5.1.1,
  §6.2), and `RedeemPreAuthorizedCode` refuses a Token Request's
  detail without `locations`, with `invalid_authorization_details`.
  Without it, a token from an Authorization Server several issuers
  share granted one issuer's configuration at every issuer with a
  configuration of that ID. Tokens this package mints already carry
  `locations` there; have your Authorization Server keep the ones the
  Wallet asked for.
- **Anonymous pre-authorized offers need a Transaction Code in
  production.** Under `AssuranceProduction` with
  `AnonymousPreAuthorizedCode`, `CreatePreAuthorizedOffer` refuses an
  offer with neither `TxCode` nor the new `NoTxCode`: without client
  authentication, whoever sees such an offer redeems it (OpenID4VCI
  §3.5). Set `NoTxCode` to offer without one deliberately, with a
  short `Lifetime`.
- **A Notification Endpoint needs a lifetime in production.** Under
  `AssuranceProduction`, New refuses `Endpoints.Notification` without
  a positive `Limits.NotificationLifetime`: each record names the
  client and subject, and one that never expired was never swept.
- **The deprecated `MetadataHandler` doesn't fall back to unsigned
  metadata in production.** Given a signer `NewMetadataHandler`
  refuses, it now answers every request with a server error under
  `AssuranceProduction`. Use `NewMetadataHandler`, which refuses the
  signer up front.

Not breaking, but worth knowing: `New` now keeps its own copy of the
`Config`, and `Metadata` returns a copy, so changing either afterwards
no longer changes what the Issuer enforces. `Prepare` gets the claims
the token's authorization detail asks for
(`CredentialRequest.AuthorizedClaims`, or `ResolveAuthorizedClaims`
for a direct caller). And jwt proofs naming their key by `kid` beside
a `key_attestation`, carrying an optional `key_attestation` an issuer
doesn't verify, or, without a Nonce Endpoint, a key attestation issued
earlier, are now accepted, as OpenID4VCI 1.0 Appendix F.1 allows.

### Verifier (`verifier`, `mdocdcapi`)

- **Production needs a store that seals transactions.** Under
  `AssuranceProduction`, `NewTransactions` refuses a store that doesn't
  implement the new `verifier.SealingStore` returning true: one that
  keeps each transaction's response decryption key and disclosed claims
  in plaintext. `sqlstore`'s `TransactionStore` seals when its
  `TransactionCodec` has a `Sealer`, or now, when it has none, when its
  DB has one. A store of your own implements `SealsTransactions`. Where
  the store is as protected as the Verifier's keys, set
  `TransactionsConfig.UnsealedStore`.
- **`sqlstore` seals transactions with the DB's Sealer.** On a DB with
  `Options.Sealer`, `DB.Transactions(verifier.TransactionCodec{})` now
  seals, and no longer reads the unsealed transactions it wrote before:
  a request in flight when you upgrade fails. Upgrade when none is.
- **Production bounds `TransactionsConfig.Lifetime`** by
  `MaxProductionTransactionLifetime`, an hour.
- **A request for a format the Verifier can't verify is refused.**
  `BuildAuthorizationRequest` and `BuildDCAPIAuthorizationRequest`, and
  so `Begin` and `BeginDCAPI`, refuse a credential query whose format
  isn't `dc+sd-jwt` or `mso_mdoc`, or isn't in
  `Config.VPFormatsSupported`. List each format you ask for
  (`SDJWTVCFormatSupport`, `MdocFormatSupport`).
- **`DiscardedPresentation.Reason` is fixed text.** It describes the new
  `Code` field rather than repeating the verification error, some of
  which the presentation's sender wrote; `Err` keeps the error, for logs
  only, and isn't stored.
- **An SD-JWT VC's array index matches any disclosed element.** A
  presentation leaves out the array elements it doesn't disclose, so the
  verifier can't check an index's position: `["nationalities", 1]` is
  answered by any disclosed nationality, and its `values` by any
  disclosed one's. This library's Wallet's answer to an index past 0,
  refused before, now verifies. Don't rely on an element's position in
  a presented SD-JWT VC.
- **`mdocdcapi` requests expire.** `BuildRequest` sets
  `Pending.ExpiresAt` (`RequestParams.Lifetime`, five minutes by
  default, at most an hour), and `VerifyResponse` refuses a response
  after it (`ErrRequestExpired`), or a `Pending` without one. Keep the
  `Pending` whole, and server-side.

### Status lists (`statuslist`)

- **A status check must bind the list's signer.** `Checker`,
  `CheckX5C` and `CheckCWTX5Chain` used to accept any Status List
  Token signer under their roots when `VerifyOptions` set neither
  `Issuer` nor `IssuerKey`: under roots several issuers share, any of
  them could sign a list deciding another's credential's status.
  They now refuse such a check unless the new
  `VerifyOptions.UnboundSigner` decides the signer, as
  `identifierlist`'s already did. Set `Issuer` or `IssuerKey` from
  the credential, or `UnboundSigner` to a policy of your own, or to
  `statuslist.AnyListSigner` where every signer under the roots may
  decide every credential's status (roots of one issuer alone). A
  `verifier.StatusPolicy`, `walletflow` and the mobile reader already
  bind the signer and need no change.
- **Token size follows `MaxTokenBytes`.** Tokens were capped at 1 MiB
  whatever `Fetcher.MaxBytes` said. `VerifyOptions.MaxTokenBytes`
  (default `DefaultMaxTokenBytes`, 1 MiB, at most
  `MaxTokenBytesLimit`) now sets the cap, and a `Checker` takes its
  `Fetcher.MaxBytes` when it's unset. `Publisher.Token` refuses a
  token over its own `MaxTokenBytes` (same default) instead of serving
  one Relying Parties refuse: a one-bit list of 16 million entries,
  say, needs both raised.
- **`Publisher` checks its times.** A `TTL` or `Lifetime` under a
  second, or a `TTL` longer than the `Lifetime`, now fails `Token`
  (and `ServeHTTP` with a 500) at once; it made every request fail
  before. `ServeHTTP` now serves the form an `Accept` header prefers
  by q, and never one it excludes with `q=0`.

### JOSE and COSE (all roles)

- **Small-order Ed25519 keys are refused when verifying.** A key of
  small order verifies a forged signature over any message. Parsing a
  JWK or COSE_Key, and a certificate's leaf, refused one; a key your
  own resolver returns (a `ProofBindingKeyResolver`,
  `SDJWTVCIssuerKeyResolver`, `AttestationVerifier`,
  `statuslist.VerifyOptions.IssuerKey`) now is too.
- **`typ` is compared as a media type everywhere.** `application/`
  forms and other cases (`application/kb+jwt`, `DC+SD-JWT`) are
  accepted for the SD-JWT VC, Key Binding JWT, jwt proof, Key and
  Wallet Attestation, Request Object, signed metadata and
  registration checks (RFC 7515 §4.1.9), as for status lists.
- **Out-of-range times are refused.** A Request Object's `exp` or
  `nbf`, or signed metadata's `iat`, `exp` or `nbf`, before 1970 or
  past year 9999 is refused rather than wrapped. A Key Attestation's
  `iat` and `exp` may be fractional.
- **`_sd_alg` only at the top level.** An SD-JWT with `_sd_alg` in a
  nested object, or a Disclosure named `_sd_alg`, is refused (RFC 9901
  §4.1.1).

### Wallet (`walletflow`, `wallet`)

- **`PendingDeferred` keeps the type requested.** It has `Format`,
  `VCT` and `DocType`: a `DeferredStore` of your own must keep them
  (`walletflow/storetest` checks every field; sqlstore's and the mobile
  stores do). A deferred credential polled after a restart, whose
  configuration now issues another type, is refused with
  `ErrReissueRequired` and settled, not stored. Records stored before
  aren't checked.
- **A refresh keeps the type too.** `RefreshCredential` returns
  `ErrReissueRequired` when the configuration's format, vct or doctype
  differs from the stored credential's: receive it again from a new
  offer.
- **Revoked and expired credentials aren't picked.** A copy
  `CheckStatus` found revoked ranks with an expired one, so a valid copy
  is presented first; `StoredCredential.Presentable` reports whether a
  Verifier could accept a credential now, a presentation lists those it
  couldn't last, and `DefaultSelection` never picks them (it returns
  `ErrNoMatchingCredential` when only those would answer).
- **Wallet invocation schemes in `redirect_uri`.** A Verifier's
  `redirect_uri` to `openid4vp`, `haip-vp`, `openid-credential-offer` or
  `haip-vci` is refused, as `http` and `javascript` were.
- **A signed presentation is sent even when its context is cancelled.**
  `Respond` posts on a context detached from the caller's, for up to 30
  seconds, once the presentation is signed.

## v0.61.0 → v0.62.0

### Authorization details (`oid4vci`)

- **Dropping every `credential_identifiers` entry is refused.**
  `AuthorizationDetailRARDefinition`'s `ValidateNarrowing` used to
  accept a token request (exchanging a code or a CIBA `auth_req_id`,
  or refreshing) whose `openid_credential` object left out all the
  identifiers its grant held. The access token then carried none, so
  the Wallet could ask for the configuration by
  `credential_configuration_id`, for whatever dataset the Credential
  Endpoint's `Prepare` picks rather than the one consented to, and the
  Token Response broke OpenID4VCI 1.0 §6.2, which requires them. Such
  a token request is now refused with `invalid_authorization_details`:
  keep a non-empty subset of the grant's identifiers, or send no
  `authorization_details` to keep the grant as it is.
- **Malformed objects are refused.** Every `openid_credential` object
  (`Validate`) is refused, with `invalid_authorization_details`, when
  `credential_identifiers`, `locations` or `claims` is an empty array,
  a location is empty, a claims `path` isn't a non-empty array of
  strings, nulls and non-negative integers (Appendix B.1), or two
  claims share a path (Appendix B.3). Leave a member out rather than
  sending it empty.
- **`ClaimsDescription.Validate` accepts decoded indices.** A path
  index decoded from JSON (a `float64`) is accepted when it's a
  non-negative integer; `CredentialMetadata.Validate` refused every
  one before.

### Verifier (`verifier`)

- **Sealed fields are bound to who may read the result.**
  `TransactionCodec` with a `Sealer` now binds the response decryption
  key and the result to the transaction's owner, browser binding hash,
  `same_device`, origin and query, not just its ID: someone who could
  write to the store but hadn't the key could rewrite the browser
  binding hash or owner and have `Lookup` hand them the result. A
  sealed record written by v0.61.0 or earlier no longer opens
  (`sqlstore.ErrRecordFormat` from `sqlstore`'s store): a request in
  flight when you upgrade fails, and a completed one's result is lost —
  at most `TransactionsConfig.Lifetime`'s worth, twice over. Upgrade
  when no request is in flight, or accept those failing. Records
  written without a `Sealer` are unaffected.
- **`RequestURIBase` and `RedirectURI` are checked as endpoint URLs.**
  `NewTransactions` checks both with `fapi.ParseEndpointURL`, as
  `Config.ResponseURI` already was: one with userinfo
  (`https://user:pw@…`, even a bare `@`) or a host that isn't ASCII is
  refused. Give an internationalized domain name as its `xn--` A-label.

## v0.60.0 → v0.61.0

### FAPIgo v0.69.0 (`issuer`)

OID4VCgo pins FAPIgo v0.69.0. See FAPIgo's UPGRADING.md, `## v0.69.0`,
for its own changes; these are the ones that reach an issuer running
`fapigo/server` beside `issuer`.

- **Attester certificates with large RSA keys are refused.** A Wallet
  Attestation whose `x5c` carries an RSA key over 4096 bits, or with an
  exponent other than 65537, is refused with `invalid_client`. Use
  2048–4096-bit RSA with e = 65537, or EC.
- **Token bindings must be passed unchanged.** `IssueAccessToken` and
  `IssueRefreshToken` refuse, with a `server_error`, a `TokenBinding`
  or `AttestedClient` changed after `VerifyTokenRequestBinding` or
  `AuthenticateAttestedClient` returned it. Pass both as returned, for
  the current request, as the passport-vdc demo's pre-authorized code
  Token Endpoint does
  ([`issuerapp/preauth.go`](examples/passport-vdc/issuerapp/preauth.go)).
- **Pushed request parameters are bounded.** `state`, `nonce`, `scope`,
  `login_hint` and `acr_values` over 4 KiB, `id_token_hint` over 16
  KiB, and `code_challenge` or `dpop_jkt` over 128 bytes are refused
  with `invalid_request`.
- **At most eight `BeginAuthorization` calls per `request_uri`.** The
  ninth returns a `LocalErrorResponse` with `invalid_request_uri`. Call
  it once per visit and keep the `InteractionHandle`.
- **No query or bare `#` in URLs.** `Config.Issuer` with a query, and an
  issuer, endpoint or redirect URI ending in a bare `#`, are refused.

### fapigo/sqlstore v0.4.0

passport-vdc and `sqlstore`'s tests pin fapigo/sqlstore v0.4.0. Its
`Migrate` and `CheckSchema` refuse a SQLite file not in WAL mode: open
it with `?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)`, as
`sqlstore`'s docs already say. Its own `AESGCMSealer` refuses a weak
key, as `verifier.AESGCMSealer`, which passport-vdc and `sqlstore`'s
docs use, now does too (see Verifier below). A Credential Endpoint running in the
Authorization Server's process keeps using `serverresource.NewVerifier`
with the server's `Dependencies`; one running apart takes its stores
from fapigo/sqlstore's new `ResourceServer`.

### Certificate chains (all roles)

- **Large RSA keys are refused.** Every certificate chain OID4VCgo
  verifies — `x5c` and `x5chain` from issuers, wallets, verifiers,
  attesters and mdoc readers — now refuses a certificate whose RSA key
  is over 4096 bits or has an exponent other than 65537, before any
  signature is checked with it. Checking a signature with an unbounded
  key cost milliseconds each, and path building tries many. Use
  2048–4096-bit RSA with e = 65537, or EC. Trust anchors you configure
  aren't checked, unless a chain sent to you carries one too.
- **Your own signing chains are checked too.** The chains you
  configure to sign with are checked when they're set up or used, so
  one carrying such a key now fails there: `verifier.Config`'s
  `ClientCertificate` and `ClientCertificateChain` (`verifier.New`),
  an issuer's signers' certificates and intermediates (`issuer.New`),
  `issuer.SignMetadataJWS`'s, `sdjwtvc.IssueOptions`'
  `IssuerCertificate` and `IssuerIntermediates`, a Key Attestation's
  `x5c` (`attestation`), and a status list's or identifier list's
  signer chain (`statuslist`, `identifierlist`).

### Verifier (`verifier`)

- **`AESGCMSealer` refuses weak keys.** A key that's one byte repeated
  (all zeros, say), or all printable text — a passphrase, or a hex or
  base64 key not yet decoded — is refused, as fapigo/sqlstore's
  `AESGCMSealer` now refuses one. Generate 32 bytes with `crypto/rand`
  and decode an encoded key before passing it. Records sealed under
  such a key open only with a `TransactionSealer` of your own over it,
  beside the new one (fapigo/sqlstore's `RotatingSealer` takes both),
  until they expire: `AESGCMSealer`'s doc gives the layout it must
  read.

### sqlstore

- **SQLite must be in WAL mode.** `Migrate` and `CheckSchema` refuse a
  SQLite database whose `journal_mode` isn't `wal`: without it, most
  reads made under concurrent requests failed. Open it with
  `?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)`, as the
  package documentation already said.

### URLs (`verifier`, `mdocdcapi`)

- **No query or fragment where a URL is extended or compared.**
  `TransactionsConfig.RequestURIBase` with a query or a fragment, even
  a bare `?` or `#`, is refused: each request's `request_uri` is it
  with `/` and the request's ID appended, which landed in the query or
  fragment instead of the path. `RedirectURI` with a fragment is
  refused: the Wallet sends the browser there with the
  `response_code` in the query; a query is still allowed. An origin
  (`Origins`, and the origin a wallet's platform reports to
  `mdocdcapi`) ending in a bare `?` or `#` is refused, as one with a
  query or fragment already was: no browser serializes an origin so.

## v0.57.1 → v0.60.0

### Authorization details (`oid4vci`)

- **Dropping locations or claims is refused.**
  `AuthorizationDetailRARDefinition`'s `ValidateNarrowing` (a token
  request exchanging a code or a CIBA `auth_req_id`, or refreshing)
  and `ValidateGrant` (consent) used to accept an `openid_credential`
  object with no `locations` or no `claims` where the wider one had
  them. Without `locations` the access token was good at any Credential
  Issuer sharing the Authorization Server, and without `claims` the
  claims limit was gone. Such a token request is now refused with
  `invalid_authorization_details`, and such a grant fails consent:
  keep a non-empty subset of the granted (or requested) `locations`
  and `claims`. Dropping every `credential_identifiers` entry is still
  accepted.

### FAPIgo v0.68.0 (`issuer`)

OID4VCgo pins FAPIgo v0.68.0. See FAPIgo's UPGRADING.md, `## v0.68.0`,
for its own changes; these are the ones that reach you.

- **More attester certificates are refused.** An issuer whose
  Authorization Server verifies Wallet Attestations with
  `server.X5CAttesterChain` and the default leaf policy now refuses,
  with `invalid_client`, an attestation signed by a certificate that
  lists, or chains only through a CA restricted to, the ISO/IEC
  18013-5 mDL JWS or VICAL signer, the ISO/IEC TS 23220-4 mdoc document
  signer or reader, RFC 9336 document signing, or an RFC 6187 SSH
  extended key usage. Issue attesters a dedicated certificate; a
  Wallet Provider purpose of your own is still accepted.
- **No copy of a trust anchor in `x5c`.** An attestation whose `x5c`
  carries a certificate with the same subject and public key as a
  trust anchor, such as a re-issued or cross-signed copy, is refused.
  Send the signing certificate and its intermediates only.

### Credential Issuer (`issuer`)

- **A proof key's trust can be undecided.** A custom
  `ProofBindingKeyResolver` that can't decide a key's trust now (a DID
  Document's host answering 503, say) can wrap
  `issuer.ErrProofKeyTrustUndecided` in its error. The Credential
  Request is then answered with a server error rather than
  `invalid_proof`, and a deferred transaction stays pending
  (`ErrDeferredProofKeyTrustUnknown`) instead of being denied. Any
  other error still refuses the key.

### sqlstore

- **`Sweep` no longer deletes wallet authorizations.** An expired
  authorization in progress names the instance and DPoP keys it was
  started with, which only walletflow deletes, with the authorization,
  when it next lists them: deleted by `Sweep`, the authorization left
  its keys in the `KeyStore` for good. walletflow still forgets expired
  authorizations itself, so there's nothing to change unless you
  counted on `Sweep` emptying `oid4vc_wallet_authorizations`; its count
  no longer includes them.
- **A pre-authorized code whose Transaction Code column was changed is
  refused.** `PreAuthorizedCodeStore.Consume` now checks the readable
  `tx_code_hash` column against the code's sealed record before
  accepting it, and refuses one where they differ with an error
  wrapping `ErrRecordFormat` — a server error, not a wrong Transaction
  Code. Codes the store wrote itself always match.

### fapigo/sqlstore v0.3.0

passport-vdc and `sqlstore`'s tests pin fapigo/sqlstore v0.3.0. If you
run v0.2.0 with a `Sealer`, upgrade every instance sharing the database
at once, since a v0.2.0 instance can't open records v0.3.0 seals, then
run `SealRecords` once to re-seal the older records.

### Verifier (`verifier`)

- **A sealed record's result must stay sealed.** With a `Sealer`,
  `TransactionCodec.Unmarshal` now refuses a record carrying a
  plaintext `result`, and without one a record carrying a
  `sealed_result`. A custom store that rewrites records must keep the
  sealed fields as `Marshal` wrote them.

## v0.56.0 → v0.57.0

### Certificate revocation (`certrevocation`)

- **A trust anchor that isn't self-signed is checked.**
  `certrevocation.CRLs` now checks the last certificate of a verified
  path against its CA's CRL whenever it isn't self-signed, not only
  when it's a pinned leaf alone. An intermediate CA among the roots, as
  when a CA's whole chain is loaded as the trust anchors, was never
  checked: beside its root it gave a path ending at itself, which
  passed after the root had revoked it. Such a path now needs the
  intermediate's own CA certificate in `CRLs.Issuers`
  (`Refresher.Checker()` sets the Refresher's `Issuers`) and a current
  CRL from that CA, or it's refused with `ErrNoCurrentCRL`. Load only
  self-signed roots as trust anchors where revocation is checked; where
  an intermediate must stay among them, add its CA's certificate to
  `Issuers` and that CA's CRL distribution point to the Refresher. On
  mobile, that CA's certificate goes in `crl_issuers`.
- **Two Refresher issuers by one name.** `certrevocation.NewRefresher`
  refuses `Issuers` holding two certificates with the same subject name
  but different keys, unless `RefresherConfig.AllowSameNameIssuers` is
  set. The rollback floor is now kept per issuer name and key, so one
  such CA's lists no longer raise, or are refused by, the other's; a
  CA that re-keyed under its name may restart its CRL numbering. Set
  the option for a CA that re-keyed and still publishes CRLs under its
  old key too, and bind each of their URLs with `URLIssuers`; otherwise
  remove the certificate that doesn't belong. Floors persisted from
  `OnAccept` need no change: each is matched to the issuer whose key
  verifies it.

### Parsing

- **base64url is the RFC 7515 §2 alphabet only.** Every JWS, JWE and
  JWK segment and member, and every SD-JWT Disclosure, is refused if it
  holds a byte outside `A–Z a–z 0–9 - _`. A token that a producer broke
  across lines (`\r`, `\n`) or padded with `=` used to be read as the
  unbroken one; it is now refused. Producers that follow the RFCs never
  emit either.
- **JSON must be UTF-8.** Every JSON object this module parses (JOSE
  headers and claims, metadata, requests and responses) is refused if
  it holds bytes that aren't UTF-8 or a `\u` escape of an unpaired
  surrogate (RFC 8259 §8.1–§8.2, RFC 7493 §2.1), instead of reading
  either as U+FFFD.
- **A COSE header label may be in only one bucket.** A COSE_Sign1 or
  COSE_Mac0 (an mdoc's IssuerAuth, DeviceAuth, a CWT Status List
  Token) naming one header label in both its protected and unprotected
  headers is refused (RFC 9052 §3).

### mdoc (`credential/mdoc`)

- **`mdoc.Verify` refuses an MSO without `signed`, `validFrom` or
  `validUntil`**, or whose `validUntil` isn't later than its
  `validFrom` (ISO/IEC 18013-5 §9.1.2.4, §12.3.4). A missing timestamp
  used to read as the zero time, which `validFrom` passed.
- **`mdoc.Issue` refuses an IssuerAuth over 64 KiB**, the most
  `mdoc.Verify` accepts, instead of issuing an mdoc no reader built on
  this module would take. Each `Claims.Decoys` digest adds about 40
  (SHA-256) to 72 (SHA-512) bytes, so a configuration near `MaxDecoys`
  in more than one namespace, or with SHA-512, now fails at issuance:
  lower the counts.

### Wallet (`proximity`, `mdocdcapi`, `walletflow`, mobile)

- **A requested identifier may not hold a line or paragraph separator
  or a format character.** A proximity or Digital Credentials API mdoc
  request naming a docType, namespace or data element with U+2028,
  U+2029 or any Unicode format character (Cf: zero-width space, word
  joiner, byte order mark, soft hyphen, tag characters, as well as the
  bidirectional ones already refused) is refused as invalid, as one
  with a control character already was.
- **Error text is cleaned like display text.** Text from an issuer,
  Authorization Server or Verifier that `walletflow` puts in an error
  (`AuthorizationDeniedError`), and every mobile `Error.Message`, now
  has line and paragraph separators made spaces and invisible format
  characters dropped, and is trimmed of surrounding space. A walletflow
  control character becomes a space instead of being dropped.

### Credential Issuer (`issuer`)

- **Key attestation signing certificates.** With `LeafPolicy` unset,
  `X5CAttestationVerifier` and `X5CProofBindingKeyResolver` now apply
  `issuer.DefaultAttestationLeafPolicy`. It refuses a signing certificate
  whose key usage doesn't allow digital signatures, that is an OCSP
  signer, or whose extended key usage lists any other role's purpose:
  TLS server or client, code signing, email, time stamping, IPsec, the
  mDL document signer's, or mdoc reader authentication. It also refuses
  one reached only through an intermediate restricted to such purposes.
  Give Wallet Providers their own certificates, or set `LeafPolicy`:
  call `issuer.DefaultAttestationLeafPolicy` from yours to keep these
  refusals, or set `issuer.AnyAttestationLeaf` to accept every
  chain-verified leaf.
- **Attestation issuer binding.** Under production, an
  `X5CAttestationVerifier` left at `AttestationIssuerUnbound` is
  refused. Set `IssuerBinding` to `AttestationIssuerBoundToAnchor` (with
  `Anchors`) where the roots certify more than one Wallet Provider, or
  to `AttestationIssuerInCertificate`. Where the roots certify a single
  Wallet Provider, set `SingleWalletProvider: true`. `New` refuses
  `SingleWalletProvider` together with any other binding.
- **Attestation status lists.** Bind an `AttestationStatusChecker`'s
  Status List Token signer by the attestation's key
  (`Options.IssuerKey = a.SignerKey`), not by `a.Claims.Issuer`, as the
  interface's doc comment now says.

### mdoc document signers (`credential/mdoc`, `verifier`, `mdocdcapi`, `proximity`, `wallet`, `walletflow`, the mobile libraries)

- **The mDL document signer extended key usage is required.**
  `mdoc.DefaultDocumentSignerPolicy`, the default of
  `X5ChainIssuerKeyResolver.LeafPolicy`, of a wallet receiving an mdoc
  with no issuer leaf policy, and of the proximity reader, now refuses
  a document signer certificate whose extended key usage doesn't list
  `mdoc.MDLDocumentSignerEKU` (1.0.18013.5.1.2, ISO/IEC 18013-5 Annex
  B.1.4), including one with no extended key usage at all. Before, such
  a certificate was accepted, so a revocation list signer's certificate,
  whose extended key usage Annex B.1.7 makes optional, could sign mdocs.
  It also refuses one reached only through an intermediate whose
  extended key usage excludes it. Ask your issuers for document signer
  certificates with the extended key usage. To keep accepting document
  signers without one, set the policy to
  `mdoc.LenientDocumentSignerPolicy`: `X5ChainIssuerKeyResolver.LeafPolicy`,
  `proximity.WithDocumentSignerPolicy`, or the wallet's issuer leaf
  policy (`VerifyIssuedCredentialParams.IssuerLeafPolicy`,
  `walletflow.Config.MdocIssuerLeafPolicy`). The mobile libraries have
  no lenient option.

### Registrations (`registration`, `walletflow`)

- **`Registrars.Revocation` is required.** `Registrars.Verify` refuses
  a nil `Revocation`: pass `certrevocation.CRLs{...}`, your own
  `certrevocation.Checker`, or `certrevocation.NoCheck{}` to decline.
  `walletflow` passes `NoCheck{}` itself in development when
  `Config.RegistrarRevocation` is unset; outside development it was
  already required.
- **Registrar certificates.** With `LeafPolicy` unset,
  `Registrars.Verify` now applies `registration.DefaultRegistrarLeafPolicy`,
  which refuses the same certificates as
  `issuer.DefaultAttestationLeafPolicy` above. Set `LeafPolicy` to your
  ecosystem's own check, calling `DefaultRegistrarLeafPolicy` first, or
  to `registration.AnyRegistrarLeaf` to accept every chain-verified
  leaf. `walletflow.Config.RegistrarLeafPolicy` defaults the same way.
- **`Verify` and `VerifyWithPolicy` are deprecated.** Use
  `Registrars.Verify`, which takes a context and a revocation choice.
  The deprecated functions check no revocation and apply
  `DefaultRegistrarLeafPolicy` when no policy is given.

### Credential Issuer (`issuer`) stores

- **Records name the Credential Issuer that created them.**
  `PreAuthorizedCodeRecord`, `DeferredTransactionRecord`,
  `NotificationRecord`, `NonceIssuance`, `NonceConsumption` and
  `NonceRecord` gain `Owner`, set to `Config.Issuer`, and an `Issuer`
  honours only its own records: Credential Issuers sharing a store, such
  as the tenants of one deployment, no longer redeem each other's
  pre-authorized codes, c_nonces, transaction_ids or notification_ids.
  A custom store must persist `Owner` like any other field. Under
  production a record without one is refused, and the issuer reads its
  first pre-authorized code, deferred transaction and notification_id
  back and refuses a store that dropped it. `NonceStore.Consume`
  retires only a nonce issued with `NonceConsumption.Owner`, leaving
  another Owner's in place (`issuer.ErrNonceUnknown`), and returns its
  `Owner` in the record. A deferred transaction your own business
  process creates in the store sets `Owner` to the `Config.Issuer` of
  the issuer that will serve it. Records saved before the upgrade have
  no `Owner`: under production, let pending c_nonces, deferred
  transactions and notification_ids expire, or set their `Owner`,
  before upgrading. Pre-authorized codes are also keyed by the `Owner`
  (below).
- **Store errors: unknown versus unavailable.** Each issuer store now
  has a sentinel for a record it doesn't hold:
  `issuer.ErrNonceUnknown` (`NonceStore.Consume`),
  `issuer.ErrPreAuthorizedCodeUnknown` (`PreAuthorizedCodeStore.Consume`),
  `issuer.ErrDeferredTransactionUnknown` (`DeferredTransactionStore`'s
  `Get`, `Invalidate` and `Update`) and `issuer.ErrNotificationIDUnknown`
  (`NotificationStore.Get`). A custom store returns an error wrapping it
  for a record it never had, or one already consumed or invalidated
  (`sql.ErrNoRows`, say). Any other error, including the context's,
  now fails the request with a 500 instead of `invalid_nonce`,
  `invalid_grant`, `invalid_transaction_id` or
  `invalid_notification_id`, so an outage no longer tells a holder their
  PIN is wrong. Run the `issuertest` contracts against your stores.
- **Pre-authorized codes and Transaction Codes are stored as hashes.**
  `PreAuthorizedCodeStore` is keyed by a SHA-256 hash of the code and
  the issuing Credential Issuer, and
  `PreAuthorizedCodeRecord.TxCode` is now `TxCodeHash`, an HMAC of the
  Transaction Code keyed by the code; `Consume` compares the hash it's
  given with it (in constant time). A store keeps both as opaque
  strings. Codes outstanding at the upgrade, stored under the code
  itself, stop working: let them expire, or issue new offers. A caller
  that called `PreAuthorizedCodeStore.Issue` itself calls
  `Issuer.IssuePreAuthorizedCode(ctx, code, txCode, record)` instead,
  which is refused under production, as `CreateCredentialOffer` with a
  pre-authorized grant is: use `CreatePreAuthorizedOffer` there. An
  offer made `ByReference` still holds its code in the
  `CredentialOfferStore` until it expires.

### Verifier (`verifier`, `mdocdcapi`)

- **Revocation is its own decision, `Status`, not `Accept`.** Under
  `AssuranceProduction`, any `Accept` used to satisfy the status gate, so
  an `Accept` checking business rules alone accepted revoked
  credentials. `TransactionsConfig`, `VerifyResponseRequest` and
  `mdocdcapi.VerifyParams` now take `Status`, a `verifier.StatusPolicy`
  the library runs before `Accept`, and production requires `Status` or
  `NoStatusCheck`; an `Accept` no longer counts. Under production,
  `Status.Checker.Fetcher` must be `HardenedForProduction` and
  `Status.Checker.Options.Revocation` set (`certrevocation.NoCheck{}` to
  decline checking status list signers' certificates). Setting both
  `Status` and `NoStatusCheck` is refused at every level. Move the
  status check out of `Accept`:

  ```go
  // Before
  Accept: func(ctx context.Context, id string, r verifier.VerifyResponseResult) error {
  	if err := verifier.RequireValidStatus(checker)(ctx, id, r); err != nil {
  		return err
  	}
  	return myChecks(ctx, id, r)
  },

  // After
  Status: &verifier.StatusPolicy{Checker: checker},
  Accept: myChecks, // verifier.Chain(a, b, …) composes several
  ```

  `RequireValidStatusFrom(checker, issuers)` becomes
  `StatusPolicy{Checker: checker, StatusIssuers: issuers}`, and
  `RequireStatusReference(…)` becomes `RequireReference: true`. The
  old functions still work as `Accept`s, but don't satisfy the
  production gate. A `Status` refusal is recorded as `LastError`, as an
  `Accept` refusal is. A `statuslist.NotValidError` for INVALID now
  says "(revoked)" in its text.
- **A status naming no known mechanism is refused.** A credential whose
  status names neither a Token Status List nor, for an mdoc, an
  identifier list — another mechanism, or a misspelt key — was read as
  having no status, so `RequireValidStatus` passed an mdoc revoked
  through it. `VerifiedCredential.StatusListRef` now returns an error
  for one, and `RequireValidStatus` and `RequireStatusReference` refuse
  it, in both formats. A decoded `mdoc.Status` with neither member is
  such a status, not "none". Nothing to change unless your issuers use
  a status mechanism this library doesn't know: accept those
  credentials only with `NoStatusCheck` and a check of your own.

### Credential Issuer (`issuer`) production bounds

- **Proof ages are capped under production.** Without a Nonce Endpoint,
  `Limits.MaxProofAge` may be at most `issuer.MaxProductionProofAge` (5
  minutes): a jwt proof's `iat` is then its only freshness, and one
  proof is good for any number of Credentials. Set `Endpoints.Nonce`
  (HAIP 1.0 §4.1 requires it) to make each proof single-use instead.
- **The system clock.** `Dependencies.Clock` is optional: nil is the
  system clock. Under production `issuer.New` refuses any other `Clock`
  unless it declares `issuer.ClockAssurance` (`ReadsSystemTime() bool`,
  the same method as `fapigo/server.ClockAssurance`, so
  `server.SystemClock` declares it): a fixed or offset test clock would
  stop every lifetime the issuer enforces. Replace
  `Clock: issuer.ClockFunc(time.Now)` with nothing.
- **HAIP as a profile (`haip`).** `haip.ValidateIssuerConfig` takes the
  `Dependencies` too: `haip.ValidateIssuerConfig(cfg, deps)`. It now
  also refuses a proof type whose `ProofSigningAlgValuesSupported`
  lacks ES256 (HAIP 1.0 §7), and a nil
  `PreAuthorizedCodeClientAuthentication` when `deps.PreAuthorizedCodes`
  is set (anonymous redemption under development assurance), and it
  reports every problem it finds rather than the first. Rather than
  calling it after `issuer.New`, set `Config.Profile:
  haip.IssuerProfile{}`, and `issuer.New` runs it with its own checks.
- **Deferred transactions keep x5c- and kid-conveyed proof keys'
  headers.** `DeferredTransactionRecord` gains `ProofKeyHeaders`: for a
  binding key a jwt proof conveyed by `kid` or `x5c`, the proof's JOSE
  header, which `IssueDeferredCredential` resolves again with
  `Dependencies.ProofBindingKeys`. A certificate revoked or no longer
  trusted while the transaction was pending now denies it
  (`issuer.ErrDeferredProofKey`), and one whose revocation can't be
  decided leaves it pending (`issuer.ErrDeferredProofKeyTrustUnknown`),
  as for key attestations. A custom `DeferredTransactionStore` must
  persist `ProofKeyHeaders` like any other field (the `issuertest`
  contract checks it), and an issuer issuing such a transaction needs
  the `ProofBindingKeys` that resolved it.

### FAPIgo v0.66.0 (`issuer`, `storage`, `haip`, `oid4vci`)

OID4VCgo pins FAPIgo v0.66.0. See FAPIgo's UPGRADING.md, `## v0.66.0`,
for its own changes; these are the ones that reach you.

- **The Authorization Server verifies every pre-authorized code
  redemption's DPoP proof.** Under `AnonymousPreAuthorizedCode` the
  issuer verified the Token Request's DPoP proof itself, with its own
  replay record and nonces, so a proof used at the authorization code
  grant could be used again at the pre-authorized code grant.
  `ExchangePreAuthorizedCodeRequest` loses `DPoPProof` and
  `TokenEndpoint`. In the Token Endpoint handler, refuse a request that
  authenticates a client (a Client Attestation, a `client_assertion`
  or `client_secret`, a TLS client certificate), call
  `srv.VerifyTokenRequestDPoP(ctx, tr)` on your `fapigo/server.Server`,
  and pass what it verified, with no `ClientID`:

  ```go
  b, err := srv.VerifyTokenRequestDPoP(ctx, tr)
  if err != nil {
  	server.WriteError(w, err) // use_dpop_nonce carries its DPoP-Nonce header
  	return
  }
  res, err := iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
  	PreAuthorizedCode: params["pre-authorized_code"], TxCode: params["tx_code"],
  	Verified: &issuer.VerifiedTokenRequest{DPoPThumbprint: b.Thumbprint, NextDPoPNonce: b.NextDPoPNonce},
  })
  ```

  `AnonymousPreAuthorizedCode`'s doc comment has the whole handler.
  `ExchangePreAuthorizedCode` refuses a `Verified` naming a client under
  `AnonymousPreAuthorizedCode`, and a request without `Verified` under
  either choice.
- **Removed with it.** `issuer.Dependencies.DPoPReplay` and
  `DPoPNonces`; `issuer.Limits.MaxDPoPProofAge`, `MaxDPoPClockSkew` and
  `DPoPNonceLifetime`; `issuer.MaxProductionDPoPProofAge`;
  `issuer.DPoPReplayChecker`, `DPoPNonceStore`, `DPoPNonceIssuance`,
  `DPoPNonceLookup`, `DPoPNonceRecord`, `NoDPoPNonces` and
  `ErrDPoPNonceUnknown`; `issuer.ErrorUseDPoPNonce`,
  `ErrorInvalidDPoPProof` and `(*issuer.Error).Nonce`, which no issuer
  call returns any more; `storage.DPoPReplayChecker` and
  `storage.DPoPNonceStore`; `issuertest.TestDPoPNonceStoreContract` and
  `TestDPoPReplayCheckerContract`. Delete them from your configuration:
  the proof's age, clock skew, replay record and nonces are
  `fapigo/server`'s (`Limits.MaxDPoPProofAge`, `MaxClockSkew`,
  `Dependencies.Replay`, `Dependencies.Nonces`), under its own
  production bounds. A DPoP nonce store of your own for the issuer has
  no use any more.
- **Wallet Attestation signing certificates.** `server.X5CAttesterChain`
  now applies `server.DefaultAttesterLeafPolicy{}` when `LeafPolicy` is
  nil: an attestation signed by a certificate whose extended key usage
  names another role (TLS server or client, OCSP or code signing, the
  ISO/IEC 18013-5 mdoc reader or document signer), or reached only
  through a CA restricted to such roles, is refused with
  `invalid_client`. Give Wallet Providers dedicated attestation signing
  certificates, or set `LeafPolicy` (`server.AnyAttesterLeaf{}` to opt
  out, a `server.AttesterLeafPolicyFunc` to add your own requirement).
- **No trust anchor in a Wallet Attestation's `x5c`.**
  `server.X5CAttesterChain` refuses an attestation whose `x5c` carries
  the trust anchor, or another self-signed certificate, below the
  signing certificate (HAIP 1.0). A Wallet Provider sends the signing
  certificate and its intermediates only.
- **Client Attestation PoP age under production.** With
  attestation-based client authentication, `server.New` under
  `server.AssuranceProduction` refuses a
  `Limits.MaxClientAttestationPoPAge` above 5 minutes.
  `haip.RecommendedAuthorizationServerConfig` sets 60 seconds.
- **`openid_credential` authorization_details.** Register
  `oid4vci.AuthorizationDetailRARDefinition(maxObjects, maxBytesPerObject)`
  in `server.Config.RAR` in place of a hand-built
  `extension.RARDefinition[oid4vci.AuthorizationDetail]`. It refuses a
  Wallet's own `credential_identifiers` at the pushed authorization
  request (`invalid_authorization_details`), lets the consent add the
  ones it mints, lets a token request (code exchange, CIBA, refresh)
  only keep or drop the identifiers its grant holds — never add one,
  even to a grant that holds none (FAPIgo v0.67.0's
  `RARDefinition.ValidateNarrowing`) — and requires
  `credential_configuration_id`, which a
  definition without `Validate` didn't. A Credential Endpoint's
  `Prepare` that maps a `credential_identifier` to a dataset looks it up
  among those minted for `grant.Subject`, never by the identifier
  alone.

### Wallet stores (`walletflow`)

Several Wallets — in separate processes, such as an app and its
extension or a server's replicas — may now share one set of stores.
Every read-modify-write of a stored record is one atomic store
operation, where it used to be a read then a write under a lock inside
one Wallet. A store of your own implements the new methods:

- **`AuthorizationStore.ConsumeAuthorization(ctx, state)`** returns
  the authorization and deletes it in one step. Of concurrent calls for
  one state, exactly one gets it, and the others get an error wrapping
  `ErrNotFound`. In SQL, use `DELETE … RETURNING`, or a `SELECT … FOR
  UPDATE` and a `DELETE` in one transaction.
- **`CredentialStore.Update(ctx, id, fn)`** and
  **`GrantStore.UpdateGrant(ctx, id, fn)`** load the record, call `fn`
  on it and store the result atomically, as the issuer's
  `DeferredTransactionStore.Update` and the verifier's
  `TransactionStore.Update` already do. An unknown record is
  `ErrNotFound`. An error from `fn` stores nothing and is returned. A
  store may call `fn` again on the current record after a conflicting
  write, as an optimistic compare-and-swap does. In SQL, use a
  transaction with `SELECT … FOR UPDATE`, or a conditional `UPDATE` on a
  version column, retried.
- **New fields to persist.** `CredentialCopy.Reservation` marks the
  latest presentation that reserved the copy. A presentation that isn't
  sent undoes only its own reservation, whichever Wallet made a later
  one. `RefreshGrant.Redemption` and `RedemptionExpiresAt` claim a
  grant while a refresh redeems its token. A store that drops them
  loses that protection between Wallets.
- **`ErrRefreshInProgress`.** `Wallet.RefreshCredential` returns an
  error wrapping it when another Wallet sharing the `GrantStore` is
  redeeming the same refresh grant. Before, both would have redeemed
  the token, and an Authorization Server that rotates refresh tokens
  takes that for a replay. Try again later. A claim lapses after two
  minutes if its Wallet stopped mid-refresh. Refreshes within one
  Wallet still wait for each other.
- `walletflow/storetest` checks the new operations, including under
  concurrency. Run `TestSharedCredentialStoreContract`,
  `TestSharedAuthorizationStoreContract` and
  `TestSharedGrantStoreContract` with a separate handle per goroutine
  on one storage.
- `KeysInUse` still knows only the issuances open in its own Wallet:
  sweep keys only while no Wallet sharing the stores has an issuance or
  refresh under way.

### Mobile (ABI 13; the Swift and Kotlin libraries)

- **`ABIVersion` is 13.** The Swift and Kotlin libraries refuse a
  framework built for another version: upgrade them together.
- **A `CredentialStore` of your own implements `compareAndSwap`.**
  Swift: `compareAndSwap(id:expected:record:) throws -> Data?`. Kotlin:
  `compareAndSwap(id, expected, record): ByteArray?`. Gomobile:
  `CompareAndSwap(id, expected, record) → []byte`. Replace `id`'s
  record with `record`, or delete it when `record` is nil or empty,
  only if the stored record is byte for byte `expected`. Return what
  was stored before. This must be atomic across every process that
  shares the store. Take the same lock in `put` and `delete`, and
  compare the plaintext if the store encrypts. `FileCredentialStore`
  on both platforms now does this with a file lock in its directory,
  so an iOS app and its extension can share one through
  `FileCredentialStore.inAppGroup`.
- `RefreshCredential` can now fail with `unavailable` and the detail
  `refresh_in_progress` while another process sharing the store is
  refreshing with the same grant. It is retryable.
- Records gain `reservation` on each copy, and `redemption` and
  `redemption_expires_at` on refresh grants. The Go side writes them; a
  store keeps them as it keeps the rest of a record.
- **Mobile readers are production by default (ABI 13).** A
  `ProximityReader`'s configuration takes `no_revocation_check`,
  `any_issuer_for_any_type` and `development`, as a Wallet's.
  `NewProximityReader` refuses (`invalid_input`) a configuration that
  leaves a role's revocation (`issuer`, `status`) out of both
  `revocation` and `no_revocation_check`, or sets `issuer_roots`
  without `any_issuer_for_any_type` (otherwise name each document
  type's IACAs in `issuer_roots_by_doctype`), unless it sets
  `"development": true`, which never ships. Make those decisions in a
  reader configuration that didn't; a development or test reader can
  set `development` instead. In Swift and Kotlin,
  `ProximityReaderConfiguration` has `noRevocationCheck`,
  `anyIssuerForAnyType` and `development` (default `false`).

### Proximity reader (`proximity`, `walletflow`, mobile)

- **A reader makes a Verifier's decisions.** `NewReaderSession` and the
  NFC reader constructors now require `WithAssurance` (as
  `verifier.Config.Assurance`) and `WithIssuerRevocation`, at every
  level: pass `certrevocation.CRLs{...}`, your own
  `certrevocation.Checker`, or `certrevocation.NoCheck{}` to decline.
  A nil checker, which used to mean no check, is refused. Under
  `verifier.AssuranceProduction` they also require which issuers may
  issue which document types (`WithIssuerAuthorization`, or
  `WithAnyIssuerForAnyType`) and the documents' status
  (`WithStatus(&verifier.StatusPolicy{…})`, or `WithNoStatusCheck`,
  checked with `verifier.CheckStatusDecision`), and refuse the system
  root pool, in `WithIssuerRootsByDocType` or as `Verify`'s roots.

  ```go
  // Before
  r, err := proximity.NewReaderSession(qr, proximity.WithReaderAuth(key, chain))
  v, err := r.Verify(msg, iacas, time.Time{})
  // then check v.Status yourself

  // After
  r, err := proximity.NewReaderSession(qr,
  	proximity.WithAssurance(verifier.AssuranceProduction),
  	proximity.WithIssuerRevocation(crls), // certrevocation.NoCheck{} to decline
  	proximity.WithIssuerRootsByDocType(iacasByDocType),
  	proximity.WithAnyIssuerForAnyType(),
  	proximity.WithStatus(&verifier.StatusPolicy{Checker: statusChecker}),
  	proximity.WithReaderAuth(key, chain))
  v, err := r.Verify(ctx, msg, iacas, time.Time{})
  ```

- **`ReaderSession.Verify` takes a context**, its first argument. It
  bounds the document signer's revocation check (which used
  `context.Background()`) and the status check. `WithStatus` and
  `WithIssuerAuthorization` run in `Verify`, after the document
  verifies; their refusals are `Verify`'s errors.
- **`Verified.Credential()`** gives the document as a
  `verifier.VerifiedCredential`, for `verifier.StatusPolicy.Check` or
  `verifier.RequireValidStatus` after `Verify`. Its `IssuerChain` leaves
  out the trust anchor, as a Verifier's mdoc's does.
- **Respond after Terminate.** `walletflow.ProximityPresentation.Respond`
  fails with the new `walletflow.ErrTerminated`, sending nothing, when
  `Terminate` is called while it runs (the holder key's prompt is up,
  say); it used to return a response the app could still send. The
  mobile code is `cancelled`. The Swift and Kotlin libraries also check
  that the app hasn't cancelled before they send a response.

### Verifier (`verifier`)

- **Transaction stores keep every field.** `Begin` and `BeginDCAPI`
  read back the first transaction of each kind they create —
  cross-device, same-device, Digital Credentials API — and refuse a
  store that changed its `ID`, `KeyID`, `State`, `Nonce`,
  `ResponseDecryptionKey`, `RequestObject`, `Origin`, `Owner`,
  `BrowserBindingHash`, `SameDevice` or `Status`, or moved `ExpiresAt`
  or `RetainUntil` by a second or more. Until now only `Owner` was
  checked, and a store that dropped `SameDevice` answered a same-device
  request as a cross-device one. `verifiertest.TestTransactionStoreContract`
  now checks that `Create` and `Update` keep every field, including a
  result's claims in the types their format decodes to (an mdoc's
  integers and byte strings, not JSON's); a store that hand-encodes
  `Transaction` may fail it. Encode transactions with
  `verifier.TransactionCodec`, which keeps every field.
- **Unrequested claims are refused.** `VerifyResponse`, and so
  `Transactions`, discards a presentation that discloses a selectively
  disclosable SD-JWT VC claim, or an mdoc data element, its Credential
  Query doesn't name — every claims path of the query counts, whichever
  `claim_sets` option was chosen, and none when the query lists no
  claims — as `ReasonUnrequestedClaims`, as `mdocdcapi` already refused
  an mdoc. A Wallet that minimises its disclosures, as OpenID4VP §6.4.1
  requires (`wallet.PresentCredentials`, the OpenID Foundation
  conformance suite), is unaffected; one that presents every claim
  (`wallet.PresentSDJWTVC`, `wallet.PresentMdoc`) is refused. Set
  `VerifyResponseRequest.AllowUnrequestedClaims` (in
  `TransactionsConfig.Verify` for `Transactions`) to accept it as
  before.

## v0.55.0 → v0.56.0

This release pins FAPIgo v0.65.1, which carries the breaking changes of
FAPIgo v0.63.0, v0.64.0 and v0.65.0: see FAPIgo's UPGRADING.md for
each. Those that reach OID4VCgo's callers:

### Credential Issuer (`issuer`, `haip`) and its Authorization Server

- **Resource verifier URLs.** `serverresource.NewVerifier` and
  `resource.NewVerifier` require `ResourceURLs`: the URLs the Credential,
  Nonce, Deferred Credential and Notification Endpoints are reached
  under, such as the Credential Issuer's own. `issuer/fapiresource`
  checks a DPoP proof against the endpoint URL the handler is given, so
  it must be under one of them. A handler of your own calls
  `resource.VerifyRequestFromHTTP(r)` and sets the request's `URL` to
  the endpoint's absolute URL (the recipe in `issuer/resource_verifier.go`).
- **Authorization Server DPoP nonces.** Under production, the server's
  `Dependencies.Nonces` is required (or `server.NoDPoPNonces{}`), and
  so is the resource verifier's: `serverresource.Options.Nonces`, a
  store of its own, or `resource.NoDPoPNonces{}`. A custom
  `storage.NonceStore` renames `Consume` to `Lookup` and keeps a nonce
  until it expires.
- **Server limits.** `Limits.MaxAccessTokenClaimsBytes` is required;
  `server.RecommendedLimits()`, which `haip` builds on, sets it.
  Production bounds the DPoP, JARM and interaction lifetimes, and
  requires a `Clock` that reads the system time.
- **Pre-authorized code refresh tokens** issued before this release
  record no grant type and are refused with `invalid_grant`: a wallet
  holding one receives a new pre-authorized code, as when it expires.
- **RSA keys.** Every RSA key must use the exponent 65537, and one a
  wallet or Wallet Provider supplies is at most 4096 bits.
- **The issuer's own DPoP nonces are valid for a time window, and
  `DPoPNonceStore.Consume` is now `Lookup`.** RFC 9449 §8 has a server
  keep a window of recent nonces and a client use one until given a new
  one; a single-use nonce challenged every concurrent Token Request from
  a Wallet but the first. `ExchangePreAuthorizedCode` now hands out one
  current nonce per `Issuer`, valid for `Limits.DPoPNonceLifetime` for
  any number of proofs, and issues the next once half that lifetime has
  passed; the previous one keeps working until it expires. A proof's
  `jti` (`Dependencies.DPoPReplay`) still refuses a replay. For your own
  store: rename `Consume` to `Lookup` (`issuer.DPoPNonceConsumption` is
  now `issuer.DPoPNonceLookup`), stop deleting the record on lookup
  (drop it only after its `ExpiresAt`), and return an error wrapping
  `issuer.ErrDPoPNonceUnknown` for a nonce you hold no record of. Any
  other `Lookup` error now fails the request as a server error (500)
  instead of a `use_dpop_nonce` challenge. Run
  `issuertest.TestDPoPNonceStoreContract` against it. Under production
  the store must declare `StoreCapabilities{Durable: true}`;
  `AtomicConsume` is no longer required of it.
- **The issuer's own DPoP nonces are required under production.** Under
  `issuer.AssuranceProduction`, where the issuer verifies the Token
  Request's DPoP proof itself (`Dependencies.PreAuthorizedCodes` set,
  `Config.PreAuthorizedCodeClientAuthentication` not
  `issuer.VerifiedPreAuthorizedCode{}`), `issuer.New` refuses a nil
  `Dependencies.DPoPNonces`. Pass a durable `issuer.DPoPNonceStore` with
  `Limits.DPoPNonceLifetime` (at most 15 minutes under production; five
  minutes suits most deployments), or `issuer.NoDPoPNonces{}` to keep
  accepting proofs without a nonce, as nil did before.

### Wallet (`walletflow`)

- **Clock.** Outside `Development`, `walletflow.New` refuses a
  `Dependencies.Clock` when the wallet receives credentials: leave it
  nil, the system clock. FAPIgo's client requires it under production;
  before, the wallet would have failed at its first issuance instead.

## v0.54.0 → v0.55.0

This release pins FAPIgo v0.62.0.

### Credential Issuer (`issuer`, `haip`)

- **Revocation choices under production.** Under
  `issuer.AssuranceProduction`, every `issuer.X5CAttestationVerifier`
  and `issuer.X5CProofBindingKeyResolver` in Dependencies must set
  `Revocation`: `certrevocation.CRLs` (a `certrevocation.Refresher`'s
  `Checker()`, say), your own `certrevocation.Checker`, or
  `certrevocation.NoCheck{}` to keep accepting certificates without a
  revocation check.
- **Attestation proof type.** Under production, `issuer.New` refuses a
  Credential Configuration that takes the `attestation` proof type
  unless `Config.AllowAttestationProofType` is set: a key attestation
  sent that way can be relayed to another issuer. Take jwt proofs
  carrying it in their `key_attestation` header instead
  (`haip.RecommendedJWTKeyAttestationProofType`).
  `haip.RecommendedIssuerConfig` no longer includes the attestation
  proof type, or a jwt proof type without a key attestation.
- **iss.** An SD-JWT VC whose `Prepare` sets no `Iss` now carries `iss`
  set to `Config.Issuer`.
- **Key attestation status.** An `AttestationStatusChecker` that should
  deny a revoked or suspended key attestation must wrap
  `issuer.ErrKeyAttestationRevoked`. Any other error now leaves a
  pending deferred transaction pending
  (`ErrDeferredAttestationStatusUnknown`) until it's decided or expires,
  and is answered `server_error` (500) at a Credential Request instead
  of `invalid_proof`. The same holds for a key attestation's or an x5c
  proof key's certificate whose revocation can't be decided: no current
  CRL, or a cancelled request.
- **Nonce lifetime.** Under production, `issuer.New` refuses a
  `Limits.NonceLifetime` over an hour.
- **HAIP scopes.** `haip.ValidateIssuerConfig` refuses a scope shared by
  Credential Configurations that require different key attestations.
- **The Authorization Server** (fapigo/server, FAPIgo v0.62.0): an
  `X5CAttesterChain` must set `Revocation` at every assurance level, to
  `server.ClientCertificateCRLs` or
  `server.NoClientCertificateRevocationCheck{}`. Under production with
  attestation-based client authentication,
  `Dependencies.ClientAttestationStatus` is required: a checker of the
  Wallet Attestation's status claim, or
  `server.NoClientAttestationStatusCheck{}`. A custom
  `ClientCertificateRevocation` must wrap `server.ErrCertificateRevoked`
  for a revoked certificate; any other error now answers `server_error`.
  See `haip.RecommendedAuthorizationServerConfig`.

### Verifier (`verifier`, `mdocdcapi`)

- **Transaction stores.** A `TransactionStore` must persist the new
  `Transaction.Owner`: `Begin` and `BeginDCAPI` read the first
  transaction back and fail if it was dropped (`verifiertest`'s contract
  checks it). Under production, transactions saved before the upgrade
  can't be read: let pending ones expire first.
- **Shared stores.** `Transactions` instances sharing a store each read
  only their own transactions. Instances meant to handle each other's
  requests must have the same client_id, response_uri and
  `RequestURIBase`, or set the same `TransactionsConfig.Scope`.
  Instances with all three in common but different policies, such as
  several DC-API-only `Transactions` on one Verifier, set a distinct
  `Scope` each.
- **DC API origins.** Under production, `TransactionsConfig.Origins`
  must list the origins of the pages that call
  `navigator.credentials.get`. `BeginDCAPI` refuses any other, and
  `NewTransactions` refuses a DC-API-only configuration (no
  `RequestURIBase`) without them. `mdocdcapi.VerifyParams.Origins` is
  required under production; `BuildRequest` refuses an origin that isn't
  https or loopback http, and `VerifyResponse` refuses a non-loopback
  http origin, in development too. List origins as
  `scheme://host[:port]`.
- **SD-JWT VC issuer certificates.** With `X5CIssuerKeyResolver.LeafPolicy`
  unset, an issuer certificate is refused when its extended key usage
  lists only other roles' purposes (TLS server or client, code signing,
  email, time stamping, IPsec), lists OCSP signing or the mdoc reader
  authentication purpose at all, or when every path to it goes through
  an intermediate restricted to other roles. Issue SD-JWT VC issuers
  their own certificates, or set `LeafPolicy`: call
  `verifier.DefaultSDJWTIssuerLeafPolicy` from yours to keep these
  refusals, or set `verifier.AnyIssuerLeaf` to accept every
  chain-verified leaf.
- **System roots.** Under production, issuer roots must be the issuers'
  own CAs. `x509.SystemCertPool()` is refused, and on Linux and other
  Unix systems so is a pool built by adding certificates to it.
- **Status checks.** `RequireValidStatus` refuses a credential whose
  status list signer it can't bind to the credential's issuer: one
  verified by a custom key resolver that reports no issuer chain, with
  no iss (SD-JWT VC) or no MSO status Certificate (mdoc). Report the
  chain (`SDJWTVCIssuerChainResolver`, `MdocIssuerChainResolver`), or
  use `RequireValidStatusFrom` with a `StatusIssuerPolicy`
  (`verifier.AnyStatusListSigner` where every signer under the roots may
  decide every credential's status). A non-object SD-JWT VC `status`
  claim is an error.

### Wallet (`walletflow`, the mobile libraries)

- **Redirect URIs.** `walletflow.New`, and the mobile `NewWallet` as
  `invalid_input`, refuse a `RedirectURI` that isn't a private-use
  scheme in `reverse.domain:/path` form (`com.example.wallet:/callback`)
  or loopback http (or, in development, https), or that carries a
  fragment or credentials. Outside development, loopback must be
  `127.0.0.1` or `[::1]`. A wallet with any other redirect URI could never complete an
  authenticated issuance.
- **Identifier lists.** `Wallet.CheckStatus` records
  `walletflow.StatusUnknown` for an mdoc naming an ISO/IEC 18013-5
  identifier list, which the wallet doesn't check yet, and the mobile
  `ProximityReader` reports `unknown` for one; treat it as not checked.
  The Swift and Kotlin `CredentialStatus.Value` gain an `unknown` case:
  add it to exhaustive `switch` and `when` expressions.
- **Missing configuration.** The mobile libraries report a missing
  `issuer_roots`, `redirect_uri`, `verifier_roots` or HAIP provider as
  `invalid_input` with the detail `not_configured`, not as `protocol`.
- **Status lists.** An mdoc's status list without `exp`, or with its
  `x5chain` outside the protected header, is refused (ISO/IEC 18013-5
  §12.3.6.3).
- **Pinned certificates and CRLs.** A certificate pinned in a roots PEM
  (a Verifier's leaf in `verifier_roots`, say) whose role is listed in
  `revocation` is checked against its CA's CRL: give that CA's
  certificate in the new `crl_issuers`, or it's refused.
- **Revocation is an explicit choice.** Outside `Development`,
  `walletflow.New` refuses a trust role in use without a revocation
  Checker: `IssuerRevocation` and `StatusRevocation` when
  `IssuerRoots`, `MdocIssuerRoots` or `MdocIssuerRootsByDocType` is
  set, `IssuerMetadataRevocation` with `IssuerMetadataRoots`,
  `RegistrarRevocation` with `RegistrarRoots`, `MdocReaderRevocation`
  with `MdocReaderRoots`, and `Revocation` on a
  `wallet.X5CVerifierRoots` `VerifierTrust`. Set each to a
  `certrevocation.Refresher`'s `Checker()` (or your own Checker), or to
  `certrevocation.NoCheck{}` to keep the old behaviour of checking
  nothing. `wallet.New` under `wallet.AssuranceProduction` requires the
  same of `IssuerMetadataRevocation` and an `X5CVerifierRoots`. In the
  mobile libraries, outside `development`, each role whose roots are set
  must be named in `revocation` (checked against `crls`) or in the new
  `no_revocation_check` (`noRevocationCheck` in Swift and Kotlin) to
  decline, or `NewWallet` is `invalid_input`; a role can't be in both.
  The roles are `issuer` and `status` (for `issuer_roots` and the mdoc
  roots), `issuer_metadata`, `registrar`, `mdoc_reader` and `verifier`.

### Revocation lists (`statuslist`, `identifierlist`, `certrevocation`, `mdoc`)

- **Status List Tokens.** A token whose `ttl` is 0 or negative, or whose
  `exp` isn't after its `iat`, is refused, and a negative
  `VerifyOptions.MaxAge` is an error instead of turning freshness checks
  off.
- **CWT Status List Tokens.** `statuslist.Checker.Check` and
  `RequireValid` with cwt true refuse a token without `exp` or with an
  unprotected `x5chain`. To check a CWT token outside ISO/IEC 18013-5,
  fetch it with `Fetcher` and call `statuslist.CheckCWTX5Chain` with the
  options it needs. Elsewhere, `statuslist.VerifyOptions.RequireExp` and
  `X5ChainProtectedOnly` apply the same rules.
- **Identifier lists.** `identifierlist.Check` and `Checker.Check`
  refuse a reference with no Certificate when no document signer path is
  given: pass the MSO's verified IssuerAuth x5chain, or set
  `VerifyOptions.UnboundSigner` (`identifierlist.AnyListSigner` where
  every CA under the roots may decide every MSO's revocation).
- **Issuing mdocs.** `mdoc.Issue` refuses an `IdentifierList` reference
  with no ID or URI, or whose Certificate isn't an X.509 certificate.
- **Pinned leaves.** `certrevocation.CRLs` checks a pinned leaf
  certificate against its CA's CRL: add the CA's certificate to
  `CRLs.Issuers`, or to a `Refresher`'s `Issuers`, or the leaf is
  refused with `ErrNoCurrentCRL`.

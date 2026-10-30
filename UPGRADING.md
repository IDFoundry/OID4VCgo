# Upgrading

What to change when upgrading OID4VCgo, release by release. Each entry
covers the breaking changes a caller has to act on; CHANGELOG.md lists
everything else. A release that pins a new FAPIgo release passes on
that release's own breaking changes: see FAPIgo's UPGRADING.md for
them.

## v0.56.0 → next

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

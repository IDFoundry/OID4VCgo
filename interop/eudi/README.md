# EUDI interop

Interop runs against the [EUDI Wallet reference implementation](https://github.com/eu-digital-identity-wallet)'s
own components, run locally from their published images and
libraries. They run in CI from [`.github/workflows/eudi-interop.yml`](../../.github/workflows/eudi-interop.yml):
the verifier from its image ([below](#wallet--eudi-verifier-endpoint)),
the wallet library against `cmd/conformance-verifier`
([further down](#eudi-wallet-library--verifier)) and against
`cmd/conformance-issuer` ([after that](#eudi-wallet-library--issuer)),
and our wallet against the PID Issuer ([last](#wallet--eudi-pid-issuer)).

## Wallet ↔ EUDI Verifier Endpoint

[`run-verifier.sh`](run-verifier.sh) presents from
`cmd/conformance-wallet-vp` to
[eudi-srv-verifier-endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
driving the verifier through its own REST API (`POST /ui/presentations`
to start a transaction, `GET /ui/presentations/{id}` for the result) and
standing in for the same-device launch and the browser. The wallet
fetches each Request Object as a wallet does, through
`wallet.Wallet.FetchAuthorizationRequest` (or
`FetchAuthorizationRequestPost`), and checks the verifier's TLS
certificate on every call it makes to it: the anchor
(`verifier_tls_trust_anchors_pem`) is the verifier's own leaf, the
certificate `scripts/setup` made for its listener, and a server that
presents that very certificate is accepted whatever host name it was
dialed as (`cmd/conformance-wallet-vp`'s `verifyVerifierTLS`); only a
chain to an anchor is checked for the host name. So this pins the
verifier's certificate rather than verifying its name.
Its engine `walletflow` presents through `walletflow` instead
(`StartPresentation`, `Presentation.Respond`), as a wallet app does,
with walletflow's own request fetch and `wallet_metadata`:

| Case | Expected |
|---|---|
| SD-JWT VC PID, `haip` profile, `direct_post.jwt` | accepted |
| The same, `openid4vp` profile | accepted |
| mdoc PID, `haip` profile | accepted |
| mdoc PID, `openid4vp` profile | accepted |
| SD-JWT VC PID and mdoc PID, `haip` profile, `request_uri_method=post` | accepted |
| mdoc PID over the Digital Credentials API (`openid4vp-v1-signed`) | accepted |
| The answered request launched again | refused |
| The verifier trusts an unrelated issuer CA | the verifier refuses the credential |
| The launch's `client_id` isn't the signed request's | the wallet refuses |
| A query for a credential the wallet doesn't hold | the verifier receives `access_denied` |
| The wallet trusts an unrelated CA for the verifier | the wallet refuses |
| An SD-JWT VC at a fresh status list index, then revoked (INVALID) by the issuer side and presented again | accepted, then refused (`StatusNotValid`) |
| The same, suspended (SUSPENDED) | accepted, then refused (`StatusNotValid`) |
| An SD-JWT VC whose `vct#integrity` doesn't match its Type Metadata, before the verifier has the metadata cached | the verifier refuses it |
| An mdoc at a fresh status list index, then revoked by the issuer side and presented again | accepted, then refused (`DocumentHasBeenRevoked`) |
| SD-JWT VC PID, `openid4vp` profile, the verifier's `client_id` `x509_san_dns:localhost`, by GET and by `request_uri_method=post`, to a wallet with `accept_x509_san_dns` | accepted |
| The same `x509_san_dns` request to a wallet without `accept_x509_san_dns` | the wallet refuses |
| walletflow: SD-JWT VC PID and mdoc PID, `haip` profile, by GET and by `request_uri_method=post` | accepted |
| walletflow: the `x509_san_dns` SD-JWT VC cases, with `Config.AcceptX509SANDNS` | accepted |
| The wallet doesn't trust the verifier's TLS certificate | the wallet refuses to fetch the request |
| The Access Certificate's CA revokes it (its CRL names the certificate) | the wallet refuses: `untrusted verifier: … certrevocation: certificate is revoked` |
| The Access Certificate's CA publishes no current CRL (its distribution point serves one past its `nextUpdate`) | the wallet refuses: `untrusted verifier: … certrevocation: no current CRL from the certificate's issuer` |
| The verifier's response encryption key, `client_metadata.jwks` | as v0.12.0 sends it (below) |

In every case the wallet checks the Access Certificate against its
CA's CRL (`verifier_crl`): the CA, `scripts/setup`'s, names an https
distribution point on `localhost:$CRL_PORT` in the certificate, the
wallet process serves the CRL there (`crl_publisher`), and a
`certrevocation.Refresher` fetches it back, https only, bound to the
CA. The two revocation controls start the wallet serving a CRL that
revokes the certificate, and one past its `nextUpdate`. The EUDI
verifier fetches nothing for them: the check is the wallet's alone.

The `x509_san_dns` cases restart the verifier with
`VERIFIER_CLIENTIDPREFIX=x509_san_dns` and
`VERIFIER_ORIGINALCLIENTID=localhost`: its Access Certificate carries
the dNSName `localhost`, the host of its `response_uri`, which
OpenID4VP 1.0 §5.9.3 has the wallet require, and chains to the CA the
wallet trusts for it. They use the `openid4vp` profile, since HAIP 1.0
§5 has a Verifier use `x509_hash`.

Each accepted case also completes the same-device return: the wallet
follows the verifier's `redirect_uri`, and the verifier releases the
`vp_token` only for that `response_code`. With `request_uri_method=post`
the wallet posts its `wallet_metadata`, which the EUDI verifier reads
as RFC 8414 Authorization Server metadata and refuses without `issuer`
and `response_types_supported`, or without `x509_hash` among its
`client_id_prefixes_supported`. The wallet, like walletflow, names
`https://self-issued.me/v2` as its `issuer`, having no identifier of
its own, so the Request Object's `aud` is that value under either of
OpenID4VP 1.0 §5.8's rules. Each control is checked for
its reason, not just for a failure: a verifier's refusal by the error
its transaction's events give (`TypeMetadataResolutionFailure`,
`IssuerCertificateIsNotTrusted`, `StatusNotValid`,
`DocumentHasBeenRevoked`), with the wallet seeing `InvalidVpToken`; a
wallet's by its own error. A refusal for anything else, or the run's
own failure, fails the control.

The verifier is run as strictly as it can be configured:

- Each credential carries a Token Status List reference, and the
  verifier reads it (`VERIFIER_VALIDATION_STATUSCHECK_ENABLED`): it
  fetches the list, a JWT Status List Token for the SD-JWT VC, a CWT
  one for the mdoc, and refuses a credential whose entry isn't valid.
  It never verifies the token's signature (below), so this exercises
  the reference and the entry, not the list's authenticity.
- The lists are published as an issuer publishes them, by OID4VCgo's
  `statuslist` ([`scripts/serve`](scripts/serve) `-publish`): an
  `Allocator` hands each fixture credential its index, at random, and
  keeps its status, and a `Publisher` signs the list from it on each
  fetch, by the credential's issuer (the SD-JWT VC's key, `x5c` its
  certificate; the mdoc's Document Signer, `x5chain` its certificate).
  The SD-JWT VC's list takes 2 bits a status, the mdoc's 1 (ISO/IEC
  18013-5 §12.3.6.5). serve's loopback admin listener is the issuer's
  side: `POST /allocate` hands out an index, and `POST /status` sets
  one's status through `Allocator.SetStatus`, so the next fetch reads
  it (`Publisher.Invalidate`; the tokens carry no `ttl`). Each status
  control presents a credential at an index of its own, which the
  verifier accepts, has the issuer side revoke (or suspend) it, and
  presents it again, which the verifier must refuse: the two
  presentations differ in that status alone. The verifier fetched the
  list for each presentation, the run's serve.log shows: v0.12.0
  doesn't cache it.
- SD-JWT VC Type Metadata is required (`always_required`), resolved for
  `urn:eudi:pid:1` and checked against the credential's `vct#integrity`
  (`..._INTEGRITY_ENABLED`).
- It fetches both over TLS it verifies: the `self-signed` profile, which
  makes its HTTP client trust any certificate, is off, and the CA of
  [`scripts/serve`](scripts/serve), which serves the documents, is added
  to its trust store through the image's `ca-certificates` binding.
- Each transaction names the issuer CA it trusts (`issuer_chain`); with
  no trust validator configured, the verifier would otherwise trust any
  issuer.
- It signs its Request Objects ES512 with a P-521 Access Certificate
  (`VERIFIER_ACCESS_CERTIFICATE_SIGNING_ALGORITHM`), as the verifier's
  own docker-compose configures it, so the wallet's ES512 verification
  is what each accepted case runs through.

The run also checks the verifier fetched each status list and the Type
Metadata, so a run in which it silently skipped a check fails.

The wallet is lenient about some of what it receives (SPECIFICATIONS.md,
"Known leniencies"). Of that, the verifier sends its response
encryption key, whose `alg` OpenID4VP 1.0 §8.3 requires and the wallet
doesn't. The run reads it from a Request Object of a transaction of its
own and asserts it as v0.12.0 sends it, an EC P-256 key with `alg`
`ECDH-ES` and a `kid`, so a change is noticed; it follows the spec. Fetching
a list shows the verifier read it, not that it verified it.

What v0.12.0 doesn't check, whatever its configuration:

- A Status List Token's signature: it passes statium a signature check
  that always succeeds (`StatusListTokenValidator`), so the run shows
  that it reads the list, but not that it would refuse a forged one.
- `vct#integrity`, once it has resolved the Type Metadata: it caches the
  resolved metadata by `vct` alone (`VerifierContext`, the
  `ResolveTypeMetadata` it registers), and checks the integrity only on
  a cache miss. So the mismatched-integrity control runs first, on a
  cold cache, and the run presents the same credential again once the
  cache is warm: that is accepted, and the run notes it without failing,
  and says so if a later image refuses it for its integrity. Refused
  for anything else, it fails.

Every key, certificate and document is throwaway, made per run by
[`scripts/setup`](scripts/setup):

- the wallet's fixture credentials, an SD-JWT VC under a CA and an mdoc
  under an IACA, whose issuers' keys sign the status lists serve
  publishes (setup's fixed Status List Tokens, index 0 valid and 1
  invalid, are what serve serves without `-publish`, for
  [`run-wallet.sh`](run-wallet.sh));
- the PID's Type Metadata;
- the verifier's Access Certificate (its Request Object signing key, a
  P-521 leaf under a CA the wallet trusts; EUDI refuses a self-signed
  one, naming its CA's CRL distribution point), the CA's three CRLs
  (current, revoking the certificate, expired), its
  TLS listener, and a Relying Party registration certificate, which EUDI
  refuses a transaction without;
- `scripts/serve`'s TLS certificate, for `host.docker.internal`, under
  its own CA.

What isn't covered:

- Plain `direct_post`: `cmd/conformance-wallet-vp` always encrypts its
  response.
- ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): the EUDI verifier has no
  such endpoint.
- Credentials an OID4VCgo issuer issued: the fixtures are signed by
  `scripts/setup`, and their status lists published by `scripts/serve`'s
  `statuslist` `Allocator` over an in-memory store, as
  `cmd/conformance-wallet-vp` presents the credentials its configuration
  holds rather than ones it obtains. `cmd/conformance-issuer`'s
  production setup, its status lists in `sqlstore`, issues to wallets in
  the issuer and walt.id runs, where Verifier2 checks its lists.

Run it locally (Docker, Go, jq, curl and openssl; on Apple silicon the
amd64 image runs emulated and takes a couple of minutes to start):

```sh
interop/eudi/run-verifier.sh
VERIFIER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:latest interop/eudi/run-verifier.sh
```

`PORT`, `WALLET_PORT`, `SERVE_PORT`, `ADMIN_PORT` and `CRL_PORT`
(18443 to 18446, and 18448) move the listeners, `CONTAINER` names the
verifier's container, and `WORK` keeps the run's files. On Linux, `serve`
listens on the Docker bridge's gateway, which the verifier reaches as
`host.docker.internal`.

### Moving the pin

The image is pinned by digest in `run-verifier.sh`. The weekly run tests
EUDI's `latest` image, and opens an `interop-eudi-latest` issue when
that fails. To move the pin, read the release's changes, then set the
digest of its `vX.Y.Z` tag:

```sh
docker buildx imagetools inspect ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:vX.Y.Z
```

## EUDI wallet library ↔ Verifier

[`run-wallet.sh`](run-wallet.sh) is the other way round: the EUDI
reference wallet library
[eudi-lib-jvm-openid4vp-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vp-kt)
presents to `cmd/conformance-verifier`. [`presentation/`](presentation)
is a small JVM driver on it, run once per case: openid4vp-kt resolves
and validates the request (the launch's `client_id`, the `x509_hash`
Client Identifier and its certificate chain, the signed Request Object,
`request_uri_method`, `wallet_nonce`, the DCQL query, `expected_origins`)
and sends the encrypted response, or over the Digital Credentials API
assembles it. The library leaves the `vp_token` to its caller, so the
driver builds it as a wallet on it would: an SD-JWT VC issued and
presented with
[eudi-lib-jvm-sdjwt-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt),
its Key Binding JWT bound to the request's nonce and audience, or an
mdoc issued and presented with [Multipaz](https://github.com/openwallet-foundation/multipaz),
its DeviceResponse signing the OpenID4VP SessionTranscript (Appendix
B.2.6.1, or B.2.6.2 over the Digital Credentials API). Each credential
is issued for the run under `scripts/setup`'s throwaway issuer CA (or
IACA), and carries a Token Status List reference.

Four verifiers run, two asking for the SD-JWT VC PID (`dc+sd-jwt`,
`urn:eudi:pid:1`), two for the mdoc PID (`eu.europa.ec.eudi.pid.1`),
each for `family_name` and `given_name`. One of each runs as a
deployment's Verifier does: through `verifier.Transactions`, the API a
deployment uses (`cmd/conformance-verifier`'s transactions engine),
under `verifier.AssuranceProduction`, its transactions in a sealed
SQLite file (its `production` setting: `sqlstore`'s
`TransactionStore`, `sealing.AESGCMSealer`; the binary is built with
the `conformance_production` tag). Its links ask for
`request_uri_method=post`, the wallet's POST carries its
`wallet_metadata`, to which the Request Object's `client_metadata` is
narrowed, and the result is released only to the browser holding the
request's cookie, at the `redirect_uri`. The presentations, and every
control the verifier must refuse, go to these two, each refusal graded
by the result page that browser sees: the refusal's `verifier.Reason`
(its `reason:` line) and its error.

The other two, the binary's default engine at development assurance
(`verifier.AssuranceDevelopment`, an in-memory session store), serve
what the transactions engine doesn't: the `request_uri_method` a case
asks for (`get`, or none; the transactions engine asks for `post`),
the Digital Credentials API (the binary routes no Digital Credentials
API through `verifier.Transactions`, though the package's `BeginDCAPI`
does), and the default engine's own controls (a `response_code`
redeemed again at its `/result/{id}/redeem`, the replayed response, the
holder declining) and the wallet's (graded by the library's refusal,
whichever engine served the request).

On both engines: the issuer trusted by its x5c chain to the run's CA
(or IACA), never a pinned key; every credential's Token Status List
checked, a status reference required, the list signed by the
credential's issuer and fetched over TLS it verifies; holder binding
required; a disclosed claim the query didn't ask for refused. The
status lists are on loopback, where [`scripts/serve`](scripts/serve)
serves them, so the fetchers may reach loopback
(`status_list_allow_loopback`): a production fetcher dials public
addresses only, and a runner has none to serve from. Under production,
`TransactionsConfig.Status` refuses that fetcher, so the binary runs the
same status policy as the `Accept` (conformance/verifier/README.md's
"Transactions engine"): a revoked credential's refusal is then the
`Accept`'s own error, with no `verifier.Reason`, and the controls
check the result page names none. No certificate's revocation is
checked: both engines take `certrevocation.NoCheck` for the issuer's
and the status list signer's certificates, as the run's throwaway CAs
publish no CRL. The run also checks that the status lists were
fetched.

| Case | Expected |
|---|---|
| SD-JWT VC, `request_uri_method=post` | accepted; the wallet fetches with a form POST, a `wallet_nonce` and `wallet_metadata` |
| SD-JWT VC, `request_uri_method=get` | accepted; fetched with GET |
| SD-JWT VC, no `request_uri_method` | accepted; fetched with GET |
| SD-JWT VC through `verifier.Transactions` under production (`TransactionsConfig.RequestURIMethodPost`) | accepted; fetched with a form POST, the result released to the browser that began the request |
| The same, a wallet that supports only GET | accepted; fetched with GET |
| The same, a wallet that encrypts only with A256GCM | accepted, encrypted with A256GCM |
| SD-JWT VC over the Digital Credentials API (`openid4vp-v1-signed`, `dc_api.jwt`) | accepted |
| mdoc through `verifier.Transactions` under production | accepted, released to the browser that began the request |
| mdoc, `request_uri_method=post` and `get` | accepted |
| mdoc over the Digital Credentials API | accepted |
| A `response_code` redeemed a second time | the verifier refuses |
| A Digital Credentials API answer posted a second time | the verifier refuses |
| A revoked SD-JWT VC, or mdoc (its status list entry invalid), under production | the verifier refuses it: the status policy's error (`statuslist: the referenced token's status is INVALID (revoked)`), no `verifier.Reason` (the `Accept`'s) |
| An SD-JWT VC, or mdoc, from an issuer under an untrusted CA, under production | the verifier refuses it: `untrusted_issuer`, `x509: certificate signed by unknown authority` |
| A KB-JWT for another nonce, or another `aud`, under production | the verifier refuses it: `holder_binding`, `key binding JWT is for another request` |
| An SD-JWT VC without a KB-JWT, under production | the verifier refuses it: `invalid_credential`, `key binding is required but no Key Binding JWT was presented` |
| An SD-JWT VC, or mdoc, disclosing a claim the query didn't ask for, under production | the verifier refuses it: `unrequested_claims` |
| An mdoc whose SessionTranscript names another nonce, or another `client_id`, under production | the verifier refuses it: `holder_binding`, the DeviceSignature doesn't verify |
| Over the Digital Credentials API, a KB-JWT whose `aud` is the `client_id`, not `origin:<origin>` (Appendix A.4) | the verifier refuses it |
| Over the Digital Credentials API, an mdoc SessionTranscript naming the `client_id`, not the origin | the verifier refuses it |
| The holder declines | the verifier records the wallet's `access_denied` |
| A response posted again after it was answered | the verifier refuses it (HTTP 400) |
| The wallet trusts an unrelated CA for the verifier | the wallet refuses |
| The launch's `client_id` isn't the Request Object's | the wallet refuses |
| An `http` `request_uri` | the wallet refuses |
| A Request Object carrying another `wallet_nonce`, or none (§5.10.1) | the wallet refuses |
| A Digital Credentials API request from an origin not in `expected_origins` | the wallet refuses |
| A signed request under the `openid4vp-v1-unsigned` protocol | the wallet refuses |

Each accepted redirect-flow case completes the same-device return: the
verifier answers the response with a `redirect_uri` carrying a
`response_code`, and releases the result once, for that code: the
default engine at `/result/{id}/redeem`, with how the wallet fetched
the Request Object; the transactions engine to the browser that began
the request (`Transactions.Redeem`), whose log says how it was fetched.
The released claims must be the two asked for and none of the PID's
others. Each control is checked for its reason: OID4VCgo's verifier's
error, or the EUDI library's (`InvalidJarJwt`, `UnexpectedOrigin`, ...),
not just a failure; the driver failing isn't a refusal.

### Findings

In OID4VCgo:

- `cmd/conformance-verifier` took a response's session as pending
  before taking the session's lock, so two concurrent responses to one
  request could both be verified. It now checks again under the lock.
  (Found reading the handler for this run, not by the run itself.)
- It had no `response_code` and no Digital Credentials API endpoints,
  checked no status and trusted SD-JWT VC issuers only by a pinned key;
  the run needed all four, which it now has as interop-only
  configuration (the OIDF suite's configuration leaves it unset).

The run found no fault in the `verifier` package.

In eudi-lib-jvm-openid4vp-kt 0.17.0, set against OpenID4VP 1.0 Final
and HAIP 1.0 Final:

- **The Request URI POST's Accept header names a second media type.**
  §5.10: "The request MUST use the HTTP POST method with the https
  scheme, and the content type application/x-www-form-urlencoded and
  the Accept header set to application/oauth-authz-req+jwt." The
  library sends `Accept: application/oauth-authz-req+jwt,application/jwt`
  (`addAcceptContentTypeJwt` in `internal/request/RequestFetcher.kt`,
  used for both the GET and the POST fetch). Harmless to a verifier that
  serves `application/oauth-authz-req+jwt`, as this one does, so the run
  records the header without failing on it.
- **An `http` `request_uri` throws instead of resolving as invalid.**
  The library refuses it, as it must, but `resolveRequestUri` throws an
  `IllegalArgumentException` ("URL must use HTTPS") rather than
  returning `Resolution.Invalid`, the outcome its API promises for an
  invalid request: `requestUriValue.asHttpsURL().getOrThrow()` in
  `internal/request/DefaultRequestResolverOverHttp.kt` throws an
  exception that isn't an `AuthorizationRequestException`, which is
  what the resolver turns into `Invalid`. Not a spec deviation; a
  wallet that doesn't catch it crashes on a hostile launch. The driver
  catches it and counts it as the refusal.
- Not a deviation, but worth knowing on top of the library: it leaves
  the `vp_token`, and so its holder binding, to the caller, and over the
  Digital Credentials API a signed request's resolved `client.id` is its
  `x509_hash` Client Identifier. A wallet that binds to that gets
  refused: Appendix A.4 says "The audience for the response (for
  example, the aud value in a Key Binding JWT) MUST be the Origin,
  prefixed with origin: ... This is the case even for signed requests",
  and an mdoc's SessionTranscript names the origin (B.2.6.2). The run
  has both as controls.
- Not exercised: `wallet_metadata`'s `response_modes_supported` is
  always `["direct_post", "direct_post.jwt"]` (a TODO in
  `internal/request/WalletMetaData.kt`), whatever the wallet's
  `responseEncryptionConfiguration`. The run's wallet supports both, so
  what it sent was true. It also sends `issuer` and
  `response_types_supported`, which the EUDI verifier requires (see
  above); the default engine ignores `wallet_metadata`
  (`verifier.Transactions` narrows its Request Object to it), and the run checks
  its `client_id_prefixes_supported`, `vp_formats_supported` and
  `request_object_signing_alg_values_supported`.

### What isn't covered

The verifier, not the library, sets the limits here:

- Transaction data: the `verifier` package neither sends
  `transaction_data` nor checks `transaction_data_hashes`.
- Client Identifier Prefixes other than `x509_hash` (`x509_san_dns`,
  `redirect_uri`, `decentralized_identifier`, `verifier_attestation`,
  pre-registered): the `verifier` package uses `x509_hash`, HAIP's, only.
- Plain `direct_post` and `dc_api`, and unsigned or multi-signed
  Digital Credentials API requests: the `verifier` package always
  encrypts the response (HAIP §5.1, §5.2) and signs the request as one
  JWS. So there is no non-HAIP mode either; the library has no HAIP
  switch of its own.
- An encrypted Request Object (`request_uri_method=post` with JAR
  encryption): the verifier doesn't encrypt one.
- `verifier_info` and the library's registration certificate policy:
  `cmd/conformance-verifier` sends none.
- More than one Credential Query, `credential_sets` and `claim_sets`:
  `cmd/conformance-verifier` asks one query.
- SD-JWT VC Type Metadata and `vct#integrity`: the `verifier` package doesn't
  resolve Type Metadata.
- ISO/IEC TS 18013-7 Annex C (`org-iso-mdoc`): the library is
  OpenID4VP only.
- A `response_code` bound to the browser that started the request
  outside the `verifier.Transactions` cases: `cmd/conformance-verifier`'s
  default engine has none (see `conformance/verifier/README.md`).
- The Digital Credentials API, the `request_uri_method` choices and the
  default engine's own controls under production assurance: they run
  on the default engine, at development (above).
- A production status list fetch: the lists are on loopback (above).
- The revocation (CRLs) of the issuer's and the status list signer's
  certificates: both engines check none (`certrevocation.NoCheck`).

Run it locally (Go, a JDK 21 or later, jq, curl and openssl):

```sh
interop/eudi/run-wallet.sh
```

`PORT`, `MDOC_PORT`, `SERVE_PORT`, `TX_PORT` and `TX_MDOC_PORT` (20443
to 20447) move the listeners, and `WORK` keeps the run's files. Every key, certificate and
document is throwaway, made per run by [`scripts/setup`](scripts/setup)
and the driver; CI uploads the logs and the verifiers' answers, never
the work directory's keys.

### Moving the pins

The driver pins every dependency in
[`presentation/build.gradle.kts`](presentation/build.gradle.kts), its
lockfiles pin the transitive ones, and `gradle/verification-metadata.xml`
records each one's checksum. To move one, read the release's changes,
set the version, then, in `presentation/`, with an empty Gradle cache
so that Gradle fetches, and records, every artifact and POM a clean
runner does:

```sh
GRADLE_USER_HOME="$(mktemp -d)" ./gradlew --write-verification-metadata sha256 --write-locks dependencies installDist
```

and review the new checksums. Nothing moves them automatically, and
the weekly run doesn't test the libraries' newest releases.

## EUDI wallet library ↔ Issuer

[`run-issuer.sh`](run-issuer.sh) has the EUDI wallet library,
[eudi-lib-jvm-openid4vci-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-openid4vci-kt)
0.16.0, obtain credentials from `cmd/conformance-issuer`, the
Credential Issuer and Authorization Server the OIDF HAIP issuer plan
certifies, through a small Kotlin driver, [`issuance/`](issuance). The
driver uses the library's own API for everything a wallet does
(resolving the offer and the metadata, PAR, the Token Request, nonces,
proofs, the Credential, Deferred Credential and Notification
Endpoints), and stands in for the browser only at the issuer's consent
page, whose form it submits.

The wallet is registered as a native client (`application_type`
`native`) with the EUDI wallet app's own redirect URI,
`eu.europa.ec.euidi://authorization`, a private-use URI with an
authority, which FAPIgo takes from v0.73.0: each authorization code
case checks that PAR sends it and that the consent redirects to exactly
it, the driver reading the authorization response from the redirect's
`Location`, since no HTTP client follows such a URI.

The wallet is configured as strictly as the issuer allows: PAR and
DPoP required (DPoP binding the authorization code at PAR), the
authorization response's `iss` required, Wallet Attestation client
authentication (draft-ietf-oauth-attestation-based-client-auth-07)
with an attestation the issuer trusts by its `x5c` chain, every proof
type, and a TLS client trusting only the issuer's CA. What's issued is
checked on the wallet side: each SD-JWT VC by EUDI's own verifier,
[eudi-lib-jvm-sdjwt-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-sdjwt-kt)
0.21.0 (its signature by the `x5c` leaf, the chain to the issuer's CA,
`vct`, every claim disclosed), and each mdoc by the driver itself,
EUDI having no JVM mdoc verifier (the `issuerAuth` signature, the
`x5chain` to the IACA, every item's digest in the MSO, docType,
validity, claims); and every credential must be bound to a different
one of the keys its proofs named. The driver records each request the
library makes, so a case also checks how it was made: DPoP proof and
token, attestation headers, PKCE S256, `issuer_state`, the Nonce
Endpoint, encrypted bodies, DPoP nonce retries.

The issuer runs in five configurations in turn, its profiles, the
last its production setup:

| Profile | Case | Expected |
|---|---|---|
| base | pre-authorized code, SD-JWT VC, jwt proof, offer by value; then a notification | issued, verified |
| base | the same pre-authorized code redeemed again | refused, `invalid_grant` |
| base | a wrong `tx_code` | refused, `invalid_grant` |
| base | pre-authorized code with `tx_code`, mdoc, offer by reference, after the wrong `tx_code` | issued, verified: the wrong one didn't spend the code |
| base | pre-authorized code granting `credential_identifiers`, both formats, requested by identifier | issued, verified |
| base | pre-authorized code, the wallet asking for `authorization_details` in the Token Request | known deviation, finding 2: refused as `invalid_authorization_details`; the code then redeems without them |
| base | authorization code, wallet-initiated, SD-JWT VC; then a notification | issued, verified |
| base | authorization code from an offer with `issuer_state`, by reference, both formats on one token | issued, verified |
| base | authorization code by `authorization_details`, both formats, by `credential_identifier`; then a `credential_deleted` notification | issued, verified |
| base | batch issuance, three jwt proofs | three credentials, one per key |
| base | attestation proof: a key attestation of two keys, SD-JWT VC; of one, mdoc | one credential per attested key |
| base | Credential Request and Response encryption (ECDH-ES, A128GCM/A256GCM, DEF), both formats | issued, verified, both bodies `application/jwt` |
| base | signed Credential Issuer Metadata required, trusted by the issuer's CA | issued, verified |
| base | signed metadata, the wallet trusting an unrelated CA | the wallet refuses the metadata |
| base | a Wallet Attestation under an untrusted attester CA, at the Token Endpoint and at PAR | refused: 401 `invalid_client`, "no matching attester key" |
| base | an attestation proof whose key attestation an untrusted key signed | refused: `invalid_proof`, "attestation 0: verification failed" |
| base | the End-User denies consent | `access_denied` |
| base | an SD-JWT VC checked against an unrelated CA; an mdoc against an unrelated IACA | the wallet side refuses each |
| key-attestation | jwt proof with a key attestation of two keys, SD-JWT VC, authorization code; of one, mdoc, pre-authorized code | one credential per attested key |
| key-attestation | a jwt proof whose key attestation an untrusted key signed | refused: `invalid_proof`, "attestation 0: verification failed" |
| deferred | SD-JWT VC, polled at once | deferred, then issued with a `notification_id` |
| deferred | mdoc batch, polled after the interval the issuer asked for | deferred, then issued |
| deferred | with Request and Response encryption | deferred, then issued, encrypted |
| deferred | a `transaction_id` polled again once issued | refused, `invalid_transaction_id` |
| dpop-nonces | authorization code, SD-JWT VC; pre-authorized code, mdoc | PAR, the Token and the Credential Endpoints each challenge with `use_dpop_nonce`, and the wallet retries |
| production | authorization code, SD-JWT VC, a jwt proof carrying the Wallet Provider's Key Attestation of two keys | two credentials, one per attested key |
| production | pre-authorized code, mdoc, offer by reference, one key | issued, verified |
| production | both formats on one pre-authorized token, Credential Request and Response encryption | issued, verified, both bodies `application/jwt` |
| production | a Wallet Attestation from a Wallet Provider under a CA the issuer doesn't trust | refused: 401 `invalid_client`, "no matching attester key" |
| production | a Wallet Attestation the wallet obtained before the Wallet Provider revoked its instance, once the cached status list's `ttl` has passed | refused: 401 `invalid_client`, "client attestation has been revoked" |
| production | a new Wallet Attestation for the revoked instance | the Wallet Provider refuses it: 403 `instance_revoked` |

`base` is the issuer as the OIDF plan runs it, plus `offers` (the
pre-authorized code grant, Credential Offers, and a loopback-only
endpoint minting offers for the driver) and `authorization_details`
(PAR taking openid_credential `authorization_details`, the consent
minting a `credential_identifier` for each). `key-attestation` also
has the jwt proof type require a key attestation
(`key_attestation.jwt_proof_requires_key_attestation`, HAIP 1.0
§4.5.1's "jwt proof type using key_attestation"): the library adds a
key attestation to a jwt proof only when the issuer requires one.
`deferred` defers every request, and `dpop-nonces` has the
Authorization Server and the Credential Issuer each require their own
DPoP nonce.

`production` is the issuer as a deployment runs it
(`cmd/conformance-issuer`'s `production` setting, the binary built with
the `conformance_production` tag): the Authorization Server and the
Credential Issuer under production assurance, every store `sqlstore`'s
or `fapigo/sqlstore`'s in a sealed SQLite file, the access token key
loaded from its configuration, audit sinks, `jwt` proofs that must
carry a key attestation (`haip.RecommendedIssuerConfig`, no
`attestation` proof type), and DPoP nonces. Every Wallet Attestation
and Key Attestation is OID4VCgo's Wallet Provider's
([`../walletprovider`](../walletprovider): `walletprovider.Provider`
over sealed SQLite stores, its status lists served), which the driver
obtains through the provider's agent (the wallet's side of its v1
protocol, as the Swift and Kotlin libraries' `HttpWalletProvider` is
on a device; only the platform evidence is a stand-in,
`walletprovidertest.FakeVerifier`). The issuer trusts both by their
`x5c` chain to the provider's CA, and checks their status on its lists.
Those are on loopback under the provider's own TLS certificate, which
production's status fetcher refuses (`HardenedForProduction`), so this
profile alone sets `attestation_status_allow_loopback` and
`attestation_status_tls_trust_anchors_pem`, the one setting a
deployment wouldn't make: `issuer.New` would refuse that fetcher, so
the key attestation check runs through a wrapper it can't inspect,
checking exactly what it would (the binary logs a warning). The
revocation control holds a Wallet Attestation from before the
revocation, differing from the passing cases in its status alone; the
provider's `ttl` is 2 s, so the issuer's cached list expires within the
run, and the run checks the issuer fetched the list again. The other
profiles' cases don't run here: production takes no `attestation`
proofs and no `jwt` proof without a key attestation.

Each control is checked for its reason, from the issuer's error
response as the driver recorded it, not only from the library's
error, which for a 401 carries none (finding 3). FAPIgo describes a
Wallet Attestation whose attester it has no key for as "no matching
attester key", apart from the attestation's other checks, and the
passing cases differ from those controls in the attester's key and
certificate alone. The issuer trusts one
key for key attestations, so one signed by another fails its own
verification, whose description ("attestation 0: verification
failed") also covers its time claims: the controls build their key
attestations as the passing cases do, the signing key the one
difference. A nonce, a missing `exp` or a proof key the attestation
doesn't attest each has a description of its own.

Of what the issuer is lenient about (SPECIFICATIONS.md, "Known
leniencies"), the library sends a Client Attestation PoP, whose `iss`
draft-07 §5.2 requires and FAPIgo's server doesn't. Each PAR and token
request that carries one is checked for an `iss` naming the client_id,
as the library sends it today, so a PoP without one fails the case
rather than passing on the leniency unnoticed.

Every key and certificate is throwaway, made per run by
[`scripts/setup-issuer`](scripts/setup-issuer): the issuer's TLS
certificate under its own CA, its SD-JWT VC signer under an issuer CA,
its mdoc Document Signer under an IACA, its request decryption key, the
Wallet Provider's attester CA and key, a key attestation key, and the
unrelated CAs and keys of the controls.

### Findings

1. **The library refuses Credential Issuer Metadata whose
   `credential_request_encryption.jwks` keys have no `use`.**
   OpenID4VCI 1.0 §12.2.4 requires only a `kid` on each key: "jwks:
   REQUIRED. A JSON Web Key Set, as defined in [RFC7591], that contains
   one or more public keys, to be used by the Wallet as an input to a
   key agreement for encryption of the Credential Request. Each JWK in
   the set MUST have a kid (Key ID) parameter that uniquely identifies
   the key." §10 makes `alg` the other required member and `use` a
   hint: "any may be selected based on the information about each key,
   such as the kty (Key Type), use (Public Key Use), alg (Algorithm),
   and other JWK parameters. The alg parameter MUST be present." (`use`
   is OPTIONAL in RFC 7517 §4.2.) The library's
   `SupportedRequestEncryptionParameters` (`CredentialIssuerMetadataResolver.kt`)
   requires `it.keyUse == KeyUse.ENCRYPTION` of every key
   (`CredentialRequestEncryptionKeysMustHaveEncryptionUsage`), and the
   issuer is then unusable, whether the wallet encrypts or not.
   OID4VCgo's `issuer` now publishes `"use": "enc"` on these keys, as
   the spec's own example does, so the run proceeds.
2. **The library URL-encodes `authorization_details` in the Token
   Request twice.** OpenID4VCI 1.0 §6.1.1: "The Wallet can use
   authorization_details in the Token Request to request a specific
   Credential Configuration in both the Authorization Code Flow and the
   Pre-Authorized Code Flow. The value of the authorization_details
   parameter is defined in Section 5.1.1", a JSON array (RFC 9396 §2),
   in an `application/x-www-form-urlencoded` body (the section's example:
   `authorization_details=%5B%7B%22type%22...`). The library's
   `TokenEndpointClient.authorizationDetailsFormParam` returns
   `toFormParamString()` (`internal/http/AuthorizationDetailsOps.kt`),
   which already applies `URLEncoder.encode` to the JSON, and hands it
   to ktor's `submitForm`, which form-encodes it again: the issuer
   receives `%5B%7B...`, not JSON, and refuses it as
   `invalid_authorization_details`. Every `AccessTokenOption.Limited`
   Token Request, in either flow, is affected. The run notes it
   (`known`) without failing, and says so once a release fixes it. The
   refusal doesn't spend the pre-authorized code: OID4VCgo checks
   `authorization_details` before consuming it.
3. **The library doesn't read an error response that isn't a 400.**
   RFC 6749 §5.2 lets the Token Endpoint answer `invalid_client` with a
   401 ("The authorization server MAY return an HTTP 401 (Unauthorized)
   status code"), and RFC 9126 §2.3 gives PAR the same error format.
   `TokenEndpointClient` and `AuthorizationEndpointClient` parse the
   error object only for a 400; any other status becomes
   `AccessTokenRequestFailed("Token request failed with 401 Unauthorized", "N/A")`,
   for PAR as well, so the wallet can't tell an untrusted attestation
   from any other failure. The request is refused either way; the
   controls read the 401's error object from the exchange itself.

The run found nothing to fix in OID4VCgo's issuer beyond the `use` of
finding 1.

### What isn't covered

- Refreshing the access token: FAPIgo's Authorization Server issues a
  refresh token only when the grant includes `offline_access`, as
  OpenID Connect does, and the library requests only the scopes of the
  configurations it asks for.
- A Wallet Attestation challenge (attestation-based client auth's
  challenge endpoint or `OAuth-Client-Attestation-Challenge`): the
  issuer issues none.
- `authorization_details` in the Token Request, beyond the refusal:
  finding 2.
- Status lists in issued credentials: this run's `cmd/conformance-issuer`
  issues none (it leaves `status_lists` unset), and the library is a
  wallet, which wouldn't check them. The OIDF issuer runs, and the
  walt.id run's Verifier2, check the issuer's.
- Key attestations trusted by a trust chain: the development profiles
  trust one configured key, the production profile the Wallet
  Provider's `x5c` chain. Several key-attested proofs in one request:
  the library sends one (ETSI TS 119 472-3).
- PostgreSQL, and several issuer instances sharing a store: the
  production profile's stores are one SQLite file, one instance.
- RSA request or response encryption: the issuer supports ECDH-ES only.
- Credential reuse policies and registration certificates (ETSI TS
  119 472-3, the ARF): not part of OpenID4VCI or HAIP, and the issuer
  publishes neither.
- A newer library than the pinned one: unlike the verifier's image, the
  library is pinned with its dependencies locked and checksum-verified,
  so the weekly run doesn't try `latest`.

Run it locally (Go, a JDK 17 or later, curl and jq; the driver's
dependencies come from Maven Central):

```sh
interop/eudi/run-issuer.sh
PROFILES="base deferred" interop/eudi/run-issuer.sh
```

`PORT` and `OFFERS_PORT` (18446 and 18447) move the issuer's
listeners, `WP_PORT` (`PORT`+2, and the five ports after) the
production profile's Wallet Providers, their admin listeners and
agents, and `WORK` keeps the run's files, its keys among them. The
driver's stack traces and the library's logging go to
`driver-<profile>.log`, the issuer's to `issuer-<profile>.log`.

### Moving the library's pin

The library's version is in [`issuance/gradle/libs.versions.toml`](issuance/gradle/libs.versions.toml),
every resolved dependency locked in `gradle.lockfile`, and each one's
checksum in `gradle/verification-metadata.xml`. To move it, read the
release's changes, change the version, then, in `issuance/`, with an
empty Gradle cache so that Gradle fetches, and records, every artifact
and POM a clean runner does:

```sh
GRADLE_USER_HOME="$(mktemp -d)" ./gradlew --write-verification-metadata sha256 --write-locks resolveAndLockAll installDist
```

and review the new checksums: Gradle records what Maven Central serves.

## Wallet ↔ EUDI PID Issuer

[`run-pid-issuer.sh`](run-pid-issuer.sh) has OID4VCgo's wallet obtain
PIDs from
[eudi-srv-pid-issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer)
v0.11.2, run as the stack its own `docker-compose/` defines, with
Keycloak 26 and its attestation-based client authentication extension
(`abca-keycloak-ext` 0.2.0), the status list service
(`eudi-srv-statuslist-py` v0.9.0), Postgres and HAProxy.
[`pid-issuer/compose.yaml`](pid-issuer/compose.yaml) reproduces that
file, not as it is: besides every image pinned by digest, every key,
certificate and password made for the run, and HAProxy alone published,
on loopback, it differs in

- the `insecure` Spring profile, off, and TLS verified: Keycloak trusts
  the run's TLS CA (`KC_TRUSTSTORE_PATHS`), and the issuer's JVM too,
  through the image's `ca-certificates` binding (`SERVICE_BINDING_ROOT`);
- a Credential Reuse Policy (`once_only`) for both PID formats, without
  which the issuer allocates no status list entry, so its PIDs carry no
  status (finding 6);
- the issuer's registration certificate (`ISSUER_WRPRC`), the run's own
  rather than the one the file embeds, and its display name, without
  the logo;
- `-XX:MaxDirectMemorySize=128M` for the issuer's JVM, where the file
  sets 64M;
- HAProxy's file descriptor limit (`ulimits`), which a GitHub runner's
  containers need raised;
- Keycloak's extension mounted as a provider jar, rather than built into
  an image of its own.

The wallet is [`scripts/pidwallet`](scripts/pidwallet): the `wallet`
package and `fapigo/client`, used as walletflow uses them (engine
`core`), or walletflow itself (engine `walletflow`). Not all of `core`
is walletflow's code: its status check (`checkStatus` in
[`scripts/pidwallet/verify.go`](scripts/pidwallet/verify.go)) is a
copy of the signer trust walletflow's `CheckStatus` applies, kept by
hand, which the `walletflow` engine runs itself. It stands in for the
holder's browser too,
signing the test user in on Keycloak's login page.

Every issuance runs the authorization code flow: PAR with PKCE, a
Wallet Attestation at the PAR and token endpoints (its PoP carrying a
challenge from Keycloak's challenge endpoint), a DPoP-bound access
token, the Nonce Endpoint's c_nonce (and its DPoP-Nonce, for the
Credential Request), and a Credential Request and Response both
encrypted, as the issuer requires. The wallet asks for signed metadata
only, and verifies it under the Access Certificate's CA, its signer
naming the issuer. It verifies each credential as walletflow does on
receipt (`wallet.VerifyIssuedCredential`: signature under the issuer's
IACA, the signer's role, the SD-JWT VC's iss named by its certificate,
validity, holder binding to one of its keys), checks its Token Status
List entry as walletflow's `CheckStatus` does (`statuslist.Checker`),
and acknowledges it at the Notification Endpoint.

| Case | Expected |
|---|---|
| Wallet-initiated, SD-JWT VC PID, `attestation` proof | issued and verified, status `VALID` |
| Wallet-initiated, SD-JWT VC PID, `jwt` proof with `key_attestation` | issued and verified, status `VALID` |
| Wallet-initiated, mdoc PID, each proof type | issued and verified; the wallet refuses its status list (see Findings) |
| The issuer's own Credential Offer, each format | issued and verified, the offer's configuration requested |
| A batch: three PIDs for three keys in one Key Attestation, each format | three credentials, each bound to its own key |
| Deferred, each format | deferred, then fetched from the Deferred Credential Endpoint |
| An SD-JWT VC revoked at the status list service (its `/set`) | the wallet reads it as `INVALID` |
| Metadata signed under a CA the wallet doesn't trust | the wallet refuses the metadata |
| Credentials under an IACA the wallet doesn't trust, each format | the wallet refuses them |
| Credentials whose signer the IACA revoked (its CRL names the Document Signer and the SD-JWT VC signer), each format | the wallet refuses them: `issuer certificate: … certrevocation: certificate is revoked` |
| Credentials whose IACA publishes no current CRL (its distribution point serves one past its `nextUpdate`), each format | the wallet refuses them: `issuer certificate: … certrevocation: no current CRL from the certificate's issuer` |
| A Wallet Attestation whose `client_status` is revoked | Keycloak refuses the PAR |
| A Key Attestation whose `key_storage_status` is revoked | the issuer refuses the proof |
| walletflow, under `ProfileHAIP` with its default proof: one PID, then a batch of three | issued and verified, status `VALID` |
| A `jwt` proof naming its key in `jwk`, as `GenerateProofWithKeyAttestation` makes it | refused, `invalid_proof` naming `kid` (a note, not a failure: see Findings) |
| walletflow naming the proof's key in `jwk` (`Config.ProofKeyByJWK`) | refused, the same (a note: see Findings) |
| A batch of one `jwt` proof per key | refused, `invalid_proof`: at most one proof (a note: see Findings) |

Every run checks the issuer's certificates for revocation, both
engines alike: the Document Signer, the SD-JWT VC signer and the
status list signer against the IACA's CRL, and the signed metadata's
Access Certificate against its CA's
(`IssuerRevocation`, `StatusRevocation` and `IssuerMetadataRevocation`
for walletflow; `VerifyIssuedCredentialParams.IssuerRevocation`,
`statuslist.VerifyOptions.Revocation` and
`Config.IssuerMetadataRevocation` for the wallet package). Each
certificate names an https distribution point on `localhost:$CRL_PORT`,
where `pidwallet` serves the lists `scripts/pidsetup` signed (its
`-crl-set`) and fetches them back with a `certrevocation.Refresher`,
https only, bound to each CA. The issuer and its status list service,
which sign with those certificates, fetch nothing for them: the check
is the wallet's alone. The two revocation controls differ from the
issuances above only in the IACA's list the wallet is served; the
metadata CA's stays current, so each fails at the credential.

A Wallet Attestation and a Key Attestation are each other's controls'
twins: the same Wallet Provider, the same status list, another index.
The run also checks Keycloak and the issuer fetched that list from
[`scripts/serve`](scripts/serve), so a run in which they skipped the
check fails.

The issuer is run as strictly as it can be configured:

- Its `insecure` profile, which the stack sets and which makes every
  outbound client trust any certificate, is off: it trusts the run's
  TLS CA, through the image's `ca-certificates` binding, for Keycloak's
  own listener (introspection, admin API) and for the Wallet Provider's
  status list. Keycloak trusts it through `KC_TRUSTSTORE_PATHS`.
- Its PIDs carry a Token Status List entry. It allocates one only under
  a Credential Reuse Policy, which the stack leaves unset, so its PIDs
  carry none; the run sets `once_only` for both formats.
- Keycloak's realm is the stack's, with one change: the introspection
  client's secret is the run's own. The wallet is the realm's own
  `eudiw-abca` client with the EUDI wallet app's redirect URI,
  `eu.europa.ec.euidi://authorization`, which the realm registers for
  it (see Findings); the run refuses a realm that no longer does.

Every key, certificate and password is the run's own, made by
[`scripts/pidsetup`](scripts/pidsetup) and the script: the TLS CA and
the stack's listeners' certificates; the issuer's IACA, its Document
Signer, its SD-JWT VC signer, its Access Certificate (under a CA of its
own), its request and nonce encryption keys, the status list service's
signer, and a Wallet Relying Party Registration Certificate; the Wallet
Provider's CA, Wallet Attestation and Key Attestation signers, and its
status list. The stack's own keystore, certificates and passwords,
which are in its public repository, aren't used. The fetched files
(the realm, the status list service, the Keycloak extension) are pinned
by SHA-256, and the images by digest; the status list service's Python
dependencies are binary wheels, each pinned by SHA-256 in
[`pid-issuer/status-list-requirements.txt`](pid-issuer/status-list-requirements.txt)
(regenerate it with `pip download --only-binary :all:` in the pinned
Python image when its version moves). Only the stack's logs, with the
run's passwords redacted, and the wallet's results are uploaded.

The Wallet Provider is a stand-in: package `attestation` issues only
OpenID4VCI 1.0 Appendix D's and E's claims, and the EUDI stack requires
those the EUDI Wallet Unit Attestation specification (TS3) adds —
`wallet_name`, `wallet_version`,
`wallet_solution_certification_information` and `client_status` in the
Wallet Attestation, `key_storage` and `user_authentication`
(`iso_18045_high`), `certification` and `key_storage_status` in the Key
Attestation, each status valid for more than the issuer's 31-day
preferred period. HAIP 1.0 §4.4.1 leaves an ecosystem room for such
claims, and walletflow takes them through its `WalletProvider`, which
`pidwallet`'s implements. OID4VCgo's own Wallet Provider
(`walletprovider.Provider`, which the issuer, walt.id and Multipaz runs
use as deployed, [`../walletprovider`](../walletprovider)) issues
Appendix D's and E's claims alone too, with no setting for TS3's, so
this run keeps the stand-in.

Of what the wallet is lenient about (SPECIFICATIONS.md, "Known
leniencies"), the issuer sends its `credential_request_encryption`
keys, whose `kid` OpenID4VCI 1.0 §12.2.4 requires and the wallet
doesn't, and Keycloak its `token_type`, which the wallet would take as
`Bearer`. The run asserts the keys as v0.11.2 publishes them, one with
`alg` `ECDH-ES` and a `kid`, and `token_type` `DPoP` for every
issuance, so a change is noticed; both follow the specifications.

### Findings

Against OpenID4VCI 1.0 Final and HAIP 1.0 Final, from the live run and
the issuer's v0.11.2 source:

1. **The issuer refuses a `jwt` proof that names its key in `jwk`.**
   With a `key_attestation`, it requires `kid` `"0"`, the key's index in
   `attested_keys` (ETSI TS 119 472-3; `ValidateJwtProofWithKeyAttestation.kt`,
   `"JWT Proof with key_attestation must contain header kid with value 0"`).
   Appendix F.1 allows any of three: "The Credential Issuer MUST
   validate that the JWT used as a proof is actually signed by a key
   identified in the JOSE Header through either kid, jwk or x5c
   element", and of `jwk`, "It MUST NOT be present if kid or x5c is
   present"; Appendix D.1 adds only "If used with the jwt proof type,
   the Credential Issuer MUST validate that the JWT used as a proof is
   signed by a key contained in the attestation in the JOSE Header".
   `wallet.Wallet.GenerateProofWithKeyAttestation` conveys the key in
   `jwk`, as walletflow, which prefers the `jwt` proof type, does under
   `Config.ProofKeyByJWK`. `wallet.Wallet.GenerateProofWithAttestedKeyIndex`
   names it by kid `"0"` with no `jwk`, also valid under F.1, which the
   issuer accepts; walletflow uses it by default, as the run does.
2. **It advertises batch issuance but refuses more than one proof.**
   Its metadata has `batch_credential_issuance.batch_size` 20, and a
   Credential Request with two `jwt` proofs is refused: `"You can
   provide at most 1 proof"` (`IssueCredential.kt`,
   `ProofsTO.toDomain`). §12.2.4: "The presence of this parameter means
   that the issuer supports more than one key proof in the proofs
   parameter in the Credential Request so can issue more than one
   Verifiable Credential for the same Credential Dataset in a single
   request/response", and `batch_size` is "the maximum array size for
   the proofs parameter in a Credential Request". It issues a batch
   only for the keys of one Key Attestation (which HAIP 1.0 §4.5.1
   recommends: "all public keys used in Credential Request SHOULD be
   attested within a single key attestation").
3. **The status list service's CWT Status List Tokens can't be
   verified.** v0.9.0 signs them (`app/status_list_format.py`,
   `cwt_format`) with a DER-encoded ECDSA signature, where COSE's is
   the fixed-length `r || s` (RFC 9053 §2.1), over the protected header
   and the claims concatenated, where COSE_Sign1 signs its
   `Sig_structure` (RFC 9052 §4.4); and with no `exp`, which ISO/IEC
   18013-5 §12.3.6.3 has an mdoc's list carry. Some of its tokens
   aren't even well-formed CBOR: they carry bytes after the COSE_Sign1
   (seen in CI: `cbor: 2 bytes of extraneous data`), so they fail
   before the signature is reached. An mdoc PID's status is therefore
   refused (`ecdsafixed: signature has length 71, want 64`, or the CBOR
   error), and the run's mdoc cases expect either, printing which; revocation is shown with the
   SD-JWT VC, whose JWT form verifies. Its JWT tokens carry neither
   `exp` nor `ttl`, which the status list draft recommends; the wallet
   accepts one while it's fresh.
4. **Its Credential Offer names an `authorization_server` though its
   metadata lists one.** §4.1.1, of `authorization_server`: "OPTIONAL
   string that the Wallet can use to identify the Authorization Server
   to use with this grant type when authorization_servers parameter in
   the Credential Issuer metadata has multiple entries. It MUST NOT be
   used otherwise." (`CreateCredentialsOffer.kt`,
   `authorizationCodeGrantOffer`). The wallet accepts it, since it
   matches the one listed.
5. **Its shipped keystore signs metadata with a self-signed
   certificate.** The stack's `issuer-keys.jks`, alias
   `access-certificate`, is self-signed (`CN=pid-issuer, C=GR`), where
   HAIP 1.0 §4.1 has "The X.509 certificate signing the request MUST
   NOT be self-signed"; the wallet would refuse it. Its
   `request-encryption` certificate expired on 2026-08-26. The run uses
   its own keys.
6. **With no Credential Reuse Policy, its PIDs carry no status.**
   `allocateStatusWithPolicy` (`AttestationIssuer.kt`) allocates none
   for `CredentialReusePolicy.None`, though `shouldIncludeStatusList`
   is `true` for it. HAIP 1.0 §6.1 has an SD-JWT VC carry "an exp
   claim, a status claim, or both", and these have `exp`, so this isn't
   a deviation, only why the run sets a policy.
7. **The Key Attestation's `exp` is required for the `attestation`
   proof type too** (`KeyAttestationClaims`, `@Required`), where
   Appendix D.1 has it "OPTIONAL ... MUST be present if the attestation
   is used with the JWT proof type". From the source; the run's
   attestations always carry one.
8. **Keycloak's registered redirect URIs for the wallet clients are
   private-use URIs with an authority**, such as
   `eu.europa.ec.euidi://authorization`, where RFC 8252 §7.1 writes
   "only a single slash" after the scheme. That is its description, not
   a requirement, and since FAPIgo v0.73.0 `fapigo/client` and
   `fapigo/server` take the form (an authority of letters, digits, `-`,
   `.`, `_` and `~`, matched exactly), so the run uses this one, the
   EUDI wallet app's, where it used to register one of its own; the
   EUDI wallet library ↔ Issuer run registers it for a native client of
   `cmd/conformance-issuer`. Not a deviation. The issuer's
   introspection client (`pid-issuer-srv`) also introspects "without
   audience check", as Keycloak logs, so it takes an access token
   issued for any client.

The wallet's own checks held throughout, and caught one thing while the
run was set up: an mdoc whose `issuing_country` doesn't match its
Document Signer's `countryName` (ISO/IEC 18013-5 Annex B) is refused,
so the run's certificates are issued for the issuer's default, `GR`.

What isn't covered:

- The pre-authorized code flow: the issuer has none.
- An mdoc's status and its revocation: see Finding 3.
- walletflow's protocol steps: its runs record no exchanges, so the
  run checks only what it receives; walletflow's own tests check the
  steps.
- A `use_dpop_nonce` challenge: the wallet uses the Nonce Endpoint's
  DPoP-Nonce for its Credential Request, so the issuer never has to
  challenge it, and Keycloak issues no DPoP nonces.
- Refresh tokens and credential refresh, the `credential_failure` and
  `credential_deleted` notifications, plaintext requests (the issuer
  requires encryption), and the issuer's mDL and Learning Credential.
- Attester trust: with no `trustValidator.serviceUrl` (Keycloak) or
  `ISSUER_TRUST_SERVICE_URL` (issuer), both trust every Wallet
  Provider, so no control shows them refusing an unknown one.

Run it locally (Docker with compose, Go, jq, curl, openssl and
keytool; the issuer image is amd64 only):

```sh
interop/eudi/run-pid-issuer.sh
PID_ISSUER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-pid-issuer:latest interop/eudi/run-pid-issuer.sh
```

`PORT`, `SERVE_PORT` and `CRL_PORT` (19443, 19445 and 19446) move HAProxy's, serve's and the wallet's CRL
listeners, `WORK` keeps the run's files, and `COMPOSE_PROJECT_NAME`
(`oid4vcgo-eudi-pid`) names the stack. `PID_STOP_AFTER_UP=1` leaves the
stack and serve running once the issuer is up, for working on the cases
with `pidwallet` by hand.

### Moving the pins

The issuer image is pinned by digest in `run-pid-issuer.sh`, with the
commit of its tag, whose `docker-compose/` files the run fetches by
SHA-256, and the versions that compose file names: Keycloak, Postgres
and HAProxy by digest, the Keycloak extension and the status list
service by SHA-256. The status list service's Python base image is
pinned by digest in [`pid-issuer/status-list.Dockerfile`](pid-issuer/status-list.Dockerfile),
and its wheels in `pid-issuer/status-list-requirements.txt`. The weekly run tests EUDI's `latest` issuer
image against the pinned stack. To move the pins, read the release's
changes and its `docker-compose/`, then take the new digests and hashes:

```sh
docker buildx imagetools inspect ghcr.io/eu-digital-identity-wallet/eudi-srv-pid-issuer:vX.Y.Z
curl -sSfL https://raw.githubusercontent.com/eu-digital-identity-wallet/eudi-srv-pid-issuer/COMMIT/docker-compose/PATH | openssl dgst -sha256
```

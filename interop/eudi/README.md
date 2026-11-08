# EUDI interop

Interop runs against the [EUDI Wallet reference implementation](https://github.com/eu-digital-identity-wallet)'s
own components, run locally from their published images and libraries.
They run in CI from [`.github/workflows/eudi-interop.yml`](../../.github/workflows/eudi-interop.yml).

## Wallet ↔ EUDI Verifier Endpoint

[`run-verifier.sh`](run-verifier.sh) presents from
`cmd/conformance-wallet-vp` to
[eudi-srv-verifier-endpoint](https://github.com/eu-digital-identity-wallet/eudi-srv-verifier-endpoint),
driving the verifier through its own REST API (`POST /ui/presentations`
to start a transaction, `GET /ui/presentations/{id}` for the result) and
standing in for the same-device launch and the browser:

| Case | Expected |
|---|---|
| SD-JWT VC PID, `haip` profile, `direct_post.jwt` | accepted |
| The same, `openid4vp` profile | accepted |
| mdoc PID, `haip` profile | accepted |
| mdoc PID, `openid4vp` profile | accepted |
| mdoc PID over the Digital Credentials API (`openid4vp-v1-signed`) | accepted |
| The answered request launched again | refused |
| The verifier trusts an unrelated issuer CA | the verifier refuses the credential |
| The launch's `client_id` isn't the signed request's | the wallet refuses |
| A query for a credential the wallet doesn't hold | the verifier receives `access_denied` |
| The wallet trusts an unrelated CA for the verifier | the wallet refuses |
| A revoked SD-JWT VC (its status list entry invalid) | the verifier refuses it |
| An SD-JWT VC whose `vct#integrity` doesn't match its Type Metadata, before the verifier has the metadata cached | the verifier refuses it |
| A revoked mdoc | the verifier refuses it |

Each accepted case also completes the same-device return: the wallet
follows the verifier's `redirect_uri`, and the verifier releases the
`vp_token` only for that `response_code`.

The verifier is run as strictly as it can be configured:

- Each credential carries a Token Status List reference, and the
  verifier checks it (`VERIFIER_VALIDATION_STATUSCHECK_ENABLED`): a JWT
  Status List Token for the SD-JWT VC, a CWT one for the mdoc.
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

The run also checks the verifier fetched each status list and the Type
Metadata, so a run in which it silently skipped a check fails.

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
  and says so if a later image refuses it.

Every key, certificate and document is throwaway, made per run by
[`scripts/setup`](scripts/setup):

- the wallet's fixture credentials, an SD-JWT VC under a CA and an mdoc
  under an IACA, and their x5c-signed Status List Tokens (index 0 valid,
  1 invalid);
- the PID's Type Metadata;
- the verifier's Access Certificate (its Request Object signing key, a
  leaf under a CA the wallet trusts; EUDI refuses a self-signed one), its
  TLS listener, and a Relying Party registration certificate, which EUDI
  refuses a transaction without;
- `scripts/serve`'s TLS certificate, for `host.docker.internal`, under
  its own CA.

What isn't covered:

- `request_uri_method` post: the EUDI verifier refuses a
  `wallet_metadata` without `issuer` and `response_types_supported`
  (it parses it as RFC 8414 Authorization Server metadata, which
  requires both), and `cmd/conformance-wallet-vp` sends only
  `vp_formats_supported`.
- Plain `direct_post`: `cmd/conformance-wallet-vp` always encrypts its
  response.
- ISO/IEC 18013-7 Annex C (`org-iso-mdoc`): the EUDI verifier has no
  such endpoint.

Run it locally (Docker, Go, jq, curl and openssl; on Apple silicon the
amd64 image runs emulated and takes a couple of minutes to start):

```sh
interop/eudi/run-verifier.sh
VERIFIER_IMAGE=ghcr.io/eu-digital-identity-wallet/eudi-srv-verifier-endpoint:latest interop/eudi/run-verifier.sh
```

`PORT`, `WALLET_PORT` and `SERVE_PORT` (18443, 18444 and 18445) move
the listeners, and `WORK` keeps the run's files. On Linux, `serve`
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

Two verifiers run, one asking for the SD-JWT VC PID (`dc+sd-jwt`,
`urn:eudi:pid:1`), one for the mdoc PID (`eu.europa.ec.eudi.pid.1`),
each for `family_name` and `given_name`. Each is configured as strictly
as the binary allows: the issuer trusted by its x5c chain to the run's
CA (or IACA), never a pinned key; every credential's Token Status List
checked, a status reference required, the list signed by the
credential's issuer and fetched over TLS it verifies; holder binding
required; a disclosed claim the query didn't ask for refused. The run
also checks that the status lists were fetched.

| Case | Expected |
|---|---|
| SD-JWT VC, `request_uri_method=post` | accepted; the wallet fetches with a form POST, a `wallet_nonce` and `wallet_metadata` |
| SD-JWT VC, `request_uri_method=get` | accepted; fetched with GET |
| SD-JWT VC, no `request_uri_method` | accepted; fetched with GET |
| SD-JWT VC, `post` to a wallet that supports only GET | accepted; fetched with GET |
| SD-JWT VC, a wallet that encrypts only with A256GCM | accepted, encrypted with A256GCM |
| SD-JWT VC over the Digital Credentials API (`openid4vp-v1-signed`, `dc_api.jwt`) | accepted |
| mdoc, `request_uri_method=post` and `get` | accepted |
| mdoc over the Digital Credentials API | accepted |
| A `response_code` redeemed a second time | the verifier refuses |
| A Digital Credentials API answer posted a second time | the verifier refuses |
| A revoked SD-JWT VC, or mdoc (its status list entry invalid) | the verifier refuses it |
| An SD-JWT VC, or mdoc, from an issuer under an untrusted CA | the verifier refuses it |
| A KB-JWT for another nonce, or another `aud` | the verifier refuses it |
| An SD-JWT VC without a KB-JWT | the verifier refuses it |
| An SD-JWT VC, or mdoc, disclosing a claim the query didn't ask for | the verifier refuses it |
| An mdoc whose SessionTranscript names another nonce, or another `client_id` | the verifier refuses it |
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
`response_code`, and releases the result once, for that code
(`/result/{id}/redeem`), with how the wallet fetched the Request Object.
The released claims must be the two asked for and none of the PID's
others.

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
  above); this verifier ignores `wallet_metadata`, and the run checks
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
- A `response_code` bound to the browser that started the request, and
  the issuer certificates' revocation (CRLs): `cmd/conformance-verifier`
  has neither (see `conformance/verifier/README.md`).

Run it locally (Go, a JDK 21 or later, jq, curl and openssl):

```sh
interop/eudi/run-wallet.sh
```

`PORT`, `MDOC_PORT` and `SERVE_PORT` (20443, 20444 and 20445) move the
listeners, and `WORK` keeps the run's files. Every key, certificate and
document is throwaway, made per run by [`scripts/setup`](scripts/setup)
and the driver; CI uploads the logs and the verifiers' answers, never
the work directory's keys.

### Moving the pins

The driver pins every dependency in
[`presentation/build.gradle.kts`](presentation/build.gradle.kts), and
its lockfiles pin the transitive ones. To move one, read the release's
changes, set the version, then `./gradlew dependencies --write-locks`
in `presentation/`. Nothing moves them automatically, and the weekly
run doesn't test the libraries' newest releases.

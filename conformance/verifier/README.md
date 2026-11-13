# conformance-verifier

`cmd/conformance-verifier` stands up `verifier.Verifier` behind real
HTTP for the OIDF conformance suite's own
`oid4vp-1final-verifier-haip-test-plan` ("OpenID for Verifiable
Presentations 1.0 Final/HAIP: Test a verifier", confirmed against the
suite's own source at
`gitlab.com/openid/conformance-suite`, `src/main/java/net/openid/
conformance/vp1finalverifier/VP1FinalVerifierTestPlanHaip.java`) — the
suite plays Wallet, generating its own emulated test credentials
(`vct: "urn:eudi:pid:1"`, claims including `given_name`/`family_name`/
`birthdate`/... — see the suite's own
`AbstractCreateSdJwtCredential.java`), so this binary needs no fixture
credentials of its own, only a DCQL query and trust in the issuers
that sign them: for `sd_jwt_vc`, the suite's "Credential Issuer" >
"Signing JWK", which the drivers generate per run with an `x5c`
certificate under a per-run CA; for `iso_mdl`, the suite's fixed IACA
root (see "Credential status" below).

It has two engines (`engine` in its config). The default, `sessions`,
is this binary's own session store calling `verifier.Verifier`
directly; the interop runs use it. `transactions` serves the same plan
through `verifier.Transactions`, a deployment's API, under production
assurance in the suite runs: see "Transactions engine" below.

## What not to copy

This binary is a conformance-suite harness. Its default engine drives
`verifier`'s lower-level API (`BuildAuthorizationRequest`,
`ParseDirectPostJWTResponse`, `VerifyResponse`) because those are what
the suite grades, and it skips everything a deployment needs around
them (the transactions engine has what the first three of these lack,
and is still a harness: see its section):

- **No session binding.** It keeps its own in-memory session map rather
  than a `verifier.Transactions`. The `redirect_uri` it returns names
  `/result/{id}`, which shows the verified claims to anyone who has the
  id, and the id is also in the public `request_uri`. Its
  `response_code` is single-use at `/result/{id}/redeem`, but bound to
  no browser that started the request (OpenID4VP §8.2, HAIP 1.0 §5.1),
  and the HTML page doesn't need it.
- **No atomic completion.** A session's `done` flag is checked and set
  by the handler under a per-session lock, not by a store's atomic
  update, and only one process's memory holds it.
- **Development assurance, a test harness's status fetch, no
  revocation.** It runs under `verifier.AssuranceDevelopment`. It
  checks credential status when `status_list_trust_anchors_pem` is set
  (the suite runs and the interop runs set it), but its fetch may
  reach private or loopback addresses and, in the suite runs, trusts
  the suite's TLS certificate by a pin rather than a chain, neither of
  which production allows. It declines certificate revocation
  (`certrevocation.NoCheck{}`) for the suite's per-run issuers.

A Verifier uses `verifier.Transactions` with a durable
`verifier.TransactionStore` (encoded with `verifier.TransactionCodec`),
`TransactionsConfig.Status`, and issuer key resolvers with a
`Revocation`, under `verifier.AssuranceProduction`.
`examples/passport-vdc`'s verifier is wired that way.

## Endpoints

These are the default engine's; the transactions engine's are under
"Transactions engine".

- `GET /authorize` — creates a session (the DCQL query to ask for) and
  redirects to
  `openid4vp://?client_id=...&request_uri=...&request_uri_method=post`
  — what the suite's own browser (playing Wallet) navigates to. A
  `request_uri_method` query parameter (`get`, or `none` to leave it
  out) changes the launch's, for an interop run.
  Building and signing the actual Authorization Request is deferred to
  the first `/request/{id}` fetch below, not done here — see
  `session.go`'s `ensureBuilt` for why.
- `GET|POST /request/{id}` — builds (on the first fetch) or replays
  (on any later fetch) that session's signed Request Object JWS
  (`application/oauth-authz-req+jwt`). A POST fetch (OID4VP §5.10) may
  carry a form-encoded `wallet_nonce`; if it does, and this is the
  fetch that triggers the build, the nonce is embedded as the signed
  object's own `wallet_nonce` claim (§5.10.1's own "the Verifier MUST
  use it as the wallet_nonce value in the signed authorization request
  object"). Once built, a session's own Request Object never changes
  on a later fetch — its nonce/response-encryption key have to stay
  stable for `POST /response`'s own later matching/decryption.
- `POST /response` — this Verifier's own fixed `response_uri`
  (`verifier.Config.ResponseURI` is set once at construction, so every
  session shares it): decrypts+parses the `direct_post.jwt` response,
  correlates it to a pending session by trying each one's own
  decryption key in turn (JWE's authenticated encryption rejects a
  wrong key rather than silently misdecoding — see `session.go`'s own
  doc comment), calls `VerifyResponse`, and replies with
  `{"redirect_uri": ".../result/{id}?response_code=..."}` — HAIP's own
  requirement on top of plain OID4VP §8.3. A response for no pending
  session (a replayed one among them) is refused with 400, and so,
  with `reject_unverified_responses` (the suite runs), is a
  presentation that fails verification (see "Status").
- `GET /result/{id}` — a plain HTML page reporting that session's
  outcome, for the suite's own "verifier_verification_result_screenshot"
  evidence capture.
- `GET /result/{id}/redeem?response_code=...` — the outcome as JSON,
  once, for the `response_code`, with how the Wallet fetched the
  Request Object: what an interop run checks.
- `POST /dcapi/request?origin=...` and `POST /dcapi/response/{id}` —
  with `dc_api_origins` configured, a signed Digital Credentials API
  request (`openid4vp-v1-signed`, `dc_api.jwt`) for one of those
  origins, and the page's post-back of the answer, verified against
  that origin; the outcome is the reply.

The trust and status fields (`credential_issuer_trust_anchors_pem`,
the `status_list_*` fields, `status_reference_optional`) and
`dc_api_origins` are documented in
`cmd/conformance-verifier/config.go`. The suite runs set the trust and
status fields (`internal/conformanceverifier`'s `configureTrust`);
`interop/eudi/run-wallet.sh`, `interop/waltid/run.sh` and the Multipaz
interop's peer (`interop/multipaz/scripts/peer/vp.go`) set their own,
requiring a status reference on every credential.

## Status

Driven live against a locally-run OIDF conformance suite (pre-built
Docker images, `docker-compose-prebuilt.yml`) by two tools sharing
`internal/conformanceverifier`:
`conformance/verifier/scripts/run-sdjwt-modules`
(`credential_format=sd_jwt_vc`) and
`conformance/verifier/scripts/run-mdoc-module`
(`credential_format=iso_mdl`), both under `direct_post.jwt` +
`x509_hash` + `request_uri_signed`. Each drives every module the
plan's own module list (`POST /api/plan`) names for its format, and
exits non-zero unless every module's verdict is the one its
expectation names. A module the plan lists that has no expectation
fails the run, so a module the suite adds is classified before it is
trusted.

### How a verdict is reached

OpenID4VP lets a Verifier refuse a presentation at the `response_uri`
(4xx) or answer 200 and defer verification. The suite grades the
first itself; for the second it can't see what the Verifier decided,
so it waits for a screenshot of the Verifier's result page and ends
the module `REVIEW`, whatever the Verifier decided. This binary used
to answer every response 200, so every module, positive or negative,
ended `REVIEW` and the run could not fail on a wrong verification
outcome.

The suite runs now set `reject_unverified_responses` (see
`Config.RejectUnverifiedResponses`): a presentation `VerifyResponse`
refuses is answered 400, so the suite grades a negative module
`PASSED` itself, and a wrongly accepted one ends `REVIEW` instead,
which the driver counts as a failure. A verified presentation is still
answered 200 with the HAIP-required `redirect_uri`, and the driver
fills the screenshot placeholder with a stand-in image, ending the
module `REVIEW`: the only verdict the suite gives a Verifier that
accepted a presentation. Interop runs leave the option unset: they
redeem the result page's outcome instead.

Each module is graded on three things (`conformanceverifier.Grade`):

- the suite's status and result: `FINISHED=REVIEW` for a module whose
  presentation must be accepted, `FINISHED=PASSED` for one that must
  be refused;
- this binary's own outcome, read from `GET /result/{id}`:
  `Verification succeeded` or `Verification failed` respectively;
- the module's log (`GET /api/log/{id}`): no `FAILURE` and no
  `WARNING`. `REVIEW` outranks `WARNING` in a result, so a warning would
  otherwise go unseen. That includes
  `EnsureVerifierFetchedRevocationList`, which an accepted module logs
  as a warning when the Verifier never fetched the status list its
  credential references.

### Expected verdicts

The transactions engine's legs expect the same of every module (see
"Transactions engine").

| Module | `sd_jwt_vc` | `iso_mdl` | Verifier must | Suite verdict |
| --- | --- | --- | --- | --- |
| `happy-flow` | yes | yes | accept | `FINISHED=REVIEW` |
| `minimal-cnf-jwk` | yes | — | accept | `FINISHED=REVIEW` |
| `request-uri-method-post` | yes | yes | accept | `FINISHED=REVIEW` |
| `request-uri-fetched-twice` | yes | yes | accept | `FINISHED=REVIEW` |
| `present-credential-without-status` | yes | yes | accept | `FINISHED=REVIEW` |
| `invalid-kb-jwt-signature` | yes | — | refuse | `FINISHED=PASSED` |
| `invalid-credential-signature` | yes | — | refuse | `FINISHED=PASSED` |
| `invalid-sd-hash` | yes | — | refuse | `FINISHED=PASSED` |
| `invalid-kb-jwt-nonce` | yes | — | refuse | `FINISHED=PASSED` |
| `invalid-kb-jwt-aud` | yes | — | refuse | `FINISHED=PASSED` |
| `kb-jwt-iat-in-past` | yes | — | refuse | `FINISHED=PASSED` |
| `kb-jwt-iat-in-future` | yes | — | refuse | `FINISHED=PASSED` |
| `wrong-vct` | yes | — | refuse | `FINISHED=PASSED` |
| `invalid-session-transcript` | — | yes | refuse | `FINISHED=PASSED` |
| `present-revoked-credential` | yes | yes | refuse | `FINISHED=PASSED` |
| `present-credential-on-identifier-list` | — | yes | refuse | `FINISHED=PASSED` |

`kb-jwt-iat-in-past` and `kb-jwt-iat-in-future` present a Key Binding
JWT issued a year ago or a year from now. The suite's
`VP1FinalVerifierKbJwtIatIn{Past,Future}` extend
`AbstractVP1FinalVerifierNegativeTest`, and their summaries say the
Verifier should reject the presentation: they are negative modules.
This binary refuses both (`MaxKeyBindingAge` is five minutes; the
library's clock-skew bound refuses a future `iat`). An earlier version
of this file listed them as positive modules that verify; the
Verifier's own log never said so.

`wrong-vct` and `present-credential-without-status` are newer than
this repo's certification run, and pass.

To check that the harness catches a Verifier that accepts what it
must refuse: make `server.verify` in `handlers.go` return without
setting `failErr` for an error mentioning "signature", and run
`run-sdjwt-modules`. `invalid-kb-jwt-signature` and
`invalid-credential-signature` then end `FINISHED=REVIEW` with the
result page reporting `verified`, and the run exits 1.

### Credential status

Every credential the suite presents carries a revocation reference,
except in `present-credential-without-status`: a Token Status List
entry, or for `present-credential-on-identifier-list` an mdoc
identifier list (ISO/IEC 18013-5 §12.3.6.4). Each module serves its
own list, at a URI no earlier run used, so a cached copy can't answer
for it. The suite runs check every one with a `verifier.StatusPolicy`
(one `statuslist.Cache` for the process, as production requires), its
signer bound to the credential's issuer as the library binds it:

- `sd_jwt_vc`: the suite signs the Status List Token with the
  credential's own key and `x5c` (`VP1FinalGenerateJwtStatusListToken`
  in the suite's source). The drivers give the "Signing JWK" a
  certificate under a CA generated per run, and trust that CA for the
  credential (`credential_issuer_trust_anchors_pem`) and its status
  list (`status_list_trust_anchors_pem`); the list's signer must hold
  the key that signed the credential.
- `iso_mdl`: the suite signs the CWT status list and the identifier
  list with a certificate under the IACA root that issued the
  document signer. The drivers trust that root for both, and the
  signer must chain to the CA that signed the document signer
  (§12.3.6.2's rule, `mdoc.StatusTrust`).

The lists are fetched from the suite's address on the Docker network
(`status_list_allow_private`) over TLS pinned to the certificate the
suite serves its API with (`status_list_tls_pinned_certificate_pem`):
the suite's self-signed certificate names `localhost` in its subject and has no subject alternative name. The pin and
the private address are the transport, not the trust: each list is
still verified against the anchors above. A credential with no status
reference is accepted (`status_reference_optional`), as
`present-credential-without-status` requires.

The suite fails a revocation module whose Verifier never fetched the
list, so refusing the presentation for another reason doesn't pass
it; an accepted module whose list wasn't fetched logs a
`EnsureVerifierFetchedRevocationList` warning, which fails it here.
To check that the harness catches a Verifier that ignores status: set
`Status: nil, NoStatusCheck: true` in `server.verify` in `handlers.go`
and run both drivers. `present-revoked-credential` (and, for
`iso_mdl`, `present-credential-on-identifier-list`) then ends
`FINISHED=FAILED` with the result page reporting `verified`, every
other accepted module carrying a status reference fails on the
warning, and each run exits 1.

### Transactions engine

`run-sdjwt-modules -transactions` and `run-mdoc-module -transactions`
(the OID4VP workflow's "Verifier transactions" legs) run the same plan
with `engine: "transactions"`: `verifier.Transactions` serves the whole
flow, and this binary adds only what a Verifier's frontend adds
(`cmd/conformance-verifier/transactions.go`):

- `GET /authorize` begins a same-device request
  (`Transactions.BeginWith`, `SameDevice`), its browser binding a fresh
  random value set as a `Secure`, `HttpOnly` cookie, and redirects to
  `Begun.Link`.
- `GET|POST /request/{id}` is `Transactions.RequestObjectHandler`
  (`request_uri_method=post`, `TransactionsConfig.RequestURIMethodPost`;
  each fetch's method is logged), and
  `POST /response` (the `response_uri`) is
  `Transactions.ResponseHandler`: answer routing by `kid`, `state`,
  verification against the request's own nonce and key, atomic
  completion, a 400 for any refused answer, a replay included, and for
  a verified one 200 with the `redirect_uri` HAIP 1.0 §5.1 requires.
- `GET /result?response_code=...` is that `redirect_uri`
  (`TransactionsConfig.RedirectURI`): it redeems the code for the
  browser holding the binding (`Transactions.Redeem`) and shows the
  result.
- `GET /result/{id}` shows the bound browser its request
  (`Transactions.Lookup`): "Verification succeeded" once redeemed,
  "Verification failed" with `LastError` when its latest answer was
  refused, otherwise "Pending".

The drivers act as the browser: they keep `/authorize`'s cookie, visit
the `redirect_uri` the suite logs for the tester (rewritten from the
Verifier's address on the suite's network to `-verifier-base`), and
read `/result/{id}` with the same cookie. An accepted module whose
`response_code` wasn't redeemed by that browser reads "Pending" and
fails.

In the suite runs it runs under `verifier.AssuranceProduction`
(`Config.Production`, built with the `conformance_production` tag),
with:

- a durable, atomically updated store, sealed: `sqlstore`'s
  `TransactionStore` over a SQLite file, each transaction encoded by a
  `verifier.TransactionCodec` (version 2) whose `Sealer` is
  `sealing.AESGCMSealer` under a key generated per run;
- a CA-issued client certificate, an `https` `response_uri`,
  `crypto/rand`, A128GCM and A256GCM, issuer key resolvers that verify
  `x5c`/`x5chain` chains against the run's own anchors, and
  `IssuerAuthorized` allowing the trusted issuer the configured `vct`
  or doctype alone;
- the same status policy as the default engine (one `statuslist.Cache`,
  the suite's lists trusted by the credential's issuer anchors, a
  missing reference accepted).

What production requires that the suite can't satisfy, and what runs
instead:

- **The status policy runs as the `Accept`, not as
  `TransactionsConfig.Status`.** Under production, `NewTransactions`
  refuses a `Status` whose `Fetcher` isn't `HardenedForProduction`, and
  the suite serves its status lists from its own container on the
  private Docker network this binary shares with it, which needs
  `AllowPrivate`. So the same `StatusPolicy` is checked in
  `TransactionsConfig.Accept` with `NoStatusCheck` set (the
  alternative the library documents, as `verifier.RequireValidStatus`
  does, whose `Fetcher` is the caller's to harden): it checks what
  `Status` would,
  on the same answers, before the request completes, and a refusal is
  recorded the same way. Its TLS is pinned to the suite's certificate,
  as for the default engine (`pinnedTLSConfig`). Production's own
  check of the `Fetcher` is the one thing not exercised.
- **No certificate revocation** (`certrevocation.NoCheck{}`) for the
  issuers' and the status list signers' certificates, a decision
  production accepts: the suite's per-run CAs and its IACA publish no
  CRL.

Nothing falls back to development assurance.

The transactions engine sets `TransactionsConfig.RequestURIMethodPost`:
`Begin`'s links ask for `request_uri_method=post`, and
`Transactions.RequestObjectHandler` answers the suite's POST
(OpenID4VP 1.0 §5.10) with a Request Object re-signed for it, carrying
the `wallet_nonce` it posted (the suite's
`EnsureWalletNonceClaimMatchesPostedValue`), with the transaction's
own nonce, `state` and response key. So `request-uri-method-post`
runs, and ends `FINISHED=REVIEW` with the result page reporting it
verified, as under the default engine; `request-uri-fetched-twice`
checks a second fetch is served too. The suite posts no
`wallet_metadata`, so its narrowing of `client_metadata` is covered by
`verifier`'s own tests and the EUDI interop run (`interop/eudi`). The
engine serves no Digital Credentials API (the default engine's
`/dcapi/` routes are for interop runs; the suite runs drive no
`dc_api.jwt` Verifier list).

Under the transactions engine the expected verdicts were reached by
both legs: `sd_jwt_vc` all 14 modules at their verdict,
`request-uri-method-post` included, and `iso_mdl` all 7. To
check the legs catch a Transactions wiring that's wrong: make the
`Accept` in `setStatusCheck` (`transactions.go`) return nil, and
`run-sdjwt-modules -transactions` exits 1 with
`present-revoked-credential` `FINISHED=FAILED` and every accepted
module carrying a status reference failing on
`EnsureVerifierFetchedRevocationList`'s warning; or make
`handleRedirectBack` show success without `Transactions.Redeem`, and
`run-mdoc-module -transactions` exits 1 with every accepted module's
result page "Pending".

### Earlier findings

**`request-uri-method-post` and `request-uri-fetched-twice`: real
support added, not just made to pass.** These two used to be grouped
with the self-`SKIPPED`/informational set — `request-uri-method-post`
self-skipped because this binary only ever served `request_uri` over
GET. Since HAIP itself never mentions `request_uri_method` (confirmed
directly against the spec text — it's an OPTIONAL OID4VP/RFC 9101
mechanism, not something HAIP elevates), supporting POST was scoped as
a deliberate coverage improvement, not a compliance fix. Implemented
genuine two-sided enforcement per OID4VP §5.10/§5.10.1, not just
Content-Type/method handling: this binary now advertises
`request_uri_method=post`, accepts a POST carrying `wallet_nonce`, and
embeds it as the signed Request Object's own `wallet_nonce` claim —
confirmed live via the suite's own independent check
(`EnsureWalletNonceClaimMatchesPostedValue`: "wallet_nonce claim in
request object matches the value the wallet POSTed"). Building is
deferred from `/authorize` to the first `/request/{id}` fetch
specifically so the nonce (unknowable until the POST arrives) can be
embedded in the one-and-only signature `POST /response` later
correlates against — confirmed by `request-uri-fetched-twice`'s own
check that a second fetch of the same `request_uri` doesn't error or
change ("Fetching and processing the request_uri a second time to
confirm the verifier does not treat it as single-use").

**Two more real, pre-existing gaps found while re-verifying the above
(not caused by it — confirmed present in this session's own original
`happy-flow` log capture too) — both now fixed:**

- **The Request Object signing certificate was self-signed.**
  `conformance/verifier/scripts/generate-config` generated a
  self-signed `client_certificate_pem`, and the suite's own
  `ValidateRequestObjectSignatureAgainstX5cHeader` check rejects a
  self-signed leaf outright — the exact same finding
  `wallet-vp/README.md` and `issuer/README.md` already document for
  their own credential-issuer certs, just never applied to this
  binary's own client identity cert. This silently `FAILURE`'d on
  *every* module (including the previously-reported-clean
  `happy-flow`) without affecting the suite's own `status`/`result`
  fields, so it went unnoticed until this round of re-verification
  looked at `GET /api/log` line by line rather than trusting the
  summary counts. Fixed by generating the client cert under a fresh
  throwaway CA via `internal/conformancecert.GenerateSignerAndCert`,
  the same helper `wallet-vp`/`issuer` already use.
- **`client_metadata` never set `vp_formats_supported`.** OID4VP marks
  it "REQUIRED when not available to the Wallet via another mechanism"
  — this package has no other such mechanism, so it's always required
  here. `verifier.Config` gained a `VPFormatsSupported` field (this
  binary sets it to `dc+sd-jwt`/ES256, matching its own `buildQuery`);
  `verifier.BuildAuthorizationRequest` now includes it in every
  `client_metadata` it builds (both the redirect and DC API flows,
  since both share the same helper).

Re-verified live after both fixes: `happy-flow` and every other module
above now show zero `FAILURE`/`WARNING` log entries, not just the
already-reported `SUCCESS` counts.

This role's very first live run (an earlier session) found one more
real, confirmed interop bug — not in this binary, but in
`internal/jwe`'s Concat KDF (RFC 7518 §4.6.2): `concatKDF` always
treated the sender's `apu`/`apv` header members as absent when deriving
the CEK, but the suite's own `direct_post.jwt` responses always set
both. Getting apu/apv wrong doesn't corrupt the ciphertext, it silently
derives the wrong key — the first live attempt failed with an opaque
`response did not decrypt against any pending session` until this was
traced via `GET /api/log`'s captured JWE header down to the missing
apu/apv. Fixed in `internal/jwe` (Decrypt now reads and passes through
the sender's own apu/apv); Encrypt still never sets them itself, since
neither is required to originate them (RFC 7518 §4.6.1.2/§4.6.1.3 are
both OPTIONAL).

## Interaction model, confirmed live

The suite's own module summary text ("You must configure your verifier
to use the authorization endpoint url below instead of
'openid4vp://'...") describes its manual/UI-driven mode. For scripted
automation: hit this binary's own `/authorize` to mint a session and
get its `openid4vp://?client_id=...&request_uri=...` redirect, then GET
that same query string against the suite's own
`server_configuration.authorization_endpoint` (from the test's own
config, e.g. `.../test/a/{alias}/authorize`) — this drives the suite's
entire Wallet-side flow (fetch `request_uri`, build+encrypt a real
`vp_token`, POST to this binary's `response_uri`) synchronously within
that one HTTP call, no separate polling needed.

TLS: an ECDSA (P-256) listener certificate works fine — no RSA
requirement was hit for this plan (unlike FAPIgo's own CIBA plan
precedent).

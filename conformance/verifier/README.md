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
credentials of its own, only a DCQL query and a trusted issuer key
(`Config.CredentialIssuerJWK`) matching what the suite's own
"Credential Issuer" > "Signing JWK" test configuration will sign with.

## What not to copy

This binary is a conformance-suite harness. It drives `verifier`'s
lower-level API (`BuildAuthorizationRequest`,
`ParseDirectPostJWTResponse`, `VerifyResponse`) because those are what
the suite grades, and it skips everything a deployment needs around
them:

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
- **Development assurance, no status check, no revocation.** It runs
  under `verifier.AssuranceDevelopment`, sets `NoStatusCheck` (unless
  an interop run's `status_list_trust_anchors_pem` turns the Token
  Status List check on), and declines certificate revocation
  (`certrevocation.NoCheck{}`) for the suite's per-run issuers.

A Verifier uses `verifier.Transactions` with a durable
`verifier.TransactionStore` (encoded with `verifier.TransactionCodec`),
`TransactionsConfig.Status`, and issuer key resolvers with a
`Revocation`, under `verifier.AssuranceProduction`.
`examples/passport-vdc`'s verifier is wired that way.

## Endpoints

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

The interop runs' fields (`credential_issuer_trust_anchors_pem`, the
`status_list_*` fields, `dc_api_origins`) are documented in
`cmd/conformance-verifier/config.go`; the suite's configuration leaves
them unset. `interop/eudi/run-wallet.sh`, `interop/waltid/run.sh` and
the Multipaz interop's peer (`interop/multipaz/scripts/peer/vp.go`)
use them.

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
- the module's log (`GET /api/log/{id}`): no `FAILURE`, and no
  `WARNING` but `EnsureVerifierFetchedRevocationList` on an accepted
  module. `REVIEW` outranks `WARNING` in a result, so a warning would
  otherwise go unseen.

### Expected verdicts

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
| `present-revoked-credential` | not driven | not driven | refuse | — |
| `present-credential-on-identifier-list` | — | not driven | refuse | — |

`kb-jwt-iat-in-past` and `kb-jwt-iat-in-future` present a Key Binding
JWT issued a year ago or a year from now. The suite's
`VP1FinalVerifierKbJwtIatIn{Past,Future}` extend
`AbstractVP1FinalVerifierNegativeTest`, and their summaries say the
Verifier should reject the presentation: they are negative modules.
This binary refuses both (`MaxKeyBindingAge` is five minutes; the
library's clock-skew bound refuses a future `iat`). An earlier version
of this file listed them as positive modules that verify; the
Verifier's own log never said so.

The two revocation modules aren't driven: this binary checks no
credential status in the suite's runs (`NoStatusCheck`), so it can't
refuse a revoked credential. That is also why an accepted module may
log `EnsureVerifierFetchedRevocationList` (the suite's credentials
carry a status reference the Verifier never fetches): the suite makes
it a warning, as no specification makes the check mandatory. Driving
them needs a `status_list` trust anchor for the suite's per-run
issuer.

`wrong-vct` and `present-credential-without-status` are newer than
this repo's certification run, and pass.

To check that the harness catches a Verifier that accepts what it
must refuse: make `server.verify` in `handlers.go` return without
setting `failErr` for an error mentioning "signature", and run
`run-sdjwt-modules`. `invalid-kb-jwt-signature` and
`invalid-credential-signature` then end `FINISHED=REVIEW` with the
result page reporting `verified`, and the run exits 1.

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

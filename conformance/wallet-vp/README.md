# conformance-wallet-vp

`cmd/conformance-wallet-vp` stands up `wallet`'s own OID4VP
presentation half behind real HTTP for the OIDF conformance suite's
own `oid4vp-1final-wallet-haip-test-plan` ("OpenID for Verifiable
Presentations 1.0 Final/HAIP: Test a wallet") — specifically its
**direct_post.jwt + x509_hash + request_uri_signed** module list, under
either credential format the plan's own `credential_format` variant
offers (`sd_jwt_vc`, the original/default, or `iso_mdl` — see
"credential_format: iso_mdl" below); the plan's three `dc_api.jwt`
module lists (W3C Digital Credentials API) aren't covered — see "Scope"
below.

## How the interaction model was confirmed

This took real digging into the suite's own source
(`gitlab.com/openid/conformance-suite`) before writing any code — the
Wallet-role test plan turned out to have a much more conventional
shape than an early read suggested:

- `AbstractVP1FinalWalletTest.performAuthorizationFlow()`'s
  `DIRECT_POST_JWT` branch calls `performRedirect()`, which does
  `browser.goToUrl(env.getString("redirect_to_authorization_endpoint"))`
  — a real HTTP(S) navigation, not a custom `openid4vp://` scheme
  interception. The suite's own log message ("The wallet should be
  opened via the QR code / proceed with test button...") is generic UI
  text for the suite's manual/human-operator mode; it doesn't apply to
  automated headless testing.
- `redirect_to_authorization_endpoint` is built by
  `AbstractBuildRequestObjectRedirectToAuthorizationEndpoint.buildRedirect`,
  which reads `env.getString("server", "authorization_endpoint")` —
  i.e. the tester's own configured URL (this binary's own
  `/authorize`) — and appends `client_id`/`request_uri` as plain query
  parameters. This is exactly the `GET /authorize?client_id=...&request_uri=...`
  shape `handlers.go` implements.
- A `CreateRandomBrowserApiSubmitUrl`/`SubmitMockWalletBrowserApiResponse`
  pair initially looked like the real wallet-driving mechanism, but
  that condition's own doc comment says it's "Integration-test-only...
  simulating a real wallet's DC API response" — the suite's own
  self-test fixture, not something a real wallet AUT calls.

## Endpoints

- `GET /authorize` — this binary's own `server.authorization_endpoint`.
  Runs the whole flow synchronously: fetches+verifies the Request
  Object (`requestobject.go`: JWS signature against the `x5c` leaf,
  `x509_hash` client_id cross-check, `typ` header check), presents the
  fixture credential (`wallet.PresentCredentials`), encrypts and POSTs
  the `direct_post.jwt` response to the Verifier's own `response_uri`,
  and — since HAIP requires the response to carry a `redirect_uri` —
  follows it with a plain GET, the same round trip a real same-device
  in-app-browser wallet completes before rendering its own "done"
  page.

## Status

**Confirmed live, end to end, against a real `cmd/conformance-verifier`
instance** (this repo's own other binary from the same phase) — proves
the full cryptographic chain: `verifier.BuildAuthorizationRequest` →
this binary's own JWS/x5c verification → `wallet.PresentCredentials` →
JWE response encryption → `verifier.ParseDirectPostJWTResponse`/
`VerifyResponse`'s own cryptographic checks all passed. Permanent
regression test: `TestHandleAuthorize_FullRoundTripAgainstARealVerifier`
in `integration_test.go`.

**Confirmed live against the real OIDF conformance suite itself**
(locally-run, pre-built Docker images), `oid4vp-1final-wallet-haip-test-plan`'s
`happy-flow` module, `direct_post.jwt` + `x509_hash` +
`request_uri_signed`. The suite (playing Verifier) built and signed a
real Request Object, this binary fetched and verified it, presented the
fixture SD-JWT VC, and encrypted+POSTed a `direct_post.jwt` response —
`GET /api/log` confirms every cryptographic check on the suite's own
receiving side passed: issuer JWT signature, all SD-JWT disclosures,
DCQL match, Key Binding JWT signature/`typ`/`iat`/`aud`/`nonce`/`sd_hash`.

One real gap was found and fixed on this first live run: the suite's
own log reported `FAILURE | Credential MUST contain an x5c in the
header` — `credential/sdjwtvc.Issue` had no `x5c` support at all
(`IssueOptions` only had `HashAlg`/`Decoys`/`KeyID`). Fixed by adding
`IssueOptions.IssuerCertificate *x509.Certificate`: when set, its DER
encoding becomes the issuer JWT's own single-entry `x5c` header (RFC
7515 §4.1.6), and `Issue` rejects a certificate whose public key
doesn't match the signer's. A second, related finding followed
immediately: a *self-signed* leaf is also rejected (`FAILURE | Leaf
certificate in x5c chain must not be self-signed`) — HAIP's trust
model wants the leaf issued by a separate CA, with the CA as the trust
anchor, not a leaf that is its own trust anchor. Fixed by generating a
throwaway CA (`conformancecert.GenerateCA`/`IssueLeafCertPEM`) and
issuing the credential-issuer key's certificate under it, rather than
a bare self-signed cert.

**Re-confirmed live after the fix**: same `happy-flow` module, same
suite instance — `GET /api/log` shows zero x5c-related failures, and
every other cryptographic check (issuer JWT signature, disclosures,
DCQL match, Key Binding JWT) still passes. The module's own overall
`FAILED` status is unrelated (see the pending-screenshot note above);
the one remaining log `FAILURE` (`Found invalid entries in
verifier_info input`) is an artifact of this run's own plan config
passing `client.verifier_info: []` rather than omitting the field
entirely — the suite falls back to a valid default immediately after,
so this never blocked the flow.

This first live run also resolved the "Open questions" below:
`credential.trust_anchor_pem` is indeed a PEM X.509 certificate — a CA
certificate, specifically, per the self-signed-leaf finding above. The
suite's own DCQL query was driven via `client.dcql` (a `dc+sd-jwt` /
`vct_values: ["urn:eudi:pid:1"]` / `given_name`+`family_name` claims
query, matching this binary's own fixture credential) rather than a
built-in named query.

**Both checks are also enforced on the verifying side, not just
satisfied on this binary's own issuing side** — the suite catching
these gaps only proves *the suite* rejects a bad x5c; it says nothing
about whether *our own* Verifier would. `verifier.X5CIssuerKeyResolver`
(new, `verifier/x5c_issuer_key_resolver.go`) implements
`SDJWTVCIssuerKeyResolver` by actually validating a presented `x5c`
chain against a configured trust anchor set: it requires `x5c` to be
present, rejects a self-signed leaf outright (even one that happens to
also be a configured root), and verifies the remaining chain via
`x509.Certificate.Verify`. Seven unit tests
(`verifier/x5c_issuer_key_resolver_test.go`) prove both the accept and
every reject path, including "a self-signed leaf that IS itself a
trusted root is still rejected" — the case that would be easiest to
get wrong. `TestHandleAuthorize_FullRoundTripAgainstARealVerifier`
(`integration_test.go`) now uses this real resolver instead of a
fake that trusted any key unconditionally, so this binary's own
regression test proves its issued credential passes *genuine* x5c
chain validation, not just a stub.

## Scope

Only the `direct_post.jwt` + `x509_hash` + `request_uri_signed` module
list is targeted. The plan's other three module lists all use
`dc_api.jwt` (the suite's own DC API / W3C Digital Credentials API
simulation, via `browser.requestCredential` — a genuinely different,
browser-JS-level interaction, not a plain HTTP GET) — deliberately out
of scope for this binary; `wallet`'s own DC API support
(`PresentMdocSelective`'s own Origin-bound path, per ARCHITECTURE.md)
exists but testing it against the live suite needs its own separate
harness design, not attempted here. Confirmed against the HAIP 1.0
spec text directly: HAIP §5.2's DC API requirements are conditional
("The following requirements apply to OpenID for Verifiable
Presentations via the W3C Digital Credentials API") — a separate,
optional deployment variant alongside the redirect-based flow §5.1
profiles (and that this binary implements), not a universal mandate.
HAIP §5.1 also never permits a JSON-serialized (non-JWT) Authorization
Request — "Signed Authorization Requests MUST be used by utilizing
JWT-Secured Authorization Request (JAR) [RFC9101]" — so the suite's
"JAR JSON Serialization" module list is testing a DC API-only
serialization variant this binary's redirect-based flow never uses
either way.

## Status: full module run against the real OIDF suite

**Update**: the fixture credential now sets an `exp` claim (`credential.go`'s
own `fixtureCredentialLifetime`, a year out — HAIP/SD-JWT VC §11.2.3's
own RECOMMENDED-not-required validity limit), fixing the one WARNING
every module below used to carry. Re-run live: `happy-flow` is now a
clean `FINISHED`/`PASSED` with zero log entries at `WARNING` or worse,
not just zero `FAILURE`s — every "same soft `exp`-claim note" mention
below predates this fix.

All 14 modules reachable by this binary's own scope (`direct_post.jwt`
+ `x509_hash` + `request_uri_signed`) have now been run live. The
plan's other 2 modules (`negative-test-wrong-expected-origins`,
`multisigned-one-invalid-signature`) 404 when requested against this
variant — consistent with the "Scope" section below (DC API/JAR-JSON-
Serialization-only checks, not something this binary's redirect-flow
implementation is ever asked to handle).

**Update: all 14 of these are now driven by a committed, repeatable
tool**, `conformance/wallet-vp/scripts/run-modules`, closing this
role's own "driven by hand" gap (the same gap
`conformance/verifier/scripts/run-sdjwt-modules`/`run-mdoc-module`
closed for the Verifier role). Confirmed live, twice for stability: all
7 positive-behavior modules `FINISHED`/`PASSED` (`alternate-happy-flow`
included — see below); all 7 negative-test modules correctly rejected
at this binary's own `/authorize` call (a non-200 local response,
before ever reaching `response_uri`) and `FINISHED`/`REVIEW` once the
script fills the suite's own required screenshot placeholder —
matching this section's own "the real pass/fail signal... is whether
this binary's own `/authorize` call errored out" finding below
exactly, now automated rather than eyeballed per run.

**`alternate-happy-flow`'s fragment relay is now automated too.** Its
own fragment-carrying `redirect_uri` needs relaying real fragment
content to the suite's own implicit-submission URL — two earlier
guesses at the POST body shape (`code_verifier=<fragment>` as form
data, and the bare fragment value with no leading `#`) both left the
suite reporting "URL fragment passed to redirect_uri contains more
than the one expected entry." The exact wire shape was pinned down by
decompiling the suite's own `fapi-test-suite.jar` rather than guessed
again: `implicitCallback.html`'s own JS does
`xhr.send(window.location.hash)` with `Content-type: text/plain` — and
critically, `window.location.hash` includes the leading `#` — while
`CheckUrlFragmentContainsCodeVerifier.java` compares the submitted
value literally against `"#" + code_verifier`. `run-modules`'
`driveOne` now extracts the fragment (leading `#` included) straight
out of `cmd/conformance-wallet-vp`'s own "Followed redirect_uri: ..."
response text, polls the module's log for the same
`ImplicitSubmit.FullURL` field `unblock.go` already uses for a
different stuck-point, and POSTs the fragment there as raw
`text/plain` — completing the same round trip a real browser's JS
performs, with no browser needed.

**Driving negative-test and fragment-redirect modules needs one extra
step curl alone can't do.** Two distinct suite mechanisms show up
across this module list, beyond the plain query-string callback
`happy-flow` uses:

- A **fragment-carrying `redirect_uri`** (`alternate-happy-flow`):
  HAIP's own fragment-based response variant puts data after `#`,
  which — by design — never reaches an HTTP server, real browser or
  not; a real browser's own JS reads `window.location.hash` and POSTs
  it to a suite-provided "implicit submission" URL. This binary's own
  `handleAuthorize` correctly follows the redirect (its own response
  text names the exact fragment it tried to send), and the suite's own
  log/api separately records the submission URL it's waiting on
  (`CreateRandomImplicitSubmitUrl`) — relaying the fragment from that
  response text to that submission URL (raw `text/plain`, leading `#`
  included — see the update above for the exact wire shape) completes
  the module without needing an actual browser. `run-modules` now does
  this automatically.
- **Every negative-test module** is `REVIEW`-gated: the suite's own
  condition text is explicit ("the wallet should display an error, a
  screenshot of which must be uploaded for the test to transition to
  'FINISHED'"). This binary has no UI to screenshot — the real
  pass/fail signal for a negative test is whether this binary's own
  `/authorize` call errored out *before* it ever POSTed to
  `response_uri` (confirmed directly from its own HTTP response body/
  status, and cross-checked against the suite's own log never showing
  a `responseuri` POST) — not the suite's own overall module verdict.

**Positive-behavior modules — all clean.** `alternate-happy-flow`,
`ignores-unusable-encryption-key`, `fewer-claims-than-available`,
`optional-credential-set`, `no-claims-in-dcql-query`: every one
`FINISHED`/`WARNING` with zero `FAILURE`s (the same soft `exp`-claim
`RECOMMENDED` note as `happy-flow`).

**Update: `request-uri-method-post` — real support added, not just
made to pass.** Previously self-`SKIPPED` ("the specification permits
this as a fallback when the wallet does not support POST" — this
binary always fetched via GET). Since HAIP itself never mentions
`request_uri_method` (confirmed directly against the spec text — it's
an OPTIONAL OID4VP/RFC 9101 mechanism, not something HAIP elevates),
supporting POST was scoped as a deliberate coverage improvement, not a
compliance fix. `fetchAndVerifyRequestObject` now sends a fresh,
cryptographically random `wallet_nonce` (plus an accurate
`wallet_metadata` declaring this binary's real `dc+sd-jwt`/ES256
support) over POST when the Verifier's own authorization request
carries `request_uri_method=post`, and — the genuine enforcement half,
not just Content-Type/method handling — rejects the fetched Request
Object outright if its own `wallet_nonce` claim doesn't echo back
exactly what was sent (OID4VP §5.10.1: "the Wallet MUST validate
whether the request object contains the respective nonce value... If
it does not, the Wallet MUST terminate request processing"). Confirmed
live: `FINISHED`/`PASSED`, zero log entries at `WARNING` or worse, with
the suite's own independent checks confirming both directions —
`EnsureIncomingRequestMethodIsPost` ("Client correctly used http POST
method") and `AddReceivedWalletNonceToRequestObjectClaims` (the suite
itself echoing the nonce back, which this binary's own validation then
had to accept for the module to pass at all).

**Negative-test modules found two real gaps, now fixed.** Five of
seven correctly rejected from the start (confirmed via this binary's
own error response, not needing the suite's screenshot review):
`invalid-request-object-signature`, `mismatched-client-id`,
`missing-nonce`, `invalid-client-id-prefix`,
`required-non-matching-credential`. Two did not:
`redirect-uri-with-direct-post` and `unknown-transaction-data-type`
both had this binary silently ignore the offending field and *POST to
`response_uri` anyway* — the suite's own log calls this out directly
("Direct post endpoint was called but the wallet should have rejected
the request..."). Root cause: `wireRequestObjectPayload`
(`requestobject.go`) never parsed `redirect_uri` or `transaction_data`
at all, so their presence was invisible to this binary's own
validation. Fixed: both fields are now parsed and, if present, rejected
outright — `redirect_uri` because this binary only ever builds a
`response_uri`-targeted response (the two are mutually exclusive per
RFC 9101 §5/PAR-2.1's own logic, applied here to the Wallet's own
incoming-request validation instead), `transaction_data` because this
binary recognizes no transaction_data type at all, so RFC 9101 semantics
require refusing rather than silently proceeding as if it weren't
there. `TestFetchAndVerifyRequestObject_RejectsRedirectURI`/
`RejectsTransactionData`/`AcceptsWellFormedRequest`
(`requestobject_test.go`) are new permanent regression tests. Re-run
live after the fix: both modules now correctly stop before calling
`response_uri` (the suite's own log shows "Show redirect URI error
page" / "REVIEW" instead of the direct-post-endpoint-was-called
failure).

## credential_format: iso_mdl

Closes the OID4VP Wallet role's own "iso_mdl direct_post.jwt"
certification profile (this repo's own remaining gap alongside
`dc_api.jwt`'s two profiles — see "Scope" above). Confirmed live via
`GET /api/plan/{id}` before writing any driving code that the plan's
own module list under `credential_format=iso_mdl` is exactly the same
14 modules `sd_jwt_vc` already reaches — no additional exclusions —
learned the hard way from a real mistake made on the Verifier role's
own equivalent gap (`conformance/verifier/README.md`), where one
module (`minimal-cnf-jwk`) turned out to be `sd_jwt_vc`-only despite
looking format-agnostic from its own `@PublishTestModule` alone; a live
`POST /api/plan` + module-instance-creation probe is the only source
this repo now trusts for "does module X apply under format Y", not a
Java-source read alone.

`cmd/conformance-wallet-vp`'s own `Config.CredentialFormat` (`""`/
`"dc+sd-jwt"` or `mdoc.CredentialFormat`/`"mso_mdoc"`) selects between
`issueFixtureCredential` (unchanged) and the new
`issueFixtureMdocCredential` (`credential.go`) — a real, freshly issued
mdl (`org.iso.18013.5.1.mDL`) signed by a Document Signer under a fresh
IACA (`internal/conformancecert.GenerateMdocIACA`/
`GenerateMdocDocumentSigner` — the same ISO/IEC 18013-5 certificate
hierarchy `conformance/issuer/scripts/run-fapi2sp-battery` already uses
for its own mdoc fixtures), never a self-signed leaf — the same
non-self-signed-leaf lesson this file's own SD-JWT VC x5c findings
above already established, confirmed to matter here too via the
suite's own `AbstractVP1FinalWalletTest.java` doc comment: "the
credential trust anchor also serves as the mdoc IACA trust anchor when
no VICAL is configured" — the exact same `credential.trust_anchor_pem`
plan-config field this binary's SD-JWT VC fixture already relies on,
just pointed at the IACA certificate instead of the SD-JWT-VC-issuer CA
for this format.

`handleAuthorize`'s own `wallet.PresentCredentials` call now always
computes and passes `ResponseURI`/`ResponseEncryptionJWKThumbprint`
(`responseEncryptionJWKThumbprint`, `handlers.go`) — both parameters
`wallet.PresentationRequest` documents as "REQUIRED whenever Query
requests any mso_mdoc Credential", and both harmless to pass
unconditionally for a `dc+sd-jwt`-only session (`presentSDJWTVCSelectively`
never reads them) — so this one code path now serves both credential
formats without a format-conditional branch of its own.

**Confirmed live, twice for stability, via `conformance/wallet-vp/scripts/run-modules -credential-format iso_mdl`**:
the exact same 14/14 result shape `sd_jwt_vc` already has — all 7
positive-behavior modules `localOK=true FINISHED=PASSED`, all 7
negative-test modules correctly rejected locally before ever calling
`response_uri` (`localOK=false`, suite-side `FINISHED=REVIEW`) — proving
the full mdoc cryptographic chain end to end: `mdoc.Issue` →
`PresentMdocSelective`'s own `SessionTranscriptBytes`/`DeviceSigned`
construction → the suite's own independent mdoc verification, including
its own IACA-chain validation of this binary's freshly generated
Document Signer certificate.

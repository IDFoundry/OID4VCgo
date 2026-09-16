# conformance-wallet-vp

`cmd/conformance-wallet-vp` stands up `wallet`'s own OID4VP
presentation half behind real HTTP for the OIDF conformance suite's
own `oid4vp-1final-wallet-haip-test-plan` ("OpenID for Verifiable
Presentations 1.0 Final/HAIP: Test a wallet") — specifically its
**direct_post.jwt + x509_hash + request_uri_signed** module list only;
the plan's three `dc_api.jwt` module lists (W3C Digital Credentials
API) aren't covered — see "Scope" below.

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
harness design, not attempted here.

## Remaining work

- Run the plan's other 8 `direct_post.jwt` modules (`alternate-happy-flow`,
  `request-uri-method-post`, `ignores-unusable-encryption-key`,
  `fewer-claims-than-available`, `optional-credential-set`,
  `no-claims-in-dcql-query`, and the two `negative-test-*` modules) —
  only `happy-flow` has been run live so far.

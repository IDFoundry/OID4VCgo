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
instance** (not the OIDF suite itself, but this repo's own other
binary from the same phase) — this is stronger evidence than a
suite-only smoke test, since it proves the full cryptographic chain:
`verifier.BuildAuthorizationRequest` → this binary's own JWS/x5c
verification → `wallet.PresentCredentials` → JWE response encryption →
`verifier.ParseDirectPostJWTResponse`/`VerifyResponse`'s own
cryptographic checks (SD-JWT signature, Key Binding JWT, nonce/audience)
all passed, and the disclosed claims came back correctly. This exact
scenario is now a permanent regression test
(`TestHandleAuthorize_FullRoundTripAgainstARealVerifier` in
`integration_test.go`), not just a one-off manual run.

**Not yet run against the live OIDF suite itself.** The suite's own
dozens of wallet-side condition classes (`ValidateSdJwtKeyBindingSignature`,
`ValidateDisclosedClaimsMatchDcqlQuery`, `EnsureRequestUriHasNoFragment`,
...) check details this pass didn't verify one by one against the
suite's own actual expectations — expect the first live run to surface
real gaps, the same way `conformance-verifier`'s own README already
flags for its own first run.

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

## Open questions for the live run

- What to paste into the OIDF suite's own credential-trust
  test-configuration field (`credential.trust_anchor_pem`, per the
  suite's own `AbstractVP1FinalWalletTest`'s
  `@VariantConfigurationFields` for the `haip` profile) — that field
  name suggests a PEM X.509 trust anchor validated via the credential's
  own `x5c` chain, but `credential/sdjwtvc.Issue` has no x5c support at
  all (`IssueOptions` only has `HashAlg`/`Decoys`/`KeyID`). If the live
  suite's SD-JWT VC trust check genuinely requires `x5c`, that's a real
  `credential/sdjwtvc` gap to fix as its own separate PR — not
  something to bolt onto this conformance binary. `generate-config`'s
  output is a starting point (a plain EC key, no cert), not a confirmed
  answer.
- The exact DCQL query the suite's own test configuration will send —
  `Config.VCT`/`Config.Claims` must match either one of the suite's
  built-in queries (e.g. `eudi_pid`) or a `client.dcql` custom query;
  unconfirmed which the test plan defaults to.

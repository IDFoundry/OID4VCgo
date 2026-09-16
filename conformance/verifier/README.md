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

## Endpoints

- `GET /authorize` — creates a session (the DCQL query to ask for) and
  redirects to
  `openid4vp://?client_id=...&request_uri=...&request_uri_method=post`
  — what the suite's own browser (playing Wallet) navigates to.
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
  `{"redirect_uri": ".../result/{id}"}` — HAIP's own requirement on top
  of plain OID4VP §8.3.
- `GET /result/{id}` — a plain HTML page reporting that session's
  outcome, for the suite's own "verifier_verification_result_screenshot"
  evidence capture.

## Status

**Confirmed live against a real, locally-run OIDF conformance suite**
(pre-built Docker images, `docker-compose-prebuilt.yml`, `dev` Spring
profile), covering all 12 `direct_post.jwt` + `x509_hash` +
`request_uri_signed` modules of `oid4vp-1final-verifier-haip-test-plan`
(the plan's thirteenth module, `-invalid-session-transcript`, is
`iso_mdl`-only and out of scope for the `sd_jwt_vc` variant run here):

- **7 positive-behavior modules** (`happy-flow`, `minimal-cnf-jwk`,
  `request-uri-fetched-twice`, `request-uri-method-post`,
  `kb-jwt-iat-in-past`, `kb-jwt-iat-in-future`) all end with this
  binary's own `/result` page reporting `Verification succeeded` and
  the correct disclosed claims, and `GET /api/log` shows zero entries
  at `WARNING` or worse. The suite's own `GET /api/info` reports
  `result: None`/`FAILED` while `status: WAITING` for these — that's
  expected, not a bug: each module's own summary text requires a
  manually-uploaded screenshot before it can reach `REVIEW`, which this
  scripted run never does.
- **5 negative-test modules** (`invalid-kb-jwt-signature`,
  `invalid-credential-signature`, `invalid-sd-hash`,
  `invalid-kb-jwt-nonce`, `invalid-kb-jwt-aud`) all correctly end with
  `Verification failed` and the exact expected error (e.g. `jose: ES256
  signature verification failed` for the KB-JWT signature case,
  `key binding JWT sd_hash does not match` for the sd_hash case) —
  `VerifyResponse`'s own checks reject each malformed presentation
  precisely as designed.

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

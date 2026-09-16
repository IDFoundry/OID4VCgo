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

- `GET /authorize` — builds a fresh signed Authorization Request
  (`verifier.BuildAuthorizationRequest`), stores the session, and
  redirects to `openid4vp://?client_id=...&request_uri=...` — what the
  suite's own browser (playing Wallet) navigates to.
- `GET /request/{id}` — serves that session's signed Request Object
  JWS (`application/oauth-authz-req+jwt`).
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

Code compiles, is unit-tested (`config_test.go`, `issuerkeys_test.go`,
`session_test.go`), and was smoke-tested locally end to end: started
the binary against a `generate-config`-produced config, hit
`/authorize`, followed the redirect's own `request_uri` with a plain
HTTP client, and confirmed a well-formed signed JWS (`alg: ES256`,
`typ: oauth-authz-req+jwt`, `x5c` present) comes back.

**Not yet run against the live OIDF suite.** The suite's own dozens of
negative-test condition classes (`CheckNoScopeParameter`,
`EnsureRequestUriHasNoFragment`, `VP1FinalCheckEncryptionKeyNotReused`,
...) check details this first pass didn't individually verify one by
one — expect the first live run to surface real gaps, the same way
every FAPIgo conformance leg's own README documents genuine bugs found
and fixed on first live attempt. Update this file with what the suite
actually reports once Docker is available to run it locally (see
`../../docker-compose.yml`'s own usage comment) — pass/fail counts per
module, and a reproduction/fix note for anything it catches.

## Open questions for the live run

- Whether the TLS listener needs an RSA (not ECDSA) server certificate
  — FAPIgo's own `generate-server-cert.sh` needed RSA specifically for
  a legacy FAPI-RW cipher check inside a CIBA test plan; unconfirmed
  whether the OID4VP/HAIP plans carry an equivalent constraint.
  `generate-config` currently produces an ECDSA (P-256) listener cert;
  switch it if the suite's TLS handshake fails.
- The exact `oidf-config` JSON schema the suite's own UI expects when
  creating this test plan hasn't been confirmed against a live suite
  instance — `generate-config`'s output is this binary's own config,
  not necessarily what the suite's create-test-plan form itself wants
  pasted in.

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

**Confirmed live against a real, locally-run OIDF conformance suite**
(pre-built Docker images, `docker-compose-prebuilt.yml`, `dev` Spring
profile), covering all 11 `direct_post.jwt` + `x509_hash` +
`request_uri_signed` modules of `oid4vp-1final-verifier-haip-test-plan`
(the plan's twelfth module, `-invalid-session-transcript`, is
`iso_mdl`-only and out of scope for the `sd_jwt_vc` variant run here):

- **5 positive-behavior modules** (`happy-flow`, `minimal-cnf-jwk`,
  `request-uri-fetched-twice`, `kb-jwt-iat-in-past`,
  `kb-jwt-iat-in-future`) all end with this binary's own `/result` page
  reporting `Verification succeeded` and the correct disclosed claims.
  The suite's own `GET /api/info` reports `result: FAILED` for these —
  that's expected, not a bug: the module's own summary text requires a
  manually-uploaded screenshot before it can reach `REVIEW`, which this
  scripted run never did; `GET /api/log` confirms every automated check
  along the way (DCQL validity, encryption, `redirect_uri` handling)
  reported `SUCCESS`.
- **5 negative-test modules** (`invalid-kb-jwt-signature`,
  `invalid-credential-signature`, `invalid-sd-hash`,
  `invalid-kb-jwt-nonce`, `invalid-kb-jwt-aud`) all correctly end with
  `Verification failed` and the exact expected error (e.g. `jose: ES256
  signature verification failed` for the KB-JWT signature case,
  `key binding JWT sd_hash does not match` for the sd_hash case) —
  `VerifyResponse`'s own checks reject each malformed presentation
  precisely as designed.
- **`request-uri-method-post`** is correctly `SKIPPED` by the suite
  itself ("the verifier's authorization request does not include
  request_uri_method=post") — this binary always fetches `request_uri`
  via plain GET, so the module self-excludes; not a gap. Confirmed
  against the HAIP 1.0 spec text directly (not just assumed): HAIP
  never mentions `request_uri_method` anywhere in §4 or §5 — it stays
  an OPTIONAL mechanism under the base OID4VP/JAR (RFC 9101) specs,
  never elevated to a requirement, so GET-only `request_uri` fetching
  is fully HAIP-compliant.

This first live run found one real, confirmed interop bug — not in
this binary, but in `internal/jwe`'s Concat KDF (RFC 7518 §4.6.2):
`concatKDF` always treated the sender's `apu`/`apv` header members as
absent when deriving the CEK, but the suite's own `direct_post.jwt`
responses always set both. Getting apu/apv wrong doesn't corrupt the
ciphertext, it silently derives the wrong key — the first live attempt
failed with an opaque `response did not decrypt against any pending
session` until this was traced via `GET /api/log`'s captured JWE header
down to the missing apu/apv. Fixed in `internal/jwe` (Decrypt now reads
and passes through the sender's own apu/apv); Encrypt still never sets
them itself, since neither is required to originate them (RFC 7518
§4.6.1.2/§4.6.1.3 are both OPTIONAL).

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

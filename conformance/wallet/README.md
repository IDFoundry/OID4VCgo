# conformance-wallet

`cmd/conformance-wallet` drives `oid4vcgo/wallet` and `fapigo/client`
headlessly through the OIDF conformance suite's own
`oid4vci-1_0-wallet-haip-test-plan` ("OpenID for Verifiable Credential
Issuance 1.0 Final/HAIP: Test a wallet") — both the `wallet_initiated`
and `issuer_initiated` flow variants (`-issuer-initiated`) of the same
4 non-battery modules, crossed with all 3 of the plan's own
issuance-mode/encryption variants (`immediate`+`plain`,
`deferred`+`plain`, `immediate`+`encrypted`), plus the plan's 4th
module-list entry: the generic FAPI2SP client conformance battery,
always at the fixed `immediate`+`plain` crossing — each drivable with
any of three Credential Request proof strategies via `-proof-type`
(`jwt`, `attestation`, or `jwt-key-attestation`; see "Status"). See
"Scope" below for what isn't covered yet.

## Why this binary is a one-shot CLI tool, not a server

Unlike this repo's other three conformance binaries, this one makes
outbound calls rather than receiving them. For the OID4VCI Wallet
role, the suite itself plays the entire emulated Authorization Server
*and* Credential Issuer — confirmed by reading
`AbstractVCIWalletTest.java` directly (`gitlab.com/openid/conformance-suite`,
`src/main/java/net/openid/conformance/vci10wallet/`): it serves
`par`/`authorize`/`token`/`nonce`/`challenge`/`credential`/
`deferred_credential`/`notification` and both `.well-known` documents
itself, and `authorizationEndpoint()` auto-issues a code and redirects
immediately (no consent screen at all — an exhaustive search of the
whole package found zero REVIEW/screenshot gates either). So this
binary is the HTTP *client*, the same shape as FAPIgo's own
`cmd/conformance-client` — every endpoint path is fixed and hardcoded
against the module's own base URL, and `followAuthorizationRedirect`
(`flow.go`) plays the "browser" itself, mirroring
`cmd/conformance-client`'s identical mechanism for the same
no-consent shape.

## How the config/plan quirks were found

None of these were guessed — each came from an actual `INTERRUPTED`
module and its own `/api/log/{id}` entry, driving this binary against
the already-running local suite instance one fix at a time:

- `POST /api/runner` needs the exact resolved `variant` map repeated
  as its own query parameter, not just `plan`+`test` — the HAIP plan
  enumerates the same 4 module classes across 3 issuance-mode/
  encryption crossings, and the suite can't otherwise tell which
  crossing a bare `test=<name>` means. `createPlan`'s own response
  already includes each entry's resolved `variant` map
  (`planModule.Variant`); `main.go` passes it straight through to
  `createModuleInstance`.
- `server.jwks` (the suite's own emulated AS signing key set) is
  required config regardless of `client_auth_type` — `LoadServerJWKs`
  fails "Couldn't find a JWK set in configuration" without it.
- Every JWK submitted needs an explicit `"alg"` field —
  `ExtractServerSigningAlg` fails "No algorithm specified for key"
  otherwise.
- `client_attestation.key_attestation_trust_anchor_pem` is required
  config even though this binary never sends a Key Attestation proof
  itself (Appendix D — a distinct HAIP §4.5.1 requirement from Wallet
  Attestation client auth; see `AGENTS.md`'s own note not to conflate
  the two). `config.go` reuses the attester CA cert here; nothing
  exercises this trust anchor unless an attestation-type proof is
  actually presented.
- `credential.signing_jwk`'s own certificate must not be self-signed
  (HAIP §6.1.1 — `VCIEnsureCredentialSigningCertificateIsNotSelfSigned`)
  — the same requirement `cmd/conformance-wallet-vp` already found for
  its own credential-issuer cert. A throwaway CA-issued leaf
  (`conformancecert.GenerateSignerAndCert`) satisfies it.
- `vci.credential_configuration_id` must name one of the suite's own
  fixed fixture credential configurations — confirmed directly from a
  created module's own "Created credential issuer metadata" log entry,
  which lists `eu.europa.ec.eudi.pid.1` (plain jwt-proof-type, `scope`
  `eudi.pid.1`), `eu.europa.ec.eudi.pid.1.attestation` (attestation
  proof type), `eu.europa.ec.eudi.pid.1.jwt.keyattest` (jwt + key
  attestation required), and more — not an arbitrary tester-chosen
  name. `main.go`'s own flags default to the first of these.
- The Credential Issuer Identifier (the jwt-type proof's own `aud`
  claim, and separately the Authorization Server's own issuer
  identifier a Client Attestation PoP JWT's `aud` must match) is
  published **with a trailing slash** — `flow.go` appends one to
  `module.URL` in both places; without it,
  `ValidateClientAttestationProofJwtAudience` rejects every PoP with
  "aud claim... did not match the authorization server issuer". The
  same trailing slash also matters for the Credential Issuer Metadata
  request path itself (see the `immediate`+`encrypted` finding below).
- `POST /api/plan` requires a `credential_format` variant selector too
  (`sd_jwt_vc` here) even though the HAIP plan's own module-list
  entries never set it — `createTestModule failed: Missing value for
  required variant parameter: credential_format` otherwise.
- **`deferred`+`plain`**: `RequestCredential`'s own `TransactionID`
  (§8.3's "deferred at first response" case) needs polling
  `RequestDeferredCredential` until it actually returns credentials —
  `wallet` already had this primitive; `flow.go`'s own
  `pollDeferredCredential` is the only new logic needed.
- **`immediate`+`encrypted`** surfaced two real, distinct bugs:
  - **RFC 8414 §3.1's own well-known-path-insertion rule applies to
    Credential Issuer Metadata discovery too**, and specifically to
    the URL this binary itself must build to fetch it:
    `/.well-known/openid-credential-issuer` goes *before* the issuer's
    own path component (`https://host/.well-known/openid-credential-issuer/test/a/<alias>/`),
    not appended after it — confirmed live twice, first via a plain
    404-shaped "does not match expected URL path" failure, and then
    again once discovering the path itself also needs the same
    trailing slash `CredentialIssuer`'s own `aud` claim does.
  - **A genuine bug in `wallet` itself**, not this binary:
    `RequestCredential`/`RequestDeferredCredential`'s own ephemeral
    `credential_response_encryption.jwk` never declared an `"alg"`
    member — `wallet.ResponseEncryption`'s doc comment never promised
    one either, but §8.2 requires the Issuer be told which JWE key
    management algorithm to encrypt the response back with, and the
    suite's own `invalid_encryption_parameters` check enforces it
    ("credential_response_encryption must identify the encryption
    algorithm via 'jwk.alg'"). Fixed in `wallet/encryption.go`'s
    `prepareResponseEncryption` — this package only ever performs
    ECDH-ES Direct Key Agreement (`internal/jwe`'s sole supported
    `Alg`), so `"ECDH-ES"` is always the right, unambiguous value, not
    something `ResponseEncryption` needs its own field for. New
    regression test: `TestResponseEncryptionJWKDeclaresAlg`
    (`wallet/encryption_test.go`) — the existing round-trip test never
    caught this because its own fake issuer never checked for `alg` at
    all, exactly the gap a real conformance suite closes.
- **The HAIP plan's 4th module-list entry (the generic FAPI2SP client
  battery)** surfaced two more real findings, both in this binary
  itself, not in `wallet`/`fapigo`:
  - **FAPIgo's own `client.Discover` cannot be used against this
    suite at all.** It only ever speaks OIDC Discovery's own
    convention (`<issuer-path>/.well-known/openid-configuration`,
    suffix appended *after* the path — confirmed directly in
    `client/discover.go`'s own `wellKnownURL`), and
    `AbstractVCIWalletTest.java` (lines 802-807) explicitly
    **test-fails** a wallet using either that suffix or that
    path-insertion direction instead of RFC 8414 §3.1's own
    insert-*before*-the-path rule with the `oauth-authorization-server`
    suffix — the same convention this binary already adopted for
    Credential Issuer Metadata. `flow.go`'s new
    `fetchAuthorizationServerMetadata` self-rolls the fetch+
    issuer-match check instead (reusing the existing
    `wellKnownMetadataURL` helper), which is also exactly the check
    `fapi2-security-profile-final-client-test-discovery-issuer-mismatch`
    needs: the suite corrupts its own metadata's `"issuer"` field and
    expects the client to notice and stop before ever reaching PAR.
    Confirmed behavior-preserving for every already-passing module: the
    fetched `authorization_endpoint`/`token_endpoint`/
    `pushed_authorization_request_endpoint` values are byte-identical
    to what was previously hardcoded.
  - **The generic FAPI2SP client battery never wires up the
    Attestation Challenge Endpoint at all** — confirmed directly in
    `AbstractFAPI2SPFinalClientTest.java`'s own source, which carries
    no "challenge" handling whatsoever (only unrelated PKCE
    `code_challenge` conditions). A client that still calls `/challenge`
    there hits the suite's own catch-all dispatcher: `Got unexpected
    HTTP call to challenge`, failing the module outright — confirmed
    live. Since draft-ietf-oauth-attestation-based-client-auth-07 §5.2's
    own `"challenge"` claim in the PoP JWT is optional (only present
    when a fresh challenge actually exists), `buildClient` now only
    opts into `client.ChallengeSource` for the 4 VCIWallet* modules
    (which all *do* implement `/challenge`, unlike this battery); the
    10 battery modules get a plain, unchallenged
    `staticAttestationSource`.

## Status

**Confirmed live, repeatedly (4 independent full runs), against a
real local OIDF conformance suite instance** (Docker,
`docker-compose-prebuilt.yml`). All 4 in-scope modules × all 3
issuance-mode/encryption crossings — 12 module instances —
`FINISHED`/`PASSED`:

- `oid4vci-1_0-wallet-test-credential-issuance`
- `oid4vci-1_0-wallet-test-credential-issuance-notification`
- `oid4vci-1_0-wallet-test-client-attestation-challenge` — the module
  that specifically exercises the Attestation Challenge Endpoint
  (draft-ietf-oauth-attestation-based-client-auth-07 §8), proving
  FAPIgo PR #318's `client.ChallengeSource` end to end against the
  suite's own `POST /challenge` → embed-in-PoP sequence, not just
  FAPIgo's own unit tests.
- `oid4vci-1_0-wallet-test-batch-credential-issuance`

...each crossed with `immediate`+`plain`, `deferred`+`plain`, and
`immediate`+`encrypted` (`vci_credential_issuance_mode`/
`vci_credential_encryption`).

This is the live-suite counterpart to
`cmd/conformance-issuer`'s own `TestFullFlow_RealClientDrivesAttestationAuth`:
that test proved a real `fapigo/client` wallet interoperates with a
real `fapigo/server` Authorization Server; this binary proves the same
wallet-side stack against the actual OIDF suite's own independent
implementation of the AS/Issuer side and its own Attestation
Challenge Endpoint.

**Confirmed live, repeatedly (2 independent full runs after the fix
below, both zero-failure), the HAIP plan's 4th module-list entry — the
generic FAPI2SP client conformance battery — all 10 modules
`FINISHED`/`PASSED`, all at the fixed `immediate`+`plain` crossing**:

- `fapi2-security-profile-final-client-test-happy-path`
- `fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce`
- `fapi2-security-profile-final-client-test-discovery-issuer-mismatch` —
  proves real RFC 8414 discovery + issuer-match validation: the suite
  corrupts its own metadata's `issuer` field and this binary correctly
  stops before ever reaching PAR.
- `fapi2-security-profile-final-client-test-remove-authorization-response-iss`
  / `...invalid-authorization-response-iss` — both correctly stop
  before token exchange on a missing/invalid `iss`, exercising
  `Config.RequireAuthorizationResponseIss`.
- `fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails`
  / `...invalid-missing-state-fails`
- `fapi2-security-profile-final-client-test-token-endpoint-response-without-expires_in`
- `fapi2-security-profile-final-client-test-token-type-case-insensitivity`
- `fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity`

Together with the 12 module instances above, **all 22 module instances
this binary drives are `FINISHED`/`PASSED`**.

**Confirmed live, repeatedly (2 independent full runs, both
zero-failure), HAIP §4.5.1's Key Attestation (Appendix D/F.3)
requirement**, via `-proof-type attestation -credential-configuration-id
eu.europa.ec.eudi.pid.1.attestation -scope eudi.pid.1.attestation`: all
22 module instances `FINISHED`/`PASSED` using the standalone
`attestation` proof type instead of the default jwt-type proof — the
same 22-module battery above, just with `driveModule`'s
`proofStrategyAttestation` branch exercised throughout instead. Key
finding: nothing needed building from scratch. Both
`wallet.Wallet.GenerateAttestationProof` and the whole
`github.com/idfoundry/oid4vcgo/attestation` package it delegates
to — Key Attestation JWT issuance matching OID4VCI Appendix D.1
exactly (`typ`, `iat`/`exp`/`nonce`/`attested_keys` claims, x5c/kid/
trust_chain header conveyance) — already existed and were already
fully spec-correct; this binary's own `keyattestation.go` only had to
wire them up: mint one Key Attestation JWT (x5c chaining to a new
dedicated CA, `client_attestation.key_attestation_trust_anchor_pem`,
replacing the previous placeholder that reused the Client Attestation
CA) attesting `numCreds` fresh keys, and submit it as
`CredentialRequest.Attestation`. `AGENTS.md`'s own note that "nothing
implements this yet" was stale by the time this work started — it
predated the `attestation` package landing; this PR corrects that note
too. A second, separate run confirmed the existing 22 module instances
(default jwt-type proof) still pass unchanged — this feature is
opt-in via a new `-proof-type` flag, not a default-path change.

**Confirmed live, repeatedly (2 independent full runs, both
zero-failure), Key Attestation nested inside a jwt-type proof's own
JOSE header** (OID4VCI Appendix D.1's "if used with the jwt proof
type" case, distinct from the standalone `attestation` proof type
above), via `-proof-type jwt-key-attestation
-credential-configuration-id eu.europa.ec.eudi.pid.1.jwt.keyattest
-scope eudi.pid.1.jwt.keyattest`: all 22 module instances
`FINISHED`/`PASSED`, including every `batch-credential-issuance`
crossing (`numCreds=2`) — the interesting case here. Two new pieces,
both small: `wallet.Wallet.GenerateProofWithKeyAttestation`
(`wallet/proof.go`) — a fourth jwt-type proof builder alongside
`GenerateProof`/`GenerateProofWithKeyID`/`GenerateProofWithX5C`,
embedding a Key Attestation JWT as the proof's own `key_attestation`
header member, with regression tests
(`TestGenerateProofWithKeyAttestation*`); and
`driveModule`'s new `proofStrategyJWTKeyAttestation` branch
(`flow.go`), reusing `buildKeyAttestationProof` (now with an
`includeExpiry` parameter — Appendix D.1 makes `exp` REQUIRED for this
nested case, unlike the standalone one) to mint **one** Key Attestation
JWT covering every attested key in the batch, then embedding that same
JWT in **every** per-credential jwt proof. That "one shared attestation,
not one per proof" design isn't arbitrary: the suite's own
`AbstractVCIWalletTest.java` only validates the *last* proof's own
nested attestation (each proof's own `validateNestedKeyAttestationInJwtProofIfNecessary`
call overwrites the same `vci.key_attestation_jwt` env value) against
the *first* proof's own key (`VCIValidateAttestedKeysInKeyAttestationFromJwtProof`
reads `proof_jwt.jwk`, set only once, at the first proof) — reading
that source directly (rather than discovering it via a failed live
run) is why a batch of independent, single-key attestations was never
tried: one attestation naming every key in the batch passes regardless
of which proof's copy of it the suite happens to actually check, and
was correct on the first live attempt.

**Confirmed live, repeatedly (3 independent full runs, all
zero-failure), the `issuer_initiated` flow variant** (`-issuer-initiated`),
crossed with every module/proof-type combination above: all 22 module
instances `FINISHED`/`PASSED`. Two genuine findings, one in each repo:

- **This binary never needs to receive an inbound request at all**,
  despite `issuer_initiated`'s own name and this binary's own prior
  assumption otherwise. The suite's `browser.goToUrl` (`BrowserControl.java`)
  is a headless HtmlUnit `WebClient`, not a real browser — and it only
  actually *dispatches* to a URL when the plan config's own `"browser"`
  array declares a matching automation script; with none declared (this
  binary doesn't), it just queues the URL and returns immediately, so
  the module reaches `WAITING` right away regardless of whether
  anything ever "visits" `vci.credential_offer_endpoint`. That queued
  URL — the fully-resolved Credential Offer redirect, `issuer_state`
  included — is already sitting in the module's own `/api/log`, under
  a `"Created credential offer redirect url"` entry's own
  `credential_offer_redirect_url` field. So `credential_offer_endpoint`
  is configured to an inert placeholder (`-credential-offer-endpoint`,
  never dereferenced by anyone), and `waitForCredentialOfferRedirectURL`
  (`credentialoffer.go`) just polls `/api/log` for that field and hands
  its string value straight to `wallet.Wallet.ResolveCredentialOffer` —
  no listener, no Docker networking, no TLS cert, despite an earlier,
  now-abandoned implementation attempt building exactly that (confirmed
  live: reachable via `host.docker.internal` from inside the suite's
  own container, and still never once hit — the suite's own HtmlUnit
  client wasn't ever going to call it, matching the "no browser
  automation script" finding above once actually traced through).
- **A genuine, general bug in `fapigo/client`**, not this binary:
  echoing the offer's own `issuer_state` back as a PAR extension
  parameter (`extension.Set`, OID4VCI §5.1.3) failed every time PAR
  needed to retry on a DPoP nonce challenge — `"extension parameter
  \"issuer_state\" collides with a core parameter name"`, even though
  nothing actually collides. Root cause: `buildPushedRequestForm`
  merged a plain-parameter extension by writing it into the *caller's
  own* `params` map instead of only the fresh per-call `form` map, and
  the DPoP-nonce-retry path reuses that same `params` map for a second
  call — so the retry saw its own first attempt's value already
  present and misreported it as a collision. Fixed upstream
  ([FAPIgo PR #322](https://github.com/IDFoundry/FAPIgo/pull/322),
  merged, `go.mod` pinned past it) with a regression test that fails
  without the fix reproducing this exact error message. The generic
  FAPI2SP battery modules (`fapi2-security-profile-final-client-test-*`)
  extend a different base class than the 4 VCIWalletTest* modules and
  have no `prepareCredentialOffer()` step at all regardless of
  `vci_authorization_code_flow_variant` — `main.go`'s own offer-wait is
  skipped for them (`batteryModulePrefix`), not just for
  `wallet_initiated`.

## Debugging

`-dump-config` prints the generated suite-side plan configuration JSON
and exits instead of creating a plan — useful for probing
`POST /api/plan`'s own validation by hand against a config this binary
actually generates (rather than a hand-written one, which routinely
fails on fields this binary already gets right). Every module outcome
line also includes the module's own id and `/api/log/{id}` URL, so a
suite-graded `FAILED` (as opposed to a driver error) can always be
traced to the suite's own log without re-instrumenting anything.

## Scope

**In scope**: both `wallet_initiated` and `issuer_initiated` flow
variants (`-issuer-initiated`), all 4 modules listed above (crossed
with all 3 issuance-mode/encryption variants the HAIP plan itself
enumerates for them), plus the plan's 4th module-list entry — the
generic FAPI2SP client conformance battery, all 10 modules, always at
the fixed `immediate`+`plain` crossing and unaffected by the flow
variant (see "Status") — each drivable with any of the three
`-proof-type` strategies: the default `jwt` (jwk-conveyed jwt-type
proof), `attestation` (standalone Key Attestation JWT, Appendix F.3),
or `jwt-key-attestation` (jwt-type proof with a nested Key Attestation
JWT header, Appendix D.1) — the latter two both exercise HAIP §4.5.1's
Key Attestation requirement, just via OID4VCI's two different
conveyance mechanisms for it.

**Update: the suite's own base (non-HAIP) `oid4vci-1_0-wallet-test-plan`
(`VCIWalletTestPlan.java` — the suite's own "alpha tests, not currently
part of certification program") is driven too, via `-base-plan`.**
Confirmed live, twice for stability: all 5 module instances
`FINISHED`/`PASSED`. This plan's own single `ModuleListEntry` pins no
issuance-mode/encryption crossing at all (unlike the HAIP plan's 3
separate entries) and reuses no FAPI2SP battery, so `-base-plan` always
drives one `immediate`+`plain` crossing of the same 4 `VCIWallet*`
modules as the HAIP plan, plus a 5th module HAIP's own
`VCIWalletTestPlanHaip.java` explicitly excludes ("Not needed for
HAIP"): `oid4vci-1_0-wallet-happy-path-with-scopes-without-authorization-details-in-token-response`,
whose Token Response omits `authorization_details` entirely. That
module needed no wallet code changes at all — confirmed by reading
`wallet/credential.go` first: `RequestCredential` already accepts a
bare `CredentialConfigurationID`, and this binary's own `driveModule`
never reads a Token Response's `authorization_details` in the first
place, so the absence changed nothing about how this binary builds its
Credential Request. Every axis the HAIP plan's own module-list entries
already pin (`ClientAuthType`, `FAPI2AuthRequestMethod`,
`FAPI2SenderConstrainMethod`, `FAPI2FinalOPProfile`, `VCIGrantType`,
`AuthorizationRequestType`, `VCIWalletAuthorizationCodeFlowVariant`)
the base plan leaves unpinned instead — `-base-plan` supplies the exact
same values HAIP already pins, just `fapi_profile=vci` instead of
`vci_haip`, confirmed via each `@VariantParameter`'s own `name=` in the
suite's Java source rather than guessed. One real config gap found
live: `client_attestation.key_attestation_jwks` (a fallback-verifier
JWKS, distinct from `key_attestation_trust_anchor_pem`) is hidden under
`fapi_profile=vci_haip` but required under base `vci` — added as an
empty-but-present placeholder (`config.go`), since this binary's own
Key Attestation JWTs always carry an `x5c` header
(`keyattestation.go`), which the suite's own fallback verifier
(`VerifyKeyAttestationSignatureUsingConfigJwks`) skips whenever present
— the same required-but-unused pattern already found on the Issuer
role's own equivalent field.

**Update: the suite's own `mso_mdoc` credential format is driven too,
via `-credential-format mdoc`.** Neither role in this repo had ever
exercised mdoc before — every module always used
`credential_format=sd_jwt_vc`. `wallet.Wallet.RequestCredential`'s own
credential-response handling is entirely format-agnostic (it just
returns whatever opaque `credential` string comes back), so this binary
needed **zero wallet-package code changes** — just the new
`-credential-format` flag (setting the plan's own `credential_format`
variant) plus a matching `-credential-configuration-id`/`-scope`
naming one of the suite's own mdoc-format fixtures
(`VCICredentialConfigurations.java`): `eu.europa.ec.eudi.pid.mdoc.1`/
`eudi.pid.mdoc.1` (`doctype: eu.europa.ec.eudi.pid.1` — the suite's own
fixture, not something this binary configures). Confirmed live, twice
for stability: all 22 module instances `FINISHED`/`PASSED`, identical
outcomes both times — the same full crossing set (4 modules × 3
issuance-mode/encryption variants, plus the 10-module FAPI2SP battery)
already proven under `sd_jwt_vc` above.

**Not yet covered** (separate, later, only if asked):

- `issuer_initiated_dc_api` — needs real Digital Credentials API
  browser-JS interaction, the same scope cut this repo's own
  `cmd/conformance-wallet-vp` already makes for its own `dc_api.jwt`
  module lists.
- The base (non-HAIP) `VCIWalletTestPlan`'s `ClientAuthType`≠`client_attestation`
  variants, and its own FAPI2SP-battery-equivalent coverage (the base
  plan doesn't reuse the battery at all, so there's nothing to drive
  there).

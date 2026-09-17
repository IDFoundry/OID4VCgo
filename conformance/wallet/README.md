# conformance-wallet

`cmd/conformance-wallet` drives `oid4vcigo/wallet` and `fapigo/client`
headlessly through the OIDF conformance suite's own
`oid4vci-1_0-wallet-haip-test-plan` ("OpenID for Verifiable Credential
Issuance 1.0 Final/HAIP: Test a wallet") — specifically the
`wallet_initiated` flow variant's 4 non-battery modules, crossed with
all 3 of the plan's own issuance-mode/encryption variants
(`immediate`+`plain`, `deferred`+`plain`, `immediate`+`encrypted`). See
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

**In scope**: `wallet_initiated` flow variant, all 4 modules listed
above, crossed with all 3 issuance-mode/encryption variants the HAIP
plan itself enumerates for them.

**Not yet covered** (separate, later, only if asked):

- The HAIP plan's 4th module-list entry (the generic FAPI2SP client
  battery — PAR/DPoP/token edge cases wrapped in VCI variant
  selectors). Already covered in spirit by FAPIgo's own
  `cmd/conformance-client` baseline plan.
- `issuer_initiated`/`issuer_initiated_dc_api` flow variants (need a
  small inbound HTTP GET endpoint for the credential-offer handoff —
  `wallet_initiated` needs none at all) and the base (non-HAIP)
  `VCIWalletTestPlan`'s `ClientAuthType`≠`client_attestation` variants.
- HAIP §4.5.1's own Key Attestation (Appendix D proof-of-possession
  key format) requirement — genuinely distinct from Wallet Attestation
  client auth (see `AGENTS.md`); this binary's config supplies a
  placeholder trust anchor only because the suite's config validation
  requires the field to be present, not because anything exercises it.

# conformance-wallet

`cmd/conformance-wallet` drives `oid4vcigo/wallet` and `fapigo/client`
headlessly through the OIDF conformance suite's own
`oid4vci-1_0-wallet-haip-test-plan` ("OpenID for Verifiable Credential
Issuance 1.0 Final/HAIP: Test a wallet") — specifically the
`wallet_initiated`, `immediate`+`plain` crossing of its 4 non-battery
modules. See "Scope" below for what isn't covered yet.

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
  "aud claim... did not match the authorization server issuer".

## Status

**Confirmed live, repeatedly, against a real local OIDF conformance
suite instance** (Docker, `docker-compose-prebuilt.yml`). All 4
in-scope modules `FINISHED`/`PASSED` on two independent runs:

- `oid4vci-1_0-wallet-test-credential-issuance`
- `oid4vci-1_0-wallet-test-credential-issuance-notification`
- `oid4vci-1_0-wallet-test-client-attestation-challenge` — the module
  that specifically exercises the Attestation Challenge Endpoint
  (draft-ietf-oauth-attestation-based-client-auth-07 §8), proving
  FAPIgo PR #318's `client.ChallengeSource` end to end against the
  suite's own `POST /challenge` → embed-in-PoP sequence, not just
  FAPIgo's own unit tests.
- `oid4vci-1_0-wallet-test-batch-credential-issuance`

This is the live-suite counterpart to
`cmd/conformance-issuer`'s own `TestFullFlow_RealClientDrivesAttestationAuth`:
that test proved a real `fapigo/client` wallet interoperates with a
real `fapigo/server` Authorization Server; this binary proves the same
wallet-side stack against the actual OIDF suite's own independent
implementation of the AS/Issuer side and its own Attestation
Challenge Endpoint.

## Scope

**In scope**: `wallet_initiated` flow variant, `immediate`+`plain`
issuance mode, the 4 modules listed above.

**Not yet covered** (separate, later, only if asked):

- `deferred`+`plain` and `immediate`+`encrypted` issuance-mode
  crossings — `wallet` already has `RequestDeferredCredential`/
  `RequestEncryption`/`ResponseEncryption`, so this would be a config/
  flag toggle on the same binary, not new protocol logic.
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

# conformance-issuer

`cmd/conformance-issuer` pairs a real `fapigo/server.Server` (FAPI 2.0
Security Profile Final, Wallet Attestation client authentication,
DPoP) with a real `oid4vcigo/issuer.Issuer` behind real HTTP, for the
OIDF conformance suite's own `oid4vci-1_0-issuer-haip-test-plan`
("OpenID for Verifiable Credential Issuance 1.0 Final/HAIP: Test an
issuer", confirmed against the suite's own source at
`gitlab.com/openid/conformance-suite`,
`VCIIssuerTestPlanHaip.java`).

## Why this is a full FAPI 2.0 AS, not just OID4VCI endpoints

Unlike the OID4VP Verifier/Wallet plans (Phase 1), the Issuer-role
plan's own module list literally reuses the suite's entire
`FAPI2SPFinalTestPlan` module set (PAR, DPoP, grant management, ...)
on top of VCI-specific modules — the suite's own imports in
`VCIIssuerTestPlanHaip.java` include dozens of `FAPI2SPFinal*` classes
directly. So this binary needs to *be* a real FAPI 2.0 AS, not stand
one up separately: `wiring.go` builds one from FAPIgo's own
`server`/`resource`/`storage/memstore` packages, adapted from FAPIgo's
own OpenID-Certified `cmd/conformance-as` (which has never itself been
run with `AttestationBasedClientAuthentication` enabled — this binary
is the first real exercise of that mode in either repo), trimmed to
this plan's own fixed variant selection:
`FAPI2SenderConstrainMethod=dpop`, `ClientAuthType=client_attestation`,
`FAPI2AuthRequestMethod=unsigned` (→ `server.ProfileFAPISecurity`, not
message-signing), `VCIGrantType=authorization_code` (the suite's own
docs confirm pre-authorized code isn't testable at all: "HAIP mandates
the use of the authorization code flow"), `FAPIOpenIDConnect=plain_oauth`
(→ `Config.OAuthOnly = true`: no ID tokens, no UserInfo endpoint, a
real simplification `cmd/conformance-as` itself doesn't get to make).

`issuer.Issuer`'s own Credential/Nonce endpoints are layered on top via
a real `fapigo/resource.Verifier`, per `issuer/resource_verifier.go`'s
own integration recipe — the first time that recipe has been compiled
and run anywhere in this repo, not just documented.

## Endpoints

AS side (FAPIgo, `server.Server`): `GET /.well-known/openid-configuration`,
`GET /jwks`, `POST /par`, `GET /authorize` + `POST /authorize/decision`
(a real HTML consent form, auto-filled — mirrors `cmd/conformance-as`'s
own `consentHandler`, trimmed of Rich Authorization Requests support,
which this binary's one CredentialConfiguration doesn't need), `POST
/token` (`authorization_code`/`refresh_token` only).

OID4VCI side (`issuer.Issuer`): `GET
/.well-known/openid-credential-issuer`, `POST /nonce`, `POST
/credential` (`credentialHandler` verifies the presented access token
via `resource.Verifier`, then calls `RequestCredential` with this
binary's own fixed, static claim content — `issuer.Issuer` has no user
database of its own, per `CredentialRequest.SDJWTClaims`'s own doc
comment).

## Status

**Confirmed live, end to end**: `flow_test.go`'s
`TestFullFlow_ParAuthorizeTokenNonceCredential` drives the entire
stack against a real `newServerMux` instance — PAR (with a real Client
Attestation + PoP JWT pair and a DPoP proof), the consent-form
`GET /authorize` → `POST /authorize/decision` round trip, `POST
/token` (Client Attestation authentication, DPoP-bound access token
issuance), `POST /nonce`, and finally `POST /credential` (a fresh
jwt-type key proof, DPoP-bound resource access) — and receives back a
real issued credential. Also confirmed: `TestNewServerMux_ServesRealMetadataAndJWKS`
(both metadata documents + JWKS, as a lighter-weight check).

Building the full-flow test surfaced three real bugs, all fixed
alongside it:
- `par.go`/`token.go` never forwarded the
  `OAuth-Client-Attestation`/`OAuth-Client-Attestation-PoP` headers to
  `fapigo/server` at all — `PushAuthorizationRequest`/
  `AuthorizationCodeExchangeRequest`/`RefreshTokenRequest` all have
  `ClientAttestations`/`ClientAttestationPoPs` fields distinct from
  `DPoPProofs`, and the original wiring simply never set them. Every
  attestation-authenticated request would have failed outright.
- `Config.Client` only carried `ExpectedAttesterIssuer` (a string
  identity for the attestation's own `iss` claim check) with no actual
  key material — but `fapigo/server` resolves an attestation's
  *verification* key via `Dependencies.ClientKeys`, keyed by client ID,
  regardless of that issuer string (confirmed against
  `server/client_auth_attestation.go`'s own `resolveClientKey` call).
  Added `Config.Client.AttesterJWKS` and wired it into
  `ephemeral.NewClientKeySource`.
- `credentialHandler` passed the incoming request's own `r.URL`
  straight into `resource.Verifier.Verify` for DPoP's own "htu" check
  — but a `net/http` server request's `URL` has no Scheme/Host
  populated (only what's on the request line), so the comparison
  always failed. Fixed to pass a pre-built, fully-qualified URL
  instead, matching FAPIgo's own `cmd/conformance-as/resource.go`
  precedent (`userinfoURL`/`accountsURL`, never `r.URL`) — this repo's
  own `par.go`/`token.go` never hit the equivalent bug only because
  `fapigo/server` resolves its own endpoint URLs from `Config.Endpoints`
  internally rather than trusting the incoming request's URL at all.

**Deliberately out of scope for this first pass** (see the suite's own
module list for what each would additionally cover): the Deferred
Credential Endpoint, the Notification Endpoint, request/response
encryption (§10), `mso_mdoc` format, `client2`
(PS256/RSA-negative-test un-skipping), and CIBA/client_credentials/
Grant Management modules the base `FAPI2SPFinalTestPlan` module list
carries but this specific HAIP variant selection may not actually
exercise.

## Status: live run against the real OIDF suite

**Update**: `credential.go` now sets an `exp` claim on every issued
credential (`issuedCredentialLifetime`, a year out — HAIP/SD-JWT VC
§11.2.3's own RECOMMENDED-not-required validity limit), fixing the one
WARNING every module below used to carry. Re-run live: `happy-flow` is
now a clean `FINISHED`/`PASSED` with zero log entries at `WARNING` or
worse, not just zero `FAILURE`s — every "same soft `exp`-claim note"
mention below predates this fix.

Plan creation succeeds (`oid4vci-1_0-issuer-haip-test-plan`, 61
modules, `sd_jwt_vc` variant) once the plan config supplies: a
throwaway self-signed cert wrapping this binary's own credential-issuer
key (`credential.trust_anchor_pem`/`status_list_trust_anchor_pem`), a
*private* EC JWKS for `client_attestation.attester_jwks` (the suite
signs its own emulated Client Attestation JWTs with it — this binary's
own config registers the matching *public* half as
`client.attester_jwks`/`client2.attester_jwks`), and a second throwaway
private JWKS for `client_attestation.key_attestation_jwks`. The
attester JWK itself must also carry an `x5c` entry (RFC 7517's own JWK
member, not the JWS header) — the suite's own `CreateClientAttestationJwt`
step rejects one without it ("A x5c entry is required in the client's
signing key but isn't present in the configuration"); a **CA-signed**
leaf works (a self-signed one wasn't tried here, but see the
`credential/sdjwtvc` x5c finding elsewhere in this session for why a
CA-signed leaf was used from the start).

**`oid4vci-1_0-issuer-metadata-test`: confirmed live, full PASS**
(`status: FINISHED, result: PASSED`). This module's first attempt
surfaced a real, now-fixed gap: this binary's credential issuer
metadata omits the OPTIONAL `authorization_servers` field, so the
suite falls back to RFC 8414 derivation from the credential issuer URL
and requests `GET /.well-known/oauth-authorization-server` — which
404d, since only `router.go` decides which paths serve this binary's
FAPI 2.0 AS metadata, and it only wired
`/.well-known/openid-configuration` (OIDC Discovery's own path).
**This turned out to be entirely fixable inside this binary, not a
FAPIgo-side gap**: `authorizationServerMetadataHandler` just wraps
`srv.Metadata()`, a plain data method with no opinion on which path
serves it — `router.go` now registers the same handler at both paths,
matching RFC 8414 §3.1's own stance that a plain-OAuth AS (this one:
`Config.OAuthOnly = true`) should be identifiable at its own
plain-OAuth well-known path, not only the OIDC one. Re-run live after
the fix: full pass.

**Update: `oid4vci-1_0-issuer-metadata-test-signed` — real support
added, not just made to pass.** Previously self-`SKIPPED`: HAIP §4.1
only conditions signed metadata on ecosystem policy ("When Ecosystem
policies require Issuer Authentication to a higher level than possible
with TLS alone, signed Credential Issuer Metadata... MUST be
supported"), so it stayed genuinely optional and out of scope — this
was scoped as a deliberate coverage improvement, not a compliance fix.
`credentialIssuerMetadataHandler` (`credential.go`) now does real
content negotiation per OID4VCI §12.2.2/§12.2.3: it always supports
plain `application/json` (unchanged default), and when a request's own
`Accept` header names `application/jwt`, signs the same
`issuer.Metadata()` value as a compact JWS instead — every metadata
parameter flattened as top-level JWS payload claims (§12.2.3's own
requirement), plus `sub` (the Credential Issuer Identifier) and `iat`,
under a `typ: "openidvci-issuer-metadata+jwt"` header and the same
`x5c` convention this binary's issued credentials already use, signed
with the same credential-issuer key/cert pair
(`issuer.Dependencies.SDJWTSigner` already trusts). Confirmed live:
`FINISHED`/`PASSED`, zero log entries at `WARNING` or worse, with the
suite's own independent check
(`VCIDecodeSignedCredentialIssuerMetadata`: "Successfully decoded and
verified signed credential issuer metadata using x5c certificate")
confirming the signature itself, not just the `Content-Type` header.
Re-verified `metadata-test` (the plain-JSON module) and `happy-flow`
still pass unchanged.

**`client2`: fixed, confirmed both as a unit test and live.** Even
this plan's own `happy-flow` module (not just multi-client variants)
lists `client2.client_id`/`client2.scope`/`client2.jwks` in its own
`configurationFields` — `client2` is structurally required, matching
FAPIgo's own `client_credentials` precedent. `Config.Client` was a
single struct (deliberately out of scope, per its own prior doc
comment); added `Config.Client2 *ConfigClient` (optional — nil
registers only `Client`) and extended `wiring.go` to register both as
independent `storage.ClientAuthMethodAttestation`-authenticated
clients sharing one `Dependencies.ClientKeys` source.
`TestFullFlow_Client2CanAuthenticatePAR` proves client2 can PAR-
authenticate for real, with client1 also registered alongside it. Live
confirmation: the suite's own `happy-flow` module attempt got past
`SUCCESS | Generated JWKS for client2` and all the way to actually
building and sending a PAR request as client1 (see below) — client2's
own registration didn't block or interfere with anything.

**`oid4vci-1_0-issuer-happy-flow`: PAR blocker raised with FAPIgo,
fixed upstream, pinned, and re-confirmed live — `FINISHED`, result
`WARNING`, zero `FAILURE`s.** The suite's own PAR-2.1–PAR-2.4 check
(RFC 9126/6749: "the authorization server MUST ignore unrecognized
request parameters") was traced into `fapigo/server`'s own
`Config.Extensions` — a strict allowlist that used to reject any
unregistered parameter outright rather than ignore it. Raised with
FAPIgo's maintainers as the design question this file previously
flagged it as; they agreed and shipped
`fix!: ignore unrecognized authorization request parameters at
PAR/CIBA` (commit `597f2a7`, FAPIgo PR #304) — an unregistered
authorization request parameter is now silently dropped (deleted from
the request, per `extension.Registry.Parse`'s own updated doc comment)
rather than failing the whole request. Pinned `go.mod` to this exact
commit (no tagged release yet) and re-ran the suite: PAR now succeeds,
and the module runs all the way through the consent redirect, token
exchange, nonce, and credential issuance.

That full run surfaced one more real, now-fixed gap along the way: the
issued credential itself hit the exact same x5c requirement
`conformance/wallet-vp/README.md` already documents for
`cmd/conformance-wallet-vp` (`FAILURE | Credential MUST contain an x5c
in the header`) — `issuer.SDJWTSigner` had no `IssuerCertificate` field
at all, unlike `MdocSigner`'s own `X5Chain`, which already existed.
Fixed by adding `issuer.SDJWTSigner.IssuerCertificate *x509.Certificate`
(mirrors `credential/sdjwtvc.IssueOptions.IssuerCertificate` exactly,
since `issueSDJWT` just forwards it) and wiring `cmd/conformance-issuer`
to issue its own credential-signing key's certificate under a
throwaway CA (`conformancecert.GenerateCA`/`IssueLeafCertPEM`), the
same self-signed-leaf lesson already learned on the wallet-vp side.
Re-run live after this second fix: `status: FINISHED, result: WARNING`
— the only remaining log entry is a soft `RECOMMENDED` note ("issuers
are RECOMMENDED to limit the validity of a credential using an exp
claim, status claim or both"), not a `FAILURE`; this binary's own
issued SD-JWT VC doesn't set `exp`.

`issuer/authorization_server.go`'s own "Registering issuer_state"
recipe section is updated to match the new behavior: skipping
`oid4vci.IssuerStateExtension` registration no longer produces a loud
PAR-time rejection, it silently drops `issuer_state`'s value instead —
a worse failure mode to discover later, not a better one to skip.
`TestAuthorizationServerRejectsIssuerStateWithoutExtensionRegistered`
(now `...Ignores...`) is updated to match.

## Status: all 21 OID4VCI-specific modules run live

Beyond `happy-flow`, every `oid4vci-1_0-issuer-*` module in the plan
(21 of 61 total — the other 40 are the generic
`fapi2-security-profile-final-*` FAPI 2.0 battery, not yet attempted;
see below) has now been run against the real suite. This also settled
the consent-flow-compatibility and `Config.OAuthOnly`-compatibility
open questions originally listed here: both are confirmed working —
the consent-form round trip this binary's own `flow_test.go` already
proved end to end against a hand-rolled client also works driven by
the real suite, and the suite's own `openid=plain_oauth` variant
completed successfully throughout every module below.

**One more real, high-value gap found and fixed: TLS cipher suite
configuration.** `happy-flow-additional-requests` (and, transitively,
anything requiring a second live TLS handshake mid-flow) failed with
`FAILURE | Server accepted a cipher that is not on the list of
permitted ciphers` — the suite's own FAPI-RW-8.5-1/-2 probe. Root
cause: `cmd/conformance-issuer/main.go`'s own `tls.Config` set only
`Certificates`, no `MinVersion`/`CipherSuites` — Go negotiates TLS 1.3
by default, whose three built-in AEAD suites always include
ChaCha20-Poly1305, which this specific FAPI-RW probe flags as "not
permitted" (it hardcodes the narrower FAPI-RW §8.5 AES-GCM-only list,
per `fapigo/server.FAPIRWTLSCipherSuites`'s own doc comment — even
though the broader FAPI2-SP-FINAL-5.2.2/BCP195 profile does permit
ChaCha20-Poly1305). FAPIgo's own OpenID-Certified `cmd/conformance-as`
already solves this (`server/tls.go`'s exported
`FAPIRWTLSCipherSuites`) but this binary never wired it in. Fixed by
setting `MinVersion: tls.VersionTLS12, CipherSuites:
server.FAPIRWTLSCipherSuites` on the listener — mirrors
`cmd/conformance-as/main.go` exactly. Re-confirmed live: zero
`FAILURE`s across everything this fix touched.

**Final results, 21/21 modules run live:**

- `metadata-test`: `PASSED`. `metadata-test-signed`: **`PASSED`** —
  real signed-metadata support added (see the "Update" note above),
  confirmed live with the suite independently verifying the JWS
  signature via its own `x5c` header, not just a `Content-Type` flip.
- `happy-flow`, `happy-flow-additional-requests`,
  `happy-flow-skip-notification`: all `FINISHED`/`PASSED`, zero log
  entries at `WARNING` or worse (see the "Update" note above).
- `happy-flow-multiple-clients`: **`FINISHED`/`PASSED`, zero log
  entries at `WARNING` or worse.** Getting here needed two real fixes.
  First, a config detail: client2's own registered `redirect_uris`
  must be the suite's *exact* string, including its fixed
  `?dummy1=lorem&dummy2=ipsum` query component — `fapigo/server`'s own
  exact-match redirect_uri check, per RFC 6749 §3.1.2.3, is correct
  here, this was an AS-side config gap, not a code bug. Second, a real
  privacy finding: issuing credentials for both clients moments apart
  surfaced `WARNING | Credential time information [exp] advanced by
  ~the real inter-issuance gap between two same-dataset credentials,
  indicating the issuer embeds the precise issuance time... RFC 9901
  §10.1` — two credentials issued seconds apart carried two `exp`
  values differing by exactly that gap, a linkability side-channel a
  party holding both could exploit. Fixed by rounding `exp` down to
  the start of the issuance day before adding the lifetime
  (`internal/conformancecert.CredentialExp`, shared with
  `cmd/conformance-wallet-vp`) — every credential issued on the same
  calendar day now carries an identical `exp`, closing the channel
  while still bounding validity. Driving both clients' own
  consent/implicit-submission rounds through this manual curl-driven
  harness (not the suite's own headless browser) turned out to be
  straightforward once done in the right order: complete client1's
  entire round (authorize → decision → follow redirect → implicit
  submit) before starting client2's — the suite's own
  `/api/runner/browser/{id}` endpoint accumulates a `urls` array across
  both clients rather than replacing it, so drive the *last* entry for
  the second client's own round, not `urls[0]` again.
**Update: `batch-issuance` — real support added, not just made to
pass.** Previously self-`SKIPPED`: HAIP only requires an Issuer to
*advertise* support or non-support via the `batch_credential_issuance`
metadata parameter, never a MUST to actually implement it, so this
stayed genuinely optional — scoped as a deliberate coverage
improvement, not a compliance fix. Turned out `issuer.RequestCredential`
already fully implements OID4VCI §3.3.2 batch issuance end to end
(resolves one binding key per proof in the `proofs` array, issues one
Credential per key, shares one consumed `c_nonce` across the whole
request) — `cmd/conformance-issuer` just never opted in.
`wiring.go` now sets `BatchCredentialIssuance: &issuer.BatchCredentialIssuance{BatchSize: conformanceBatchSize}`
(5) on the `issuer.Config` it builds. Confirmed live:
`FINISHED`/`PASSED`, zero log entries at `WARNING` or worse, with the
suite sending a real 5-proof batch and independently verifying: all 5
credentials share the same Credential Dataset
(`VCIEnsureBatchSdJwtCredentialDatasetsMatch`), no two share a
disclosure salt (`VCIEnsureBatchSdJwtDisclosureSaltsAreDistinct`), each
credential's own `cnf` binding key matches one of the 5 sent proof
keys and all 5 are mutually distinct
(`VCIEnsureBatchBindingKeysMatchSentProofKeys`/
`VCIEnsureBatchBindingKeysAreDistinct`), and the batch's own time
claims are non-linkable (`VCIEnsureBatchTimeClaimsNotLinkable` —
confirms the RFC 9901 §10.1 `exp`-rounding fix from earlier in this
role's own work holds up under a real multi-credential batch, not just
across separate multi-client requests). Re-verified `happy-flow`,
`metadata-test`, and `metadata-test-signed` all still `FINISHED`/`PASSED`
with no regression.

*(Verification note: an earlier "happy-flow re-confirmed, no
regression" claim in this session's own PR description for the signed-
metadata change was driven with an incomplete script — one that never
followed the `/authorize/decision` redirect back to the suite, so the
run silently stopped partway through rather than actually completing.
It showed zero `WARNING`/`FAILURE` only because it never got far enough
to hit one, not because it passed. No functional regression resulted —
this round's proper, complete re-drive above confirms `happy-flow`
genuinely still passes — but the earlier claim itself wasn't backed by
what it said it was.)*
- 10 of 10 `fail-*` negative tests that apply to this binary's own
  configuration all `PASSED`: `fail-invalid-nonce`,
  `fail-invalid-jwt-proof-signature`,
  `fail-invalid-client-attestation-signature`,
  `fail-invalid-client-attestation-pop-signature`,
  `fail-client-attestation-exp-in-past`,
  `fail-client-attestation-no-sub`,
  `fail-client-attestation-pop-wrong-aud`,
  `fail-mismatched-client-attestation-pop-key`, `fail-missing-proof`,
  `fail-unknown-credential-configuration`,
  `fail-unknown-credential-identifier`,
  `fail-on-access-token-in-query`.
- `fail-invalid-key-attestation-signature` correctly self-`SKIPPED`
  (this binary never wires an `AttestationVerifier`; only the `jwt`
  proof type is configured, not `attestation`). Confirmed against the
  HAIP 1.0 spec text directly: HAIP §4.5.1's key-attestation language
  does contain one unconditional MUST ("Wallets MUST support key
  attestations"), but that MUST falls on Wallets, not Issuers;
  Issuer-side support for the `attestation` proof type is conditioned
  on ecosystem choice ("Ecosystems that desire wallet-issuer
  interoperability on the level of key attestations SHOULD require
  Wallets to support... `jwt` proof type using `key_attestation`
  [and] `attestation` proof type"). So this skip is legitimate for the
  Issuer role specifically — but the Wallet-side
  MUST is real and unconditional, and applies to the still-blocked
  OID4VCI Wallet role (see "Not yet run live" below and `AGENTS.md`),
  not to anything already implemented. Worth keeping separate from
  that role's already-tracked Wallet Attestation (client
  authentication) gap: key attestation (proof-of-possession key
  format) and wallet attestation (client auth) are two distinct HAIP
  requirements that role will need to satisfy once unblocked.

**Update: `fail-unsupported-encryption-algorithm` — real support
added, not just made to pass.** Previously self-`SKIPPED`: HAIP never
references OID4VCI §10 encryption anywhere, so it stayed fully
optional — scoped as a deliberate coverage improvement, not a
compliance fix. Turned out `issuer.RequestCredential`'s own
`DecryptRequestBody`/`EncryptResponseBody` already fully implement §10
JWE-based request decryption/response encryption, tested end to end —
`cmd/conformance-issuer` just never opted in. `wiring.go` now sets
`Config.RequestEncryption`/`ResponseEncryption`, advertising
`A128GCM`/`A256GCM` (deliberately excluding `A192GCM`, which
`internal/jwe` genuinely implements, so "unsupported" stays a real
condition, not a vacuous one); `credential.go`'s own handler now calls
`DecryptRequestBody` before parsing the wire request and
`EncryptResponseBody` before writing the response.

Driving this live surfaced three more real, pre-existing gaps in the
already-implemented `issuer` package — none of them were exercised by
any test before this binary's own wiring made this code path reachable
for the first time:

- **`credential_request_encryption.jwks` was a bare JSON array.**
  §12.2.4 requires "A JSON Web Key Set" — RFC 7517 §5's own
  `{"keys": [...]}` object — not a bare array. The suite's own
  `VCICheckCredentialRequestEncryptionSupported` check rejected it
  outright. Fixed by adding `metadataJWKSet` (`issuer/encryption.go`)
  and wrapping every published key in one.
- **Published request-encryption keys had no `"alg"` member.** §10's
  own "The alg parameter MUST be present" — the suite rejected a key
  with no alg ("expected at least one key with... an asymmetric JWE
  alg"). Fixed by adding `Alg jwe.Alg` to `metadataJWK` and always
  publishing `"ECDH-ES"` (the only alg `internal/jwe` implements).
- **`EncryptResponseBody` never validated the Wallet's own
  `credential_response_encryption.jwk`'s own declared `"alg"`.** A
  Wallet can publish a response-encryption key whose `enc`/`kty`/`crv`
  are all valid but whose own `alg` names something this issuer can't
  actually use (the suite's own literal probe: `"UNSUPPORTED_ALG"`) —
  before this fix, `EncryptResponseBody` ignored that field entirely
  and encrypted the response anyway with its own ECDH-ES, silently
  accepting a Wallet-declared mismatch rather than rejecting it per
  §10's own "The JWE alg algorithm used MUST be equal to the alg value
  of the chosen JWK." Fixed by validating the JWK's own `alg` (when
  present) against `jwe.ECDHES`.
- **Every §10 failure used the generic `invalid_credential_request`
  error code, not §8.3.1.2's own dedicated
  `invalid_encryption_parameters`.** The suite specifically checks for
  the latter and fails the module on any other code, even a correctly-
  4xx one. Added `ErrorInvalidEncryptionParameters` and switched every
  encryption-related error site in `issuer/encryption.go`,
  `credential_endpoint.go`, and `deferred_credential_endpoint.go` to
  use it.

Confirmed live after all four fixes: `FINISHED`/`PASSED`, zero log
entries at `WARNING` or worse — the suite's own driving recipe sends a
validly-encrypted outer request whose inner
`credential_response_encryption.jwk` declares
`"alg":"UNSUPPORTED_ALG"`, gets back `EnsureHttpStatusCodeIs400`
(SUCCESS), `VCIEnsureCredentialResponseIsNotAnEncryptedJwe` (SUCCESS —
confirms the error came back as plain JSON, not an encrypted body),
and the expected `invalid_encryption_parameters` error code. Also
added a genuine positive round trip
(`TestFullFlow_EncryptedCredentialRequestAndResponse`) proving a real
encrypt→issue→encrypt→decrypt cycle works through the actual HTTP
binary, not just the library's own already-tested internals, plus two
more negative tests mirroring the suite's own two distinct failure
modes (unsupported outer/inner `enc`, and the JWK `alg` mismatch) —
none of this was suite-satisfying theater; every fix closes a real gap
a genuine encryption-aware client would have hit. Re-verified
`happy-flow`, `batch-issuance`, `metadata-test`, and
`metadata-test-signed` all still pass with no regression.

## Not yet run live

The 40 `fapi2-security-profile-final-*` modules — the generic FAPI 2.0
Security Profile Final battery (PAR/DPoP/PKCE/token-endpoint edge
cases, TLS/discovery checks, grant management). These test
`fapigo/server`'s own FAPI2 compliance more than anything specific to
this binary's own OID4VCI wiring — FAPIgo is already OpenID Certified
against this same suite family in other client-authentication
configurations, just not yet with `ClientAuthMethodAttestation`
specifically. Lower expected marginal value than the OID4VCI-specific
modules above (most findings here would be FAPIgo-side, following the
same PAR-fix precedent, rather than OID4VCIgo-side), and a
substantially larger module count — not attempted this pass.

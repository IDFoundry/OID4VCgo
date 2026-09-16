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

**`oid4vci-1_0-issuer-metadata-test-signed`: confirmed live, correctly
`SKIPPED`** — this module tests OID4VCI's optional signed
Credential Issuer Metadata feature, which `issuer.Issuer` doesn't
implement (always returns plain JSON); the suite detects this via
`Content-Type` and self-skips rather than failing. Not a gap: signed
metadata is optional and out of scope.

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

## Not yet run live

Every module past `happy-flow` (59 of 61) — this was the first module
in the plan actually attempted past the metadata/PAR stage; the
consent-flow-compatibility open question originally listed here is now
resolved (the consent-form round trip this binary's own `flow_test.go`
already proved works end to end against a hand-rolled client also
works driven by the real suite). `Config.OAuthOnly`-compatibility
remains implicitly confirmed by this same live run (the suite's own
`openid=plain_oauth` variant completed successfully throughout).

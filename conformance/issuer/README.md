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

**`oid4vci-1_0-issuer-happy-flow`: reaches real protocol traffic, then
blocked on a confirmed, deliberate `fapigo/server` design decision —
not a bug, and not fixable from OID4VCIgo.** The suite built a real
PAR request as client1 — `client_id`, `redirect_uri`, `scope`,
`state`, `response_type`, `code_challenge`, `code_challenge_method`, a
real Client Attestation + PoP JWT pair — plus one deliberately
unrecognized, randomly-named extra parameter (citing requirements
`PAR-2.1`–`PAR-2.4`: "the authorization server MUST ignore
unrecognized request parameters", RFC 9126 carrying forward RFC 6749
§3.1's general rule). `fapigo/server` rejected the *entire* request
with `400 invalid_request: "request contains an unregistered or
invalid parameter"` instead of ignoring the one extra parameter.

Traced this into `fapigo/server`'s own source (the pinned checkout at
`../go-fapi`, matching `go.mod`'s exact pseudo-version) rather than
just the HTTP symptom: `cmd/conformance-issuer/par.go` is a thin
passthrough (`server.FormRequestFromHTTP` → `srv.PushAuthorizationRequest`,
no parameter filtering of its own) — the rejection happens inside
`checkExtensions`, which runs every non-core parameter through
`Config.Extensions.Parse` (an `*extension.Registry`), rejecting any
name with no pre-registered `extension.Definition`. `extension`'s own
`doc.go` states this plainly: *"Any parameter without a registered
Definition is rejected by default; there is no production option to
silently preserve unknown fields."* FAPIgo's own `ARCHITECTURE.md`
design rules 10–11 confirm this is deliberate defense-in-depth against
parameter-pollution/confusion attacks, not an oversight, and that a
caller wanting permissive behavior "must opt in explicitly and
separately" — outside `fapigo/server` entirely, since it offers no
such option itself.

This closes off any real fix on either side: the suite generates a
*fresh random* parameter name each run, so there is no `Definition` to
pre-register even if we wanted one, and filtering unknown parameters
ourselves in `par.go` before forwarding would mean duplicating
`fapigo/server`'s own unexported core-parameter allowlist — fragile,
liable to drift, and would silently defeat the exact security property
`fapigo/server` was deliberately built to enforce. Not fixed here,
matching `AGENTS.md`'s standing rule: don't patch around a FAPIgo
design decision from inside OID4VCIgo. Unlike the Wallet Attestation
client-side gap (a genuine missing feature FAPIgo will presumably add),
this is closer to a values tradeoff FAPIgo's own maintainers made
knowingly — worth raising with them as a real design question (does
`fapigo/server` want an opt-in permissive mode for exactly this kind
of conformance/interop scenario?), not a straightforward "please fix
this bug" report.

## Not yet run live

Every module past `happy-flow`'s current blocker (59 of 61) — blocked
transitively on the PAR unrecognized-parameter gap above for any
module that reaches PAR at all. The consent-flow-compatibility and
`Config.OAuthOnly`-compatibility open questions originally listed here
remain unresolved, since no module has reached that far yet.

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

**Confirmed live**: the full wiring (`newServerMux`) boots, and a real
running instance serves correctly-formed FAPI 2.0 Authorization Server
metadata (`token_endpoint_auth_methods_supported` includes
`attest_jwt_client_auth`, `pushed_authorization_request_endpoint`
present, ...), correctly-formed OID4VCI Credential Issuer metadata
(`credential_configurations_supported` with the right `vct`/proof
types), and a real JWKS — all from the actual production wiring, not
mocks. Captured as a permanent regression test
(`TestNewServerMux_ServesRealMetadataAndJWKS`).

**Not exercised**: the actual PAR → consent → token → nonce →
credential flow end to end. Building a hand-rolled smoke-test client
for this would mean constructing a real Client Attestation + PoP JWT
pair (`draft-ietf-oauth-attestation-based-client-auth-07`), a DPoP
proof, and driving the full Authorization Code Flow — comparable in
scope to another whole binary, and out of reach in this pass. Unlike
Phase 1 (where `cmd/conformance-wallet-vp` could validate
`cmd/conformance-verifier` directly), there's no equivalent sibling
binary here to cross-test against. This is the natural next
verification step, whether via a dedicated smoke-test client or the
live OIDF suite itself.

**Deliberately out of scope for this first pass** (see the suite's own
module list for what each would additionally cover): the Deferred
Credential Endpoint, the Notification Endpoint, request/response
encryption (§10), `mso_mdoc` format, `client2`
(PS256/RSA-negative-test un-skipping), and CIBA/client_credentials/
Grant Management modules the base `FAPI2SPFinalTestPlan` module list
carries but this specific HAIP variant selection may not actually
exercise.

## Open questions for the live run

- Whether `Config.OAuthOnly = true` is actually compatible with this
  plan's own `FAPIOpenIDConnect=plain_oauth` variant, or whether the
  suite's own conditions expect something more specific from a
  plain_oauth-profiled AS that this binary's minimal wiring doesn't
  yet provide.
- Whether the consent flow (a real rendered HTML form + POST
  submission) is compatible with how the suite drives this specific
  plan — Phase 1's own wallet-role research found at least one case
  (`CreateRandomBrowserApiSubmitUrl`) where an initially-plausible
  mechanism turned out to be the suite's own internal fixture; the
  same kind of surprise is possible here and hasn't been ruled out.
- The exact `client2` requirement, if any, for this specific plan
  variant (FAPIgo's own `client_credentials` conformance work found
  `client2` structurally required regardless of whether it's actually
  used — see FAPIgo's own `conformance/server/oidf-config/README.md`).

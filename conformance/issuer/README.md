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

## Open questions for the live run

- Whether `Config.OAuthOnly = true` is actually compatible with this
  plan's own `FAPIOpenIDConnect=plain_oauth` variant, or whether the
  suite's own conditions expect something more specific from a
  plain_oauth-profiled AS that this binary's minimal wiring doesn't
  yet provide.
- Whether the consent flow (a real rendered HTML form + POST
  submission) is compatible with how the suite drives this specific
  plan — mechanically proven to work end to end against a hand-rolled
  client (`flow_test.go`), but that's not proof the *suite's own*
  browser driver interacts with it the same way. Phase 1's own
  wallet-role research found at least one case
  (`CreateRandomBrowserApiSubmitUrl`) where an initially-plausible
  mechanism turned out to be the suite's own internal fixture; the
  same kind of surprise remains possible here.
- The exact `client2` requirement, if any, for this specific plan
  variant (FAPIgo's own `client_credentials` conformance work found
  `client2` structurally required regardless of whether it's actually
  used — see FAPIgo's own `conformance/server/oidf-config/README.md`).

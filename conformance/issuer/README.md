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

## Status: first live run against the real OIDF suite

Plan creation itself succeeded (`oid4vci-1_0-issuer-haip-test-plan`,
61 modules, `sd_jwt_vc` variant) once the plan config supplied: a
throwaway self-signed cert wrapping this binary's own credential-issuer
key (`credential.trust_anchor_pem`/`status_list_trust_anchor_pem`), a
*private* EC JWKS for `client_attestation.attester_jwks` (the suite
signs its own emulated Client Attestation JWTs with it — this binary's
own config registers the matching *public* half as
`client.attester_jwks`, the same "we generate one keypair, give the
suite the private half and ourselves the public half" pattern already
confirmed for `conformance-verifier`'s `credential.signing_jwk`), and a
second throwaway private JWKS for `client_attestation.key_attestation_jwks`.

Running the simplest module first (`oid4vci-1_0-issuer-metadata-test`,
no client authentication at all) surfaced a real, confirmed gap: this
binary's credential issuer metadata omits the OPTIONAL
`authorization_servers` field, so the suite falls back to RFC 8414
derivation from the credential issuer URL and requests
`GET /.well-known/oauth-authorization-server` — which 404s, since
`fapigo/server` only ever serves `/.well-known/openid-configuration`
(OIDC-flavored discovery). This plan's own `openid=plain_oauth` variant
(matching this binary's `Config.OAuthOnly = true`) is exactly the case
where a plain-OAuth-flavored well-known path would be expected instead
of (or in addition to) the OIDC one — this looks like a genuine
`fapigo/server` gap (it has no logic to serve the RFC 8414 path even
when `OAuthOnly` is set), the first time this exact combination
(`OAuthOnly` + a conformance suite expecting RFC 8414 discovery) has
been exercised in either repo. Not fixed here — this is a FAPIgo-side
question, matching this session's standing rule to flag rather than
work around FAPIgo-side gaps from inside OID4VCIgo.

This also settled the `client2` open question below: even the
plan's own `happy-flow` module (not just multi-client variants) lists
`client2.client_id`/`client2.scope`/`client2.jwks` in its own
`configurationFields` — confirming `client2` is structurally required
for this plan, matching FAPIgo's own `client_credentials` precedent.
Since `Config.Client` here is a single struct (`cmd/conformance-issuer/config.go`'s
own doc comment already flagged this as deliberately out of scope),
running `happy-flow` itself needs `Config`/`wiring.go` extended to
register a second attestation-authenticated client before it can be
attempted — a real, concrete piece of follow-up work, not yet started.

## Not yet run live

Every module past `metadata-test` (60 of 61, including `happy-flow`
and its own `metadata-test-signed` sibling) — blocked on the
`/.well-known/oauth-authorization-server` gap above for any module that
fetches AS metadata, and additionally on the `client2` wiring gap for
`happy-flow` itself. The consent-flow-compatibility and
`Config.OAuthOnly`-compatibility open questions originally listed here
remain unresolved, since no module reached that far yet.

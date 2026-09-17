# Conformance

OIDF live-conformance-suite harnesses for OID4VCIgo's own roles,
mirroring FAPIgo's own `conformance/` structure (binaries wiring the
real production package behind real HTTP, Docker attaching to the
suite's own network, `oidf-config/` per test plan, a generator script
producing throwaway key material rather than committing any). See the
approved roadmap for the full phased plan.

Conformance testing is tracked separately per role — passing one role's
plan says nothing about another's, even where both sides share this
repo's own JOSE/DCQL code, because the protocol behaviour and
negative-test expectations differ.

- **`verifier/`** — OID4VP 1.0 Final/HAIP Verifier role
  (`oid4vp-1final-verifier-haip-test-plan`): `cmd/conformance-verifier`
  stands up `verifier.Verifier` behind real HTTP; the suite plays
  Wallet. **Confirmed live against a real, locally-run OIDF suite, all
  12 in-scope modules correct** (7 positive-behavior modules succeed —
  including genuine `request_uri_method=post` support, not a
  self-skip — 5 negative-test modules correctly reject their malformed
  presentation). Found and fixed three real gaps along the way:
  `internal/jwe`'s Concat KDF never incorporated the sender's
  `apu`/`apv` header members, silently deriving the wrong CEK against
  the suite's own `direct_post.jwt` responses (which always set both);
  this binary's own Request Object signing certificate was self-signed
  (the suite's `ValidateRequestObjectSignatureAgainstX5cHeader` check
  rejects that outright, and it was silently failing on every module
  without affecting the suite's own summary counts); and
  `verifier.BuildAuthorizationRequest` never set `client_metadata`'s
  own `vp_formats_supported`, a field OID4VP marks REQUIRED here. See
  `verifier/README.md`.
- **`wallet-vp/`** — OID4VP 1.0 Final/HAIP Wallet role, direct_post.jwt
  module list only (`oid4vp-1final-wallet-haip-test-plan`):
  `cmd/conformance-wallet-vp` stands up `wallet`'s own presentation
  half behind real HTTP; the suite plays Verifier. Confirmed live end
  to end against `cmd/conformance-verifier` itself, and **all 14
  modules this binary's own scope can reach are now run live** (the
  other 2 are DC API/JAR-JSON-Serialization-only, correctly 404 for
  this variant). Five real gaps found and fixed along the way: the
  same x5c-header/self-signed-leaf pair already found for
  `credential/sdjwtvc.Issue`, two request-object validation gaps this
  binary's own `requestobject.go` had — a request carrying
  `redirect_uri` alongside `response_uri`, or an unrecognized
  `transaction_data` type, was silently ignored and this binary POSTed
  its response anyway instead of refusing the request — and, later,
  genuine `request_uri_method=post` support (a fresh `wallet_nonce`
  sent over POST, and the fetched Request Object rejected outright if
  its own `wallet_nonce` claim doesn't echo it back). All fixed and
  re-confirmed live: six positive-behavior modules clean
  (`FINISHED`/`PASSED` or `WARNING`, zero `FAILURE`s), seven of seven
  reachable negative tests correctly reject before ever calling
  `response_uri`. Its own three `dc_api.jwt` module lists are out of
  scope for this binary. See `wallet-vp/README.md`.
- **`issuer/`** — OID4VCI 1.0 Final/HAIP Issuer role
  (`oid4vci-1_0-issuer-haip-test-plan`): `cmd/conformance-issuer` pairs
  a real `fapigo/server.Server` (FAPI 2.0 Security Profile Final,
  Wallet Attestation client authentication) with a real
  `oid4vcigo/issuer.Issuer`; the suite plays Wallet. Confirmed live
  end to end in-repo (PAR → consent → token → nonce → credential),
  a permanent regression test that surfaced and fixed three real bugs.
  **Confirmed live against the real OIDF suite**: `metadata-test`
  is a full `PASSED` (fixed by serving this binary's AS metadata at
  both `/.well-known/openid-configuration` and RFC 8414's own
  `/.well-known/oauth-authorization-server` — entirely an
  OID4VCIgo-side router fix, not FAPIgo's). `client2` support was added
  (`Config.Client2`, optional) and confirmed both by a real PAR-
  authentication unit test and live against the suite itself.
  `happy-flow` hit a `fapigo/server` design decision (`Config.Extensions`
  rejecting any parameter without a pre-registered `Definition`) that
  conflicted with the suite's own PAR-2.1–PAR-2.4 check — raised with
  FAPIgo's maintainers as a design question rather than filed as a
  plain bug; they agreed and fixed it upstream (`fix!: ignore
  unrecognized authorization request parameters at PAR/CIBA`, FAPIgo
  PR #304). `go.mod` pinned to the fix; re-run live:
  `happy-flow` now completes. That full run surfaced one more real gap
  (the same x5c requirement `wallet-vp/README.md` already documents,
  this time in `issuer.SDJWTSigner`), fixed the same way. **All 21
  OID4VCI-specific modules in the plan are now run live** (the other
  40 are the generic FAPI 2.0 Security Profile Final battery, not yet
  attempted). Two more real gaps found and fixed: this binary's TLS
  listener had no `MinVersion`/`CipherSuites` set, so Go's own TLS 1.3
  default suite (always including ChaCha20-Poly1305) tripped the
  suite's own FAPI-RW-8.5 cipher probe — fixed by wiring in
  `fapigo/server.FAPIRWTLSCipherSuites`, the exact configuration
  FAPIgo's own OpenID-Certified `cmd/conformance-as` already uses; and
  a genuine RFC 9901 §10.1 linkability issue — two credentials issued
  moments apart (`happy-flow-multiple-clients`, one per client) carried
  `exp` values differing by the real inter-issuance gap, a correlation
  side-channel — fixed by rounding `exp` to the start of the issuance
  day (`internal/conformancecert.CredentialExp`). Both fixes apply
  everywhere `exp`/TLS are exercised, not just the module that caught
  them — re-confirmed live: every module that previously carried the
  `exp`-claim `WARNING` (`happy-flow` and its three siblings including
  `multiple-clients`, plus `fail-on-access-token-in-query`) is now
  `FINISHED`/`PASSED` with zero log entries at `WARNING` or worse.
  **Update: `metadata-test-signed` — real support added, not just made
  to pass.** Previously self-`SKIPPED` (HAIP §4.1 only conditions
  signed metadata on ecosystem policy, so it stayed genuinely
  optional); `credentialIssuerMetadataHandler` now does real content
  negotiation (OID4VCI §12.2.2/§12.2.3) — plain JSON by default,
  a signed compact JWS (`typ: "openidvci-issuer-metadata+jwt"`, every
  metadata parameter as a top-level claim, the same `x5c`/signing-key
  pair issued credentials use) when a request's `Accept` header asks
  for `application/jwt`. Confirmed live: `FINISHED`/`PASSED`, with the
  suite's own `VCIDecodeSignedCredentialIssuerMetadata` check
  independently verifying the JWS signature via its `x5c` header, not
  just the `Content-Type` header.
  **Update: `batch-issuance` — real support added, not just made to
  pass.** Previously self-`SKIPPED` (HAIP only requires *advertising*
  support, never a MUST to implement it); turned out
  `issuer.RequestCredential` already fully implements OID4VCI §3.3.2
  batch issuance — `cmd/conformance-issuer`'s own wiring just never
  opted in. `wiring.go` now sets `BatchCredentialIssuance` with a
  `batch_size` of 5. Confirmed live: `FINISHED`/`PASSED`, with the
  suite sending a real 5-proof batch and independently verifying
  distinct disclosure salts, distinct `cnf` binding keys each matching
  one of the sent proofs, and non-linkable time claims across all 5
  issued credentials — not just a metadata flag flip.
  **Update: `fail-unsupported-encryption-algorithm` — real support
  added, not just made to pass.** Previously self-`SKIPPED` (HAIP never
  references OID4VCI §10 encryption, so it stayed fully optional);
  turned out `issuer`'s own `DecryptRequestBody`/`EncryptResponseBody`
  already fully implement §10 — `wiring.go` now opts in
  (`A128GCM`/`A256GCM`, deliberately excluding `A192GCM` so
  "unsupported" stays real). Driving this live surfaced three more
  genuine, pre-existing gaps in the already-implemented `issuer`
  package, never exercised before this wiring made the code path
  reachable: `credential_request_encryption.jwks` was a bare array
  instead of a required JSON Web Key Set object; published keys had no
  `alg` member (§10 requires one); and `EncryptResponseBody` never
  validated a Wallet-declared `alg` mismatch in
  `credential_response_encryption.jwk`, silently encrypting anyway
  instead of rejecting it. Also fixed: every §10 failure used the
  generic `invalid_credential_request` code instead of §8.3.1.2's own
  dedicated `invalid_encryption_parameters`, which the suite
  specifically checks for. Confirmed live after all four fixes:
  `FINISHED`/`PASSED`, zero log entries at `WARNING` or worse, plus a
  genuine positive encrypt→issue→encrypt→decrypt round trip through
  the real HTTP binary (not just the library's own internals).
  **Final tally: all 21 modules `FINISHED`/`PASSED` or correctly
  `SKIPPED`** — 10 of 10 applicable negative tests `PASSED`, 1 module
  correctly self-`SKIPPED` (key-attestation, blocked on the still-
  unbuilt OID4VCI Wallet role). See `issuer/README.md`.
- **Not yet started**: an OID4VCI Wallet role conformance binary (a
  `cmd/conformance-wallet`, mirroring the shape of the other three
  binaries here). The FAPIgo-side blocker that previously prevented this
  entirely — Wallet Attestation client authentication had no client-side
  implementation — is resolved and proven end to end at the library level
  (`cmd/conformance-issuer`'s own `TestFullFlow_RealClientDrivesAttestationAuth`;
  see `AGENTS.md`), but building and running an actual conformance binary
  against the live OIDF suite's own OID4VCI Wallet test plan is separate,
  not-yet-started work.

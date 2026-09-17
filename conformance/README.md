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
  **Final tally: all 21 OID4VCI-specific modules `FINISHED`/`PASSED`
  or correctly `SKIPPED`** — 10 of 10 applicable negative tests
  `PASSED`, 1 module correctly self-`SKIPPED` (key-attestation, blocked
  on the still-unbuilt OID4VCI Wallet role).
  **Update: the plan's own 5th module-list entry, the generic FAPI2SP
  battery, is driven too** — 42 module instances (the exact 39+1
  battery+Discovery set, derived directly from the Java source, plus 2
  known-working sanity checks), via a new tool
  (`conformance/issuer/scripts/run-fapi2sp-battery`). Unlike the Wallet
  role, this role needs no custom flow-driving code at all — the suite
  itself plays client and drives PAR→authorize→consent→callback→token
  through its own internal headless browser, the same `browser`
  automation-config mechanism FAPIgo's own OpenID-Certified
  `cmd/conformance-as` already relies on. Surfaced and fixed real gaps:
  a missing `x5c` on the suite's own emulated Client Attestation
  signing key, a required-but-unused `status_list_trust_anchor_pem`
  field, and — the highest-value find — a universal, suite-side
  HtmlUnit/Bootstrap JS bug that leaves browser-driven modules
  `WAITING` forever with no timeout, needing the same
  `unblock-implicit-callback.py`-style workaround FAPIgo's own
  `cmd/conformance-as` already needs, now ported to Go. **All 42
  modules `FINISHED` twice in a row for stability**: `PASSED` except
  one expected `WARNING`, one expected `SKIPPED`, and one expected
  `REVIEW` (a human-review negative test) — no `FAILURE`s. See
  `issuer/README.md`.
- **`wallet/`** — OID4VCI 1.0 Final/HAIP Wallet role
  (`oid4vci-1_0-wallet-haip-test-plan`): `cmd/conformance-wallet`
  drives `oid4vcigo/wallet`/`fapigo/client` as an outbound HTTP client
  — the suite itself plays the entire emulated Authorization Server
  and Credential Issuer for this role, the opposite shape from
  `issuer/`. **Confirmed live against a real, locally-run OIDF suite,
  all 22 module instances this binary drives `FINISHED`/`PASSED`**:
  the 4 in-scope modules × all 3 issuance-mode/encryption crossings
  (12 module instances) — `credential-issuance`,
  `credential-issuance-notification`, `client-attestation-challenge`
  (proving FAPIgo PR #318's `client.ChallengeSource` against the
  suite's own independent Attestation Challenge Endpoint
  implementation, not just FAPIgo's own unit tests), and
  `batch-credential-issuance`, each crossed with `immediate`+`plain`,
  `deferred`+`plain` and `immediate`+`encrypted` — plus the HAIP plan's
  4th module-list entry, the generic FAPI2SP client conformance
  battery (10 more module instances, always at the fixed
  `immediate`+`plain` crossing). Driving the encrypted crossing
  surfaced a genuine pre-existing bug in `wallet` itself — its
  ephemeral response-decryption JWK never declared its own `alg`,
  which §8.2 requires — now fixed with a regression test. Driving the
  battery surfaced two more real findings, both in this binary: it
  needed real RFC 8414 discovery (FAPIgo's own `client.Discover` can't
  be used here — it speaks OIDC Discovery's own convention, and this
  suite explicitly test-fails that), used to both build endpoints and
  catch the suite's own issuer-mismatch negative test; and the battery
  never wires up the Attestation Challenge Endpoint at all (unlike the
  4 VCIWallet* modules), so this binary now only opts into
  `client.ChallengeSource` for the modules that actually implement it.
  **Update: HAIP §4.5.1's Key Attestation (Appendix D) requirement is
  now driven too, both ways OID4VCI conveys it — confirmed live, all
  22 module instances `FINISHED`/`PASSED` for each, via a new
  `-proof-type` flag: `attestation` submits a standalone Key
  Attestation JWT as its own proof type (Appendix F.3); `jwt-key-attestation`
  nests one inside an ordinary jwt-type proof's own header (Appendix
  D.1).** Turned out nothing needed building for the standalone case:
  both `wallet.Wallet.GenerateAttestationProof` and the whole
  `oid4vcigo/attestation` package already fully implemented Key
  Attestation JWT issuance (OID4VCI Appendix D.1) — this binary's own
  `keyattestation.go` just had to mint one (a new dedicated CA/leaf,
  `client_attestation.key_attestation_trust_anchor_pem`) and submit it.
  `AGENTS.md`'s prior "nothing implements this yet" note predated that
  package landing and has been corrected. The nested case needed one
  small new `wallet` primitive, `GenerateProofWithKeyAttestation`
  (`wallet/proof.go`), plus a design choice for the batch module
  driven by reading the suite's own validation source rather than a
  failed run: one Key Attestation JWT naming every key in the batch,
  embedded identically in every proof, rather than one attestation per
  proof — see `wallet/README.md`'s own "Status" section for why.
  **Update: the `issuer_initiated` flow variant is driven too**
  (`-issuer-initiated`) — confirmed live, all 22 module instances
  `FINISHED`/`PASSED`. Turned out this binary never needs to receive an
  inbound request at all: the suite's own headless browser only
  dispatches to a URL when the plan config declares a matching
  automation script, which this binary doesn't, so it just queues the
  Credential Offer redirect URL — already fully resolved, `issuer_state`
  included — in the module's own `/api/log`, which this binary now
  simply polls. Driving this also surfaced a real, general bug in
  `fapigo/client`, not this binary: echoing back an offer's own
  `issuer_state` as a PAR extension broke every time PAR needed to
  retry on a DPoP nonce challenge, because `buildPushedRequestForm`
  mutated its caller's own shared `params` map — fixed upstream
  ([FAPIgo PR #322](https://github.com/IDFoundry/FAPIgo/pull/322),
  merged, `go.mod` pinned past it). `issuer_initiated_dc_api` isn't
  covered — same Digital Credentials API browser-JS scope cut as
  `cmd/conformance-wallet-vp`'s own `dc_api.jwt` module lists. See
  `wallet/README.md`.

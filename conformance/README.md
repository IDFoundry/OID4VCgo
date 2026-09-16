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
  OID4VCIgo-side router fix, not FAPIgo's), `metadata-test-signed`
  correctly self-`SKIPPED`. `client2` support was added
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
  **Final tally: all 21 modules `FINISHED`/`PASSED` or correctly
  `SKIPPED`** — 10 of 10 applicable negative tests `PASSED`, 3 modules
  correctly self-`SKIPPED` (signed metadata, batch issuance, key-
  attestation/encryption-algorithm features this binary doesn't
  implement). See `issuer/README.md`.
- **Not yet started**: OID4VCI Wallet role (blocked on a FAPIgo-side
  change — see `AGENTS.md`).

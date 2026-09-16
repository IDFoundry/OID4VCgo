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
  Wallet. Code written, unit-tested, and smoke-tested locally (the full
  Authorization Request → request_uri → response flow works end to
  end against a hand-rolled client); **not yet run against the live
  suite** — that's the next step once Docker is available. See
  `verifier/README.md`.
- **`wallet-vp/`** — OID4VP 1.0 Final/HAIP Wallet role, direct_post.jwt
  module list only (`oid4vp-1final-wallet-haip-test-plan`):
  `cmd/conformance-wallet-vp` stands up `wallet`'s own presentation
  half behind real HTTP; the suite plays Verifier. Confirmed live end
  to end against `cmd/conformance-verifier` itself (a real
  cryptographic round trip, now a permanent regression test) — **not
  yet run against the live OIDF suite**. Its own three `dc_api.jwt`
  module lists are out of scope for this binary. See
  `wallet-vp/README.md`.
- **`issuer/`** — OID4VCI 1.0 Final/HAIP Issuer role
  (`oid4vci-1_0-issuer-haip-test-plan`): `cmd/conformance-issuer` pairs
  a real `fapigo/server.Server` (FAPI 2.0 Security Profile Final,
  Wallet Attestation client authentication) with a real
  `oid4vcigo/issuer.Issuer`; the suite plays Wallet. This is the first
  real exercise anywhere of `AttestationBasedClientAuthentication` and
  of `issuer/resource_verifier.go`'s own recipe. Confirmed live end to
  end: PAR → consent → token → nonce → credential, with a real Client
  Attestation + PoP JWT pair and DPoP throughout — a permanent
  regression test. That test surfaced and fixed three real bugs (two
  missing header forwards, one DPoP "htu" URL bug) — see
  `issuer/README.md`'s own "Status" for the details. **Not yet run
  against the live OIDF suite.**
- **Not yet started**: OID4VCI Wallet role (blocked on a FAPIgo-side
  change — see `AGENTS.md`).

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
  Wallet. **Confirmed live against a real, locally-run OIDF suite,
  all 11 in-scope modules correct** (5 positive-behavior modules
  succeed, 5 negative-test modules correctly reject their malformed
  presentation, 1 self-skips as designed). Found and fixed one real
  interop bug along the way: `internal/jwe`'s Concat KDF never
  incorporated the sender's `apu`/`apv` header members, silently
  deriving the wrong CEK against the suite's own
  `direct_post.jwt` responses (which always set both). See
  `verifier/README.md`.
- **`wallet-vp/`** — OID4VP 1.0 Final/HAIP Wallet role, direct_post.jwt
  module list only (`oid4vp-1final-wallet-haip-test-plan`):
  `cmd/conformance-wallet-vp` stands up `wallet`'s own presentation
  half behind real HTTP; the suite plays Verifier. Confirmed live end
  to end against `cmd/conformance-verifier` itself, and **confirmed
  live against the real OIDF suite's own `happy-flow` module**. Found
  and fixed two real gaps along the way: `credential/sdjwtvc.Issue` had
  no `x5c` header support at all (HAIP's own SD-JWT VC trust model
  requires it), and once added, the suite additionally rejected a
  self-signed leaf (HAIP wants the leaf issued by a separate CA). Both
  fixed (`sdjwtvc.IssueOptions.IssuerCertificate`,
  `internal/conformancecert.GenerateCA`/`IssueLeafCertPEM`) and
  re-confirmed live: zero x5c-related failures remain. Its own three
  `dc_api.jwt` module lists are out of scope for this binary. See
  `wallet-vp/README.md`.
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
  `happy-flow` now reaches real PAR traffic before hitting a new,
  likely genuine `fapigo/server`-side gap: it rejects a PAR request
  carrying one deliberately-unrecognized extra parameter outright,
  where RFC 9126/6749 expect the parameter to be silently ignored —
  not fixed here, flagged the same way the Wallet-role FAPIgo
  dependency already is (see `AGENTS.md`). See `issuer/README.md`.
- **Not yet started**: OID4VCI Wallet role (blocked on a FAPIgo-side
  change — see `AGENTS.md`).

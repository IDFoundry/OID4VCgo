# Agent guidance

This file is for AI coding agents working in this repo. It doesn't replace
[CONTRIBUTING.md](CONTRIBUTING.md) — read that first for the
conformance-first philosophy, commit message format, and pre-PR checklist.
This file adds agent-specific process notes.

## Workflow

- Never push directly to `main`, even if asked to just "push" — always
  work on a feature branch, open a PR, and wait for CI to go green before
  merging.
- Only sync a local `main` after the user has confirmed the PR is actually
  merged (e.g. via `gh pr view <n> --json state,mergedAt`) — don't assume,
  and don't merge a PR yourself unless explicitly told to.
- This repo uses [release-please](https://github.com/googleapis/release-please):
  every commit message must be a real [Conventional Commits](https://www.conventionalcommits.org/)
  type (`fix:`, `feat:`, `feat!:`/`fix!:` for breaking, or `docs:`/
  `chore:`/`test:`/`refactor:`/`ci:` for anything that shouldn't bump the
  version) — see CONTRIBUTING.md's "Commit messages" section. Don't invent
  non-standard types.
- Merging a PR here triggers an automatic release-please PR bumping the
  version and `CHANGELOG.md` — that PR needs its own merge before the new
  version is actually cut/tagged.
- Write PR descriptions (and commit messages) as a focused summary of what
  changed and why — never narrate the conversation that produced it.

## Relationship to FAPIgo

OID4VCIgo is a sister library to [FAPIgo](https://github.com/IDFoundry/FAPIgo)
(`go-fapi` in this checkout's sibling directory), reusing FAPIgo's public
`server`/`client`/`keys`/`storage`/`fapihttp` packages for the FAPI 2.0
Security Profile Final machinery HAIP requires (PAR, DPoP, PKCE S256, `iss`
in the authorization response, RFC 8414 metadata). It cannot import
FAPIgo's `internal/` packages — that's a real Go module boundary, not a
style choice — so anything OID4VCIgo needs from FAPIgo's protocol core must
already be, or become, one of FAPIgo's public packages.

One specific, partially-blocking dependency: HAIP requires Wallet
Attestation (a client-attestation-JWT-based OAuth2 client authentication
mechanism, [`draft-ietf-oauth-attestation-based-client-auth-07`](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07))
in place of FAPI 2.0's normal `private_key_jwt`/mTLS client auth. FAPIgo's
`server` side already supports this — `storage.ClientAuthMethodAttestation`
plus `server.Config.AttestationBasedClientAuthentication` — so an
Authorization Server pairing with `issuer` can verify an incoming Wallet
Attestation today. What's still missing is the *client* side:
`fapigo/client` has no logic of its own to construct or send the Client
Attestation + PoP JWT pair when driving the Authorization Code Flow (see
`wallet/doc.go`'s own note on this) — that half is tracked as its own
change in FAPIgo, not this repo. Don't attempt to work around it by
duplicating client-authentication logic against `fapigo/client`'s
internals; wait for or contribute to the FAPIgo-side change instead.

See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the exact spec/draft
versions this repo targets, and [ARCHITECTURE.md](ARCHITECTURE.md) for
package layout and design rationale as it's built out.

## Where conformance-suite knowledge lives

[`conformance/README.md`](conformance/README.md) — mirrors FAPIgo's own
`conformance/*/README.md` documentation convention. All three binaries
(`cmd/conformance-verifier`, `cmd/conformance-wallet-vp`,
`cmd/conformance-issuer`) exist, compile, are unit-tested, and have now
been run against a real, locally-run OIDF conformance suite instance —
not just against each other. `conformance-verifier`'s own
`oid4vp-1final-verifier-haip-test-plan` is a full confirmed pass, all
11 in-scope modules. `conformance-wallet-vp`'s own `happy-flow` module
passes every cryptographic check. `conformance-issuer`'s own
`oid4vci-1_0-issuer-haip-test-plan` metadata modules pass, and its
`happy-flow` module now runs to completion (`FINISHED`, result
`WARNING`, zero `FAILURE`s). It was blocked on `fapigo/server`'s own
`Config.Extensions` (an `*extension.Registry`) rejecting any
authorization parameter without a pre-registered `extension.Definition`
— the OIDF suite's own PAR-2.1–PAR-2.4 check sends one randomly-named
extra parameter expecting it to be silently ignored (RFC 9126/6749),
which this design couldn't accommodate. Raised with FAPIgo's
maintainers as a design question rather than filed as a plain bug;
they agreed and shipped `fix!: ignore unrecognized authorization
request parameters at PAR/CIBA` (FAPIgo PR #304, commit `597f2a7`) — an
unregistered parameter is now silently dropped instead of failing the
request. `go.mod` is pinned to this exact commit (no tagged release
yet). This is the pattern this file's own "flag it, don't reach into
`fapigo/server` internals" boundary is meant to enable: OID4VCIgo
surfaces a real cross-repo finding via a live conformance run, FAPIgo's
own maintainers decide and fix it upstream, OID4VCIgo pins and
re-verifies — not something to work around locally. See
`conformance/verifier/README.md`'s, `conformance/wallet-vp/README.md`'s
and `conformance/issuer/README.md`'s own "Status" sections for the
full detail before assuming any specific suite test module passes.

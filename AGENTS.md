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
`conformance/*/README.md` documentation convention. As of this note,
`cmd/conformance-verifier` (OID4VP Verifier role) and
`cmd/conformance-wallet-vp` (OID4VP Wallet role, direct_post.jwt module
list only) exist, compile, are unit-tested, and have been confirmed
live against each other end to end (a real cryptographic round trip,
not a mock). `cmd/conformance-issuer` (OID4VCI Issuer role — a real
`fapigo/server.Server` with `AttestationBasedClientAuthentication`
enabled, paired with a real `issuer.Issuer`) also exists, compiles, and
is confirmed live end to end (PAR → consent → token → nonce →
credential, with a real Client Attestation + PoP JWT pair and DPoP
throughout) — that test surfaced and fixed three real bugs along the
way, see `conformance/issuer/README.md`'s own "Status". None of the
three binaries has been run against the live OIDF suite itself. See
`conformance/verifier/README.md`'s, `conformance/wallet-vp/README.md`'s
and `conformance/issuer/README.md`'s own "Status" sections before
assuming any specific suite test module passes.

# Contributing

OID4VCIgo implements OpenID4VCI 1.0 and OpenID4VP 1.0 under the HAIP 1.0
profile — a conformance-first library, not a best-effort implementation.
Its design decisions trace back to specific requirements in OID4VCI,
OID4VP, HAIP, or a spec HAIP pulls in (FAPI 2.0 Security Profile Final,
the attestation/status-list/SD-JWT-VC Internet-Drafts HAIP pins — see
[SPECIFICATIONS.md](SPECIFICATIONS.md) for the exact versions), and its
real correctness bar is the OpenID Foundation conformance suite, not just
this repo's own unit tests — see [FAPIgo's own CONTRIBUTING.md](https://github.com/IDFoundry/FAPIgo/blob/main/CONTRIBUTING.md)
for how that plays out in practice on the sister library this one builds on.

**Open an issue before writing a PR**, for anything beyond a trivial fix (a
typo, an obviously-wrong comment). A change that looks reasonable in
isolation can conflict with a spec requirement, an existing design rule
(see [ARCHITECTURE.md](ARCHITECTURE.md)), or conformance-suite behavior
that isn't obvious from the code alone — discussing the approach first
avoids a PR, and the work behind it, being reworked or rejected after the
fact.

## What "conformance-first" means here

- Every design rule in [ARCHITECTURE.md](ARCHITECTURE.md) exists for a
  reason — read it before changing package structure, adding a shared
  abstraction across roles, or relaxing a validation.
- A change to `issuer`, `wallet`, `verifier`, `credential`, `attestation`,
  or `statuslist` that touches actual protocol behavior should be checked
  against the relevant spec section (OID4VCI, OID4VP, or HAIP's override
  of either) and, once a conformance harness exists here, against the real
  OIDF HAIP conformance suite before it's proposed as done. "It passes the
  Go test suite" isn't the same claim as "it's HAIP conformant."
- A change that depends on FAPIgo behavior belonging to `server`/`client`/
  `keys`/`storage` (not this repo) — most notably Wallet Attestation client
  authentication — belongs in FAPIgo itself; see ARCHITECTURE.md for the
  current split.

## Commit messages

This repo merges PRs as regular merge commits, not squash — every commit
lands in history exactly as written, so **every commit message, not just
the PR title,** must follow [Conventional Commits](https://www.conventionalcommits.org/):
`fix: …`, `feat: …`, `feat!: …`/`fix!: …` for a breaking change, or another
standard type (`docs:`, `chore:`, `test:`, `refactor:`, `ci:`) for anything
that shouldn't bump the version at all. [release-please](https://github.com/googleapis/release-please)
reads these to compute the next version and `CHANGELOG.md` entry
automatically — see `release-please-config.json` and
`.github/workflows/release-please.yml`. OID4VCIgo is pre-1.0
(`bump-minor-pre-major`), so a breaking `feat!:`/`fix!:` bumps `0.x.0`,
not straight to `1.0.0` — that jump is a deliberate, manual decision, not
something a commit message alone should trigger.

## Before you open a PR

- `gofmt -l .`, `go vet ./...`, `go build ./...`, `go test -race ./...`,
  `golangci-lint run ./...` (config in `.golangci.yml`), and
  `govulncheck ./...` all need to be clean — this is what `ci.yml` enforces
  on every PR.
- Include tests for the behavior you're changing, not just the happy path.

## Reporting a security issue

Don't open a public issue or PR for a vulnerability — see
[SECURITY.md](SECURITY.md) for private disclosure.

## Maintainers: the release-please token

`.github/workflows/release-please.yml` needs a `RELEASE_PLEASE_TOKEN` repo
secret — a personal access token, not the default `GITHUB_TOKEN`, so the
release PR it opens actually triggers `ci.yml` on itself. A fine-grained
PAT scoped to this repo only, with **Contents: Read and write** and
**Pull requests: Read and write**, is enough.

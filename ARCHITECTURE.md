# Architecture

> **Status: early scaffolding.** No protocol packages exist yet — this
> document describes the planned layout and the design rules carried over
> from FAPIgo, not a finished system. Update each section as the
> corresponding package actually lands; don't let this drift into
> aspirational documentation for code that doesn't exist.

## Scope

OID4VCIgo implements the full [HAIP 1.0](SPECIFICATIONS.md) profile: both
its issuance half (OID4VCI 1.0, HAIP §4) and its presentation half
(OID4VP 1.0, HAIP §5). See [SPECIFICATIONS.md](SPECIFICATIONS.md) for the
exact spec and Internet-Draft versions this targets.

## Relationship to FAPIgo

HAIP requires compliance with the applicable provisions of FAPI 2.0
Security Profile Final, with specific overrides (DPoP mandatory, PAR only
where the Authorization Endpoint is used, Wallet Attestation in place of
`private_key_jwt`/mTLS client auth, HAIP §7's own algorithm requirements —
see SPECIFICATIONS.md's "HAIP's deviations from plain FAPI 2.0"). OID4VCIgo
does not reimplement PAR, DPoP, PKCE, or JARM-style protocol plumbing — it
consumes FAPIgo's public `server`/`client` role packages for that, and
`keys` (KeyManager/Decrypter, purpose-based Sign — no raw private keys ever
cross a package boundary) for every signing operation this repo needs
beyond what `server`/`client` already do internally (key attestation,
Wallet Attestation extra claims, status-list signing, SD-JWT VC key
binding).

OID4VCIgo cannot import `go-fapi/internal/*` — Go's `internal/` visibility
rule is scoped to the importing path's own module tree, and this is a
separate module (`github.com/idfoundry/oid4vcigo` vs.
`github.com/idfoundry/fapigo`) even though both live under the same GitHub
org. Anything this repo needs from FAPIgo's protocol core has to already
be, or become, one of FAPIgo's *public* packages (`server`, `client`,
`resource`, `keys`, `storage`, `fapihttp`, `extension`, the root `fapigo`
value types) — never a reason to vendor or reimplement FAPIgo's internals
here instead.

## Planned package layout

None of these exist yet; this is the target shape from the phase-by-phase
plan, not a description of current code.

- **`credential`** — a format-profile interface (encode/decode, selective
  disclosure, holder-binding, proof types), implemented by:
  - **`credential/sdjwtvc`** — SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-11`):
    disclosures, KB-JWT, `vct`.
  - **`credential/mdoc`** — ISO/IEC 18013-5 mdoc: CBOR/COSE
    `IssuerSigned`/`DeviceSigned` structures.
- **`statuslist`** — Token Status List (`draft-ietf-oauth-status-list-12`):
  issuance (bit-packed status list JWT) and status checking. Depended on by
  `credential/sdjwtvc`'s optional `status` claim and by Wallet Attestation.
- **`attestation`** — OID4VCI Appendix D (Key Attestation) and the
  OID4VCI-specific claims on top of FAPIgo's Wallet Attestation client-auth
  mechanism (Appendix E extra claims, not the base client-authentication
  handshake itself — that lives in FAPIgo).
- **`issuer`** — the OID4VCI Credential Issuer role (server side): Issuer
  Metadata, Credential Offer, Nonce endpoint, Credential Endpoint (batch,
  `jwt`/`attestation` proof types, dispatches into `credential/*`),
  Deferred + Notification endpoints. Built on `fapigo/server`.
- **`wallet`** — the Wallet's OID4VCI role (client side): credential-offer
  resolution, proof-of-possession generation, deferred/notification
  handling. Built on `fapigo/client`.
- **`verifier`** — the OID4VP Verifier role: DCQL query construction,
  Authorization Request via JAR, response modes (`direct_post`,
  `direct_post.jwt`, DC API), response verification.
- **`wallet`** (extended) or a distinct presentation package — the
  Wallet's OID4VP role: DCQL evaluation against held credentials, VP Token
  construction per format. Naming TBD once `verifier` exists and the
  shared/duplicated surface with the OID4VCI wallet role is clearer.
- **`haip`** — the profile layer: `RecommendedIssuerConfig()`,
  `RecommendedWalletConfig()`, `RecommendedVerifierConfig()` wiring HAIP's
  specific overrides on top of `issuer`/`wallet`/`verifier` — mirrors
  FAPIgo's `server.RecommendedLimits()`/`RecommendedAlgorithms()` pattern:
  every value traceable to a specific HAIP section.
- **`storage`** — reference in-memory implementations (credential-offer
  state, deferred transactions) for local dev/testing only, mirroring
  FAPIgo's `storage/memstore`.
- **`conformance`** — OIDF HAIP conformance suite harness, once one of the
  protocol packages above is far enough along to run against it. Mirrors
  FAPIgo's `conformance/` structure and its own AGENTS.md documentation
  convention.

## Design rules carried over from FAPIgo

These are the rules FAPIgo's own ARCHITECTURE.md establishes that this
repo inherits by construction (building on FAPIgo's role split); restate
them here as OID4VCIgo-specific packages land, don't assume they transfer
automatically to code they didn't originally govern:

- Independent public packages per role (`issuer`/`wallet`/`verifier`), no
  generic type that tries to behave as more than one role.
- No implicit defaults; closed sum types over optional fields where a spec
  defines a fixed set of choices (e.g. proof types, credential formats).
- A `KeyManager`/`Decrypter`-shaped interface for every signing/decryption
  operation — never a raw `crypto.Signer`/private key held or passed
  directly — so this repo stays HSM/KMS-compatible the same way FAPIgo is.
- **Shared public value types only where semantics match**: the root
  `oid4vci` package (see its own doc comment) holds a type only once two
  or more role packages need the exact same wire semantics for it — never
  speculatively, and never a workflow or configuration type whose meaning
  differs between, say, a credential request a wallet is about to send and
  one an issuer has already validated. Those stay in their respective role
  packages.

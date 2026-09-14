# Architecture

> **Status: early scaffolding.** `credential/sdjwtvc` (SD-JWT VC issuance,
> presentation and verification, including Key Binding), `statuslist`
> (Token Status List issuance and checking), `attestation` (Key
> Attestation, and the OID4VCI-specific extra claims on top of FAPIgo's
> Wallet Attestation), the `internal/jose` JWS helper the first three
> build on, and a first slice of `issuer` (Nonce Endpoint + a Metadata
> shape covering what SD-JWT VC issuance needs) are implemented and
> tested; everything else below is still just the planned layout, not a
> finished system. Update each section as the corresponding package
> actually lands; don't let this drift into aspirational documentation
> for code that doesn't exist.

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
see SPECIFICATIONS.md's "HAIP's deviations from plain FAPI 2.0"). `issuer`
does not reimplement PAR, DPoP, PKCE, or JARM-style protocol plumbing —
it will consume FAPIgo's public `server`/`client` role packages for that,
once its own endpoints reach the ones OID4VCI actually relies on FAPI 2.0/
OAuth 2.0 for (PAR, the Authorization/Token Endpoints, client
authentication). `go.mod` depends on FAPIgo directly as of this package
(pinned to a specific commit via a pseudo-version, not yet a tagged
release — see the PR that added it for why); `issuer`'s first slice
(Nonce Endpoint + Metadata) doesn't touch `fapigo/server` at all yet, only
the root `fapi` package's `URL`/`ParseIssuerURL`/`ParseEndpointURL` for
issuer/endpoint identifiers, the same "shared value type with identical
semantics" reasoning that package documents itself.

OID4VCIgo cannot import `go-fapi/internal/*` — Go's `internal/` visibility
rule is scoped to the importing path's own module tree, and this is a
separate module (`github.com/idfoundry/oid4vcigo` vs.
`github.com/idfoundry/fapigo`) even though both live under the same GitHub
org. Anything this repo needs from FAPIgo's protocol core has to already
be, or become, one of FAPIgo's *public* packages (`server`, `client`,
`resource`, `keys`, `storage`, `fapihttp`, `extension`, the root `fapigo`
value types) — never a reason to vendor or reimplement FAPIgo's internals
here instead.

**`keys.KeyManager` turned out not to be reusable for credential-level
signing.** Its `SigningPurpose` is a closed `iota` enum defined entirely
inside FAPIgo (`keys/signing.go`) — `SigningRequest.Purpose` is typed to
it directly, so OID4VCIgo cannot construct a request for a purpose FAPIgo
hasn't defined (credential signing, Key Binding JWT signing, key/wallet
attestation signing). Rather than block `credential/sdjwtvc` on a
FAPIgo change, it signs and verifies through this repo's own
`internal/jose` (RFC 7515 compact JWS, ES256 + EdDSA for now) against a
plain `crypto.Signer` instead. This is a real, deliberate divergence from
"reuse FAPIgo's `keys` package everywhere" — revisit it if/when FAPIgo
grows the purposes credential issuance needs, but don't assume that will
happen automatically; someone has to decide it's worth another
cross-repo change.

`storage.ClientAuthMethod` had the identical closed-enum problem for
Wallet Attestation client authentication — that one *was* worth a
cross-repo change: FAPIgo now has `storage.ClientAuthMethodAttestation`
and `internal/clientattestation` (draft-07 Client Attestation + PoP JWT
verification), gated behind `server.Config.AttestationBasedClientAuthentication`
(default off). `attestation` (below) builds the OID4VCI-specific pieces
on top of that — Key Attestation is fully self-contained here since
FAPIgo has no reason to know about it at all, while the Wallet Attestation
extra claims (`wallet_name`/`wallet_link`/`status`) needed their own
reader in this repo because FAPIgo's `clientattestation.VerifiedAttestation`
only exposes `ClientID`/`ExpiresAt`/`ConfirmationJWK` — it discards every
claim it doesn't itself model, the OID4VCI-specific ones included.

## Planned package layout

Only `credential/sdjwtvc`, `statuslist`, `attestation`, `internal/jose`
and a first slice of `issuer` exist so far; the rest below is the target
shape from the phase-by-phase plan, not a description of current code.

- **`credential/sdjwtvc`** (done) — SD-JWT VC (`draft-ietf-oauth-sd-jwt-vc-11`)
  on top of base SD-JWT (RFC 9901): `Issue`/`Verify`, `SD`/`SDElement`
  markers with full recursive-disclosure support, `Parse`/`Presentation`,
  and Key Binding JWT creation/verification. Its tests include RFC 9901's
  own known-answer disclosure/digest vectors, not just round-trip checks.
  There's deliberately no separate `credential` package defining a
  format-profile interface yet — with only one format implemented, any
  interface here would be guessed, not derived from real commonality.
  Add it once `credential/mdoc` exists and the two can be compared.
- **`credential/mdoc`** — ISO/IEC 18013-5 mdoc: CBOR/COSE
  `IssuerSigned`/`DeviceSigned` structures.
- **`statuslist`** (done) — Token Status List (`draft-ietf-oauth-status-list-12`),
  JWT/JOSE encoding only (§5.1, §6.2 — not the CWT/COSE encoding, which
  belongs with `credential/mdoc`): bit-packing and ZLIB compression
  (`Pack`/`Unpack`, `New`/`Decode`), Status List Token issuance/verification
  (`IssueToken`/`VerifyToken`), the Referenced Token `status` claim
  (`StatusListRef`/`ParseStatusClaim` — the same `map[string]any` shape
  `credential/sdjwtvc`'s `Claims.Status` expects, and covered by a test
  that wires the two packages together), and `Check`, the §8.3 steps 3-7
  orchestration. Tests include draft-12 §4.1's own known-answer bit-packing
  vectors and its Appendix's 2^20-entry compressed vector, not just
  round-trip checks. Built on `internal/jose` for the same
  `keys.KeyManager`-isn't-reusable reason `credential/sdjwtvc` is.
- **`attestation`** (done) — OID4VCI Appendix D, Key Attestation: fully
  self-contained `Issue`/`Parse`/`Verify`, plus `VerifiedClaims.KeyAttested`
  implementing Appendix D.1's own MUST ("the Credential Issuer MUST
  validate that the JWT used as a proof is signed by a key contained in
  the attestation") via a minimal JWK marshal/match for the two key types
  `internal/jose` supports (P-256 EC, Ed25519 OKP). Also Appendix E's
  three OID4VCI-specific Wallet Attestation claims
  (`ParseWalletAttestationClaims`) — deliberately *not* the base
  Client Attestation JWT handshake itself, which lives in FAPIgo's
  `internal/clientattestation` (see "Relationship to FAPIgo" above for
  why this package only reads claims FAPIgo's own verification discards,
  never re-verifies a signature FAPIgo already checked). Tests include
  OID4VCI 1.0's own Appendix D.1 and Appendix E worked examples.
- **`issuer`** (in progress) — the OID4VCI Credential Issuer role (server
  side). Done so far: `Config`/`Dependencies`/`New` (mirrors
  `fapigo/server.Config`/`server.New`'s own shape — required fields, no
  implicit defaults, an opt-in-gated Nonce Endpoint the same way
  FAPIgo gates CIBA on `Endpoints.BackchannelAuthentication` being set);
  `NonceStore`/`RequestNonce` implementing the Nonce Endpoint (§7),
  mirroring `fapigo/storage.NonceStore`'s own Issue/Consume,
  single-use-on-consume shape exactly; and `Metadata` (§12.2.4) covering
  `credential_issuer`, `credential_endpoint`, `nonce_endpoint`, and
  `credential_configurations_supported` with `format`/`scope`/
  `cryptographic_binding_methods_supported`/`proof_types_supported`
  (including `key_attestations_required`) — deliberately not yet
  `credential_request_encryption`/`credential_response_encryption`,
  `batch_credential_issuance`, `display`, or `credential_metadata`;
  add each when a concrete consumer needs it, not speculatively. Still
  to come: Credential Offer Endpoint (§4), the Credential Endpoint (§8,
  batch issuance, `jwt`/`attestation` proof types dispatching into
  `credential/sdjwtvc` and `attestation`), Deferred (§9) and
  Notification (§11) Endpoints — once those exist, this is where
  `fapigo/server` actually gets consumed (client authentication via PAR/
  Token, access-token validation for the Credential Endpoint).
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
- Never hold or pass a raw private key across a package boundary. Where
  FAPIgo's `keys.KeyManager` is reusable (once `issuer`/`wallet` sit on
  `fapigo/server`/`client`), use it; where it isn't — see "`keys.KeyManager`
  turned out not to be reusable for credential-level signing" above —
  `internal/jose`'s `crypto.Signer` parameter is the equivalent boundary:
  a caller adapts whatever backs its key (a static key, an HSM, a future
  KeyManager-based adapter) into that one standard interface, never a
  bare private key value passed around directly.
- **Shared public value types only where semantics match**: the root
  `oid4vci` package (see its own doc comment) holds a type only once two
  or more role packages need the exact same wire semantics for it — never
  speculatively, and never a workflow or configuration type whose meaning
  differs between, say, a credential request a wallet is about to send and
  one an issuer has already validated. Those stay in their respective role
  packages.

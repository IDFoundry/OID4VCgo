# Architecture

> **Status: early scaffolding.** `credential/sdjwtvc` (SD-JWT VC issuance,
> presentation and verification, including Key Binding), `credential/mdoc`
> (ISO/IEC 18013-5 mdoc, both roles: IssuerSigned/MSO/IssuerAuth on the
> issuer side, DeviceSigned/mdoc authentication on the Holder side),
> `statuslist` (Token Status List issuance and checking, both the JWT and
> CWT encodings), `attestation` (Key Attestation, and the OID4VCI-specific
> extra claims on top of FAPIgo's Wallet Attestation), the `internal/jose`
> JWS helper `credential/sdjwtvc`/`statuslist`/`attestation` build on,
> `internal/cose` (COSE_Sign1 and COSE_Mac0 signers/verifiers, the same
> role for `credential/mdoc` and `statuslist`'s CWT encoding),
> `internal/hkdf` (RFC 5869, for `credential/mdoc`'s DeviceMac key
> derivation), `internal/jwk` (JWK marshal/parse, shared by `attestation`
> and `issuer`), and `issuer` (Nonce Endpoint, Metadata, and the
> Credential Endpoint for immediate issuance of both formats) are
> implemented and tested; everything else below is still just the
> planned layout, not a finished system. Update each section as the
> corresponding package
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
  There's deliberately still no separate `credential` package defining a
  format-profile interface: now that `credential/mdoc` also exists, the
  two formats' `Issue`/`Verify` shapes are similar (signer/alg/claims/opts
  in, an issued artifact and a verified-claims value out) but not
  identical enough (JWS-compact string vs. a Go struct plus a separate
  `Marshal`; CBOR's namespace-scoped digest IDs have no SD-JWT VC
  analog) to derive a real interface from yet — revisit once a third
  format or an actual multi-format caller (`issuer`) needs one, rather
  than guessing at the shape now.
- **`internal/cose`** (done) — small, self-contained COSE_Sign1 (RFC 9052
  §4.2) and COSE_Mac0 (RFC 9052 §6.2) signers/verifiers, the CBOR/COSE
  equivalent of `internal/jose`: same curated algorithm set for signing
  (ES256, EdDSA) plus HMAC256 ("HMAC 256/256") for MACing, same
  `Sign`/`Verify`/`DecodeUnverified` shape, but with COSE's
  protected/unprotected header split (`Headers{Alg,KID,Typ,X5Chain}`)
  instead of JOSE's single header object. Handles the untagged COSE_Sign1
  form (matching mdoc's own `IssuerAuth = COSE_Sign1` CDDL) via
  `Sign`/`Verify`/`DecodeUnverified`; `COSE_Sign1_Tagged`
  (`#6.18(COSE_Sign1)`, which `statuslist`'s CWT-format Status List Token
  uses) via `SignTagged`/`VerifyTagged`/`DecodeUnverifiedTagged`; a
  detached COSE_Sign1 payload (mdoc's DeviceSignature, §12.4.6) via
  `SignDetached`/`VerifyDetached`; and COSE_Mac0 (mdoc's DeviceMac,
  §12.4.5, always detached — no embedded-payload form exists here) via
  `ComputeMAC`/`VerifyMAC`. Built on `github.com/fxamacker/cbor/v2` for
  raw CBOR encoding — Go's stdlib has none, and this is the repo's first
  non-FAPIgo dependency; hand-rolling CBOR itself was ruled out as
  materially riskier than hand-rolling JWS was (CBOR's major-type/
  indefinite-length/canonical-encoding surface is much larger, and a
  subtle bug there would silently break every COSE signature). It knows
  nothing about `IssuerSigned`, the MSO, `DeviceAuthentication`,
  `StatusList`, or any other caller-specific structure, nor about key
  agreement (`ComputeMAC`/`VerifyMAC` take an already-derived HMAC key —
  deriving mdoc's EMacKey via ECKA-DH/HKDF is `credential/mdoc`'s job) —
  those are `credential/mdoc`'s and `statuslist`'s own CBOR struct
  definitions on top of `fxamacker/cbor` directly, calling into this
  package only for the COSE envelope itself. Its ECDSA DER/fixed-width
  R||S conversion (the one piece of logic identical to `internal/jose`'s
  own ES256 handling, since JWS and COSE made the same encoding choice)
  lives in `internal/ecdsafixed`, shared by both rather than duplicated.
- **`internal/hkdf`** (done) — HKDF (RFC 5869) using SHA-256, hand-rolled
  and checked against the RFC's own three SHA-256 test vectors
  (Appendix A.1-A.3) — the one piece of key-agreement machinery
  `credential/mdoc`'s DeviceMac needs (deriving EMacKey from an ECDH
  shared secret) that `internal/cose` deliberately doesn't own.
- **`internal/jwk`** (done) — a small, self-contained JWK (RFC 7517)
  marshaler/parser for the two key types `internal/jose` signs with
  (P-256 EC, Ed25519 OKP). Originally `attestation`'s own private
  `marshalJWK`/`matchesPublicKey` (encode-and-compare only); factored
  out once `issuer`'s Credential Endpoint also needed the reverse
  direction — parsing a Wallet-supplied `jwk` proof header into a
  `crypto.PublicKey` — rather than duplicating the encoding logic a
  second time. `attestation`'s own functions are now thin wrappers
  calling into this package, keeping their existing signatures (and
  every one of `attestation`'s own already-merged tests) unchanged.
- **`credential/mdoc`** (done) — ISO/IEC 18013-5 mdoc, both roles:
  - **Issuer side**: `Issue`/`Verify` for `IssuerSigned`
    (namespace/data-element digest+salt selective disclosure, §10.3.3),
    the Mobile Security Object (§12.3.4), and `IssuerAuth` (built on
    `internal/cose`), plus `CoseKey` for `DeviceKeyInfo.DeviceKey` (the
    mdoc analog of SD-JWT VC's `cnf.jwk`). Field order in
    `IssuerSignedItem`/`MobileSecurityObject` matches §10.3.3/§12.3.4's
    own CDDL exactly and the package's CBOR encoder isn't configured for
    canonical/sorted map keys — both deliberate, since together they
    make the encoding reproduce a real issuer's byte-for-byte: its tests
    include five of ISO/IEC 18013-5's own Annex D.4.1.2 worked-example
    digests (string, tagged-date, and array-of-structs element values),
    checked against the exact SHA-256 values that worked example
    publishes, not just round-trip checks. `IssuerSigned.Marshal`/
    `UnmarshalIssuerSigned` handle the actual §10.3.3 CBOR wire form.
  - **Holder/presentation side**: `SignDeviceSignature`/
    `VerifyDeviceSignature` (ECDSA/EdDSA mdoc authentication, §12.4.6)
    and `ComputeDeviceMAC`/`VerifyDeviceMAC` (ECDH-agreed MAC
    authentication, §12.4.5, P-256 only — see `deriveEMacKey`'s own doc
    comment for why Ed25519 can't do this one) for `DeviceSigned`
    (§10.3.3), plus `CheckKeyAuthorizations` (§12.8.2 step 1).
    `SessionTranscript` construction (`DeviceEngagement`, `EReaderKey`,
    `Handover`, §12.7.1) is explicitly out of scope — every function
    that needs it takes `SessionTranscriptBytes` as an opaque,
    caller-supplied value, since building it for an OID4VP presentation
    is that spec's own "Handover" concern, not ISO/IEC 18013-5's
    proximity-flow one. `DeviceSigned.Marshal`/`UnmarshalDeviceSigned`
    handle the actual §10.3.3 CBOR wire form.
  - Both `IssuerSigned` and `DeviceSigned` cache the exact bytes they
    authenticated (`rawItems`/`nameSpacesBytes`) rather than re-deriving
    them from the decoded Go value on every `Marshal`/`Verify` call —
    necessary because Go randomizes map iteration order, so a
    native-map-typed element value could otherwise encode differently
    each time, breaking a previously-valid digest or signature purely
    from re-encoding, not any real tampering. Both types' own doc
    comments cover this; both have a regression test (a multi-key native
    map element, verified reliably across many Issue/Sign →
    Marshal/Unmarshal → Verify cycles) that fails deterministically
    without the cache and passes reliably with it.
  - MSO revocation (the optional `status` member, §12.3.6) is deferred:
    `statuslist` has the CWT/COSE encoding this needs
    (`StatusListRef.CWTStatusClaim`/`ParseCWTStatusClaim`), but
    `MobileSecurityObject` doesn't wire it in yet.
- **`statuslist`** (done) — Token Status List (`draft-ietf-oauth-status-list-12`),
  both encodings: bit-packing and ZLIB compression (`Pack`/`Unpack`,
  `New`/`Decode`, shared by both), Status List Token issuance/verification
  in JWT/JOSE (§5.1, §6.2 — `IssueToken`/`VerifyToken`, built on
  `internal/jose` for the same `keys.KeyManager`-isn't-reusable reason
  `credential/sdjwtvc` is) and CWT/COSE (§5.2, §6.3 —
  `IssueTokenCWT`/`VerifyTokenCWT`, built on `internal/cose`'s new
  `SignTagged`/`VerifyTagged` — the CWT profile's example is
  COSE_Sign1_Tagged, not the untagged form `credential/mdoc`'s IssuerAuth
  uses), the Referenced Token `status` claim for each
  (`StatusListRef`/`ParseStatusClaim` and
  `StatusListRef.CWTStatusClaim`/`ParseCWTStatusClaim` — the same shape
  `credential/sdjwtvc`'s `Claims.Status` expects for JOSE, and covered by
  a test that wires the two packages together), and `Check`/`CheckCWT`,
  the §8.3 steps 3-7 orchestration for each. The CWT profile's ttl/
  status_list/status claim keys (65534/65533/65535) are still "TBD
  (requested assignment)" in the IANA CWT Claims Registry as of the
  draft version this targets — see `cwt.go`'s own comment, and update if
  IANA finalizes different values before this package is relied on in
  production. Tests include draft-12 §4.1's own known-answer bit-packing
  vectors, its Appendix's 2^20-entry compressed vector, and (for the CWT
  profile) both of §5.2/§6.3's own non-normative COSE_Sign1_Tagged
  examples decoded and checked field-by-field — not just round-trip
  checks.
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
  single-use-on-consume shape exactly; `Metadata` (§12.2.4) covering
  `credential_issuer`, `credential_endpoint`, `nonce_endpoint`, and
  `credential_configurations_supported` with `format`/`scope`/
  `cryptographic_binding_methods_supported`/`proof_types_supported`
  (including `key_attestations_required`), plus both formats'
  format-specific parameters: `vct` (`credential/sdjwtvc`, JOSE-alg-string
  `credential_signing_alg_values_supported`) and `doctype`
  (`credential/mdoc`, numeric-COSE-alg-number
  `credential_signing_alg_values_supported` via a distinct
  `CredentialSigningAlgValuesSupportedCOSE []cose.Alg` field — the wire
  form needs bare JSON numbers here, not JOSE strings, per OID4VCI 1.0
  Appendix A.2.2, checked against that appendix's own non-normative
  example) — deliberately not yet
  `credential_request_encryption`/`credential_response_encryption`,
  `batch_credential_issuance`, `display`, or `credential_metadata`
  (including mdoc's own `claims` array, which lives under
  `credential_metadata`); and `RequestCredential` implementing the
  Credential Endpoint (§8) for immediate (non-deferred) issuance, both
  formats and both the `jwt` and `attestation` proof types, with batch
  support native to §8.2's own `proofs` parameter (one Credential per
  resolved binding key — a `jwt` proof contributes one, an `attestation`
  proof contributes one per entry in its own `attested_keys`, per
  Appendix F.3's own "SHOULD issue a Credential for each cryptographic
  public key" guidance). `RequestCredential` takes an `AuthorizedRequest`
  as an already-verified-access-token input rather than verifying the
  token itself — that needs full HTTP request context this package has
  no reason to touch, ordinarily built from
  `fapigo/resource.Verifier.Verify`'s own result — and a
  `CredentialRequest` carrying caller-supplied `sdjwtvc.Claims`/
  `mdoc.Claims` templates (this package has no user database; resolving
  what data belongs in a credential is the caller's job), with `CNF`/
  `DeviceKey` overwritten once per resolved binding key. Signing keys
  (`SDJWTSigner`/`MdocSigner`) and the attestation trust policy
  (`AttestationVerifier`) are new `Dependencies` fields, each required
  only when a configured credential/proof type actually needs it — see
  their own doc comments. New error type `Error` (§8.3.1.2's own closed
  set of Credential Request/Response error codes, all HTTP 400) with a
  `WriteJSON` mirroring `fapigo/resource.Error`'s own shape (Code/
  PublicDescription safe to expose, Unwrap for logs only). See
  `CredentialRequest`'s own doc comment for what's deliberately out of
  scope (`credential_identifier`, `di_vp`, kid/x5c-based key resolution,
  request/response encryption, deferred issuance, unbound credentials —
  add each when a concrete consumer needs it). Still to come: Credential
  Offer Endpoint (§4), Deferred (§9) and Notification (§11) Endpoints —
  and this is still where `fapigo/server` gets consumed for the
  Authorization/Token Endpoints' own PAR/DPoP/client-authentication
  machinery once those exist in this repo.
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

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
> derivation), `internal/jwe` (RFC 7516 JWE Compact Serialization,
> ECDH-ES + AES-GCM, for OID4VCI 1.0 §10 — wired into both `issuer` and
> `wallet`), `internal/jwk` (JWK marshal/parse plus RFC 7638 thumbprint,
> shared by `attestation` and `issuer`), `internal/dpop` (RFC 9449 DPoP
> proof verification — the server-side counterpart to `wallet`'s own
> DPoP proof generation, wired into `issuer`'s own `ExchangePreAuthorizedCode`), the root
> `oid4vci` package (wire value
> types shared by
> `issuer` and `wallet`: `CredentialOffer` and its `Grants` family,
> `IssuedCredential`/`CredentialResponse`, `ProofTypeJWT`/
> `ProofTypeAttestation`, `NotificationEvent`, `IssuerStateExtension`),
> `issuer` (Nonce Endpoint,
> Metadata, the Credential Endpoint for immediate issuance of both
> formats with §10 Encrypted Request/Response support, Credential Offer
> construction/dereferencing, the Deferred Credential Endpoint's polling
> protocol, the Notification Endpoint, and the Pre-Authorized Code
> Flow's own DPoP-sender-constrained Token Endpoint)
> — every OID4VCI 1.0 Credential Issuer endpoint — `storage` (in-memory
> reference implementations of every store `issuer` defines, for local
> dev/testing only), `haip` (the profile layer's own
> `RecommendedIssuerConfig`/`ValidateIssuerConfig`/`RecommendedWalletConfig`/
> `RecommendedVerifierConfig`),
> and `wallet`
> (Credential Offer resolution, jwt-type and attestation-type key proof
> generation, the Authorization Code Flow's own OID4VCI-specific
> request shape, the pre-authorized_code Flow's own
> DPoP-sender-constrained Token Request, the Credential/Deferred
> Credential/Notification Endpoints' client sides given an
> already-obtained access token, §10 Encrypted Request/Response
> support, and — its own OID4VP Wallet role — DCQL query matching
> against held credentials and `dc+sd-jwt`/`mso_mdoc` VP Token
> construction), `dcql` (the Digital Credentials Query Language, OID4VP
> §6/§7 — query types, structural validation, §7.1's own Claims Path
> Pointer evaluation, and the shared Credential-Query-satisfaction
> checks both `wallet` and `verifier` use), `oid4vpmdoc` (the
> OID4VP-specific `mso_mdoc` wire structures on top of `credential/mdoc`
> — `OpenID4VPHandover`/`SessionTranscript` construction and
> `DeviceResponse`/`Document` CBOR, shared by `verifier` and `wallet`
> since a Presentation's own `DeviceSigned` must be computed
> byte-for-byte identically on both sides), and `verifier` (the OID4VP
> Verifier role, both the redirect and DC API flows: HAIP-§5-profiled
> Authorization Request construction via `BuildAuthorizationRequest`,
> the DC API flow's own signed request via
> `BuildDCAPIAuthorizationRequest`, `direct_post.jwt`/`dc_api.jwt`
> response parsing/decryption via `ParseDirectPostJWTResponse`, and
> §8.6 VP Token Validation for both `dc+sd-jwt` and `mso_mdoc`, either
> flow, via `VerifyResponse`)
> are implemented and tested;
> everything else below is still just the
> planned layout, not a finished system. Update each section as the
> corresponding package
> actually lands; don't let this drift into aspirational documentation
> for code that doesn't exist.

## Scope

OID4VCgo implements the full [HAIP 1.0](SPECIFICATIONS.md) profile: both
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

OID4VCgo cannot import `go-fapi/internal/*` — Go's `internal/` visibility
rule is scoped to the importing path's own module tree, and this is a
separate module (`github.com/idfoundry/oid4vcgo` vs.
`github.com/idfoundry/fapigo`) even though both live under the same GitHub
org. Anything this repo needs from FAPIgo's protocol core has to already
be, or become, one of FAPIgo's *public* packages (`server`, `client`,
`resource`, `keys`, `storage`, `fapihttp`, `extension`, the root `fapigo`
value types) — never a reason to vendor or reimplement FAPIgo's internals
here instead.

**`keys.KeyManager` turned out not to be reusable for credential-level
signing.** Its `SigningPurpose` is a closed `iota` enum defined entirely
inside FAPIgo (`keys/signing.go`) — `SigningRequest.Purpose` is typed to
it directly, so OID4VCgo cannot construct a request for a purpose FAPIgo
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
  Key Binding JWT creation/verification, and `SelectDisclosures` (RFC
  9901 §7.2's own Holder-side trimming): given a Holder's own
  not-yet-resolved Issuer JWT payload and full Disclosure set, plus a
  set of paths (each a sequence of object-property names), it returns
  exactly the Disclosures needed to reveal those paths — walking
  mandatory (already-plaintext) properties directly and
  selectively-disclosable ones via the current level's own `_sd`
  array, then, once a path is fully walked, including every Disclosure
  the target value itself transitively references (§4.2.6's own
  "recursive Disclosures", array elements included) so the disclosed
  value comes through intact. `wallet.PresentSDJWTVCSelective` is this
  function's own real caller — see the `wallet` bullet below. Its
  tests include RFC 9901's own known-answer disclosure/digest vectors,
  not just round-trip checks.
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
- **`internal/jwe`** (done) — a small, self-contained JWE Compact
  Serialization (RFC 7516) encryptor/decryptor for OID4VCI 1.0 §10's
  Encrypted Credential Requests and Responses: `Encrypt`/`Decrypt` (plus
  `DecodeHeader`, mirroring `internal/jose.DecodeUnverified`'s own role
  — read `kid` to pick a private key before calling `Decrypt`). Scope is
  deliberately narrow, matching `internal/jose`'s own "curated set, not
  the full JWA registry" restraint: ECDH-ES (RFC 7518 §4.6, Direct Key
  Agreement only — no key wrapping) over a P-256 EC key for key
  management, A128GCM/A192GCM/A256GCM (RFC 7518 §5.3) for content
  encryption, and optional raw-DEFLATE compression
  (`"zip":"DEF"`) — exactly §10's own worked example combination
  (Appendix I.1). `crypto/ecdh` does the actual scalar multiplication;
  this package only implements the Concat KDF (NIST SP 800-56A §5.8.1,
  as profiled by RFC 7518 §4.6.2 — single-round only, since every `Enc`
  this package supports needs at most 32 output bytes against SHA-256's
  32-byte output) and the JWE framing around AES-GCM, the same
  narrow-primitive restraint `internal/hkdf` set for RFC 5869. No
  apu/apv (Agreement PartyUInfo/PartyVInfo) support — both are always
  empty in the Concat KDF's own OtherInfo, since OID4VCI's own examples
  don't use them. Cross-checked bidirectionally against Python's
  `jwcrypto` (Go-encrypted JWEs decrypt correctly there, and vice versa)
  for every `Enc` value and the `zip` path, not just Go-only round-trip
  tests, since ECDH-ES's Concat KDF is exactly the kind of
  precisely-specified-but-easy-to-get-subtly-wrong construction a
  same-language round-trip test can't catch a shared bug in. Wired into
  both `issuer` (`DecryptRequestBody`/`EncryptResponseBody`,
  `Config.RequestEncryption`/`Config.ResponseEncryption`) and `wallet`
  (`CredentialRequest.RequestEncryption`/`.ResponseEncryption` and
  `DeferredCredentialRequest`'s own — see each package's own bullet
  below).
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
  `JWK.Thumbprint()` computes the RFC 7638 JWK thumbprint (SHA-256
  digest of the key's required members in lexicographic order,
  base64url-encoded) directly from `JWK`'s own already-base64url X/Y/Crv
  fields, rather than re-deriving coordinates from a parsed
  `crypto.PublicKey` the way `fapigo/internal/jose`'s own equivalent
  does (that package isn't reusable here — a different module's
  `internal/` package). Cross-checked against Python's `jwcrypto`
  (`JWK(**jwk).thumbprint()`), the same independent-verification
  discipline `internal/jwe`'s own ECDH-ES tests already apply, since
  this is exactly the same kind of precisely-specified-but-easy-to-get-
  subtly-wrong construction.
- **`internal/dpop`** (done) — a small, self-contained RFC 9449 DPoP
  proof *verifier* — the server-side counterpart to `wallet`'s own
  `GenerateDPoPProof`, wired into `issuer.ExchangePreAuthorizedCode`
  (§6.1), the one grant type entirely outside `fapigo/server`'s scope,
  the same way it's outside `fapigo/client`'s (see
  `wallet.RequestPreAuthorizedCodeToken`'s own doc comment for that
  boundary's client-side half).
  `fapigo`'s own equivalent (`internal/dpop`, a different module's
  `internal/` package) isn't reusable here either — this package's own
  `Verify` mirrors its design (read-only reference, not an import) but
  is built on this repo's own `internal/jose`/`internal/jwk` rather than
  `fapigo/internal/jose`. Scope matches `GenerateDPoPProof`'s own: no
  `ath` (access token hash) checking, since a Token Request's own DPoP
  proof is presented before any access token exists to hash. `Verify`
  requires a `ReplayChecker` (RFC 9449 §11.1's own jti-replay MUST) —
  no implicit default, matching every other "no implicit defaults"
  dependency in this repo. `TestVerifyAcceptsWalletGeneratedProof`
  drives a real round trip against `wallet.GenerateDPoPProof` (not a
  simulation of one), the same "real round trip, not just our own
  assumption" discipline every other cross-package wire-format claim
  here is held to.
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
    (§10.3.3), plus `CheckKeyAuthorizations` (§12.8.2 step 1) — now a
    real consumer, `verifier.VerifyResponse`'s own mdoc path, via the
    `VerifiedMSO.KeyAuthorizations` field `Verify` populates from the
    verified MSO's own `DeviceKeyInfo.KeyAuthorizations` (added
    alongside `oid4vpmdoc`, since `CheckKeyAuthorizations` existed
    before but nothing exposed the field it needs to call it).
    `SessionTranscript` construction (`DeviceEngagement`, `EReaderKey`,
    `Handover`, §12.7.1) is explicitly out of scope — every function
    that needs it takes `SessionTranscriptBytes` as an opaque,
    caller-supplied value, since building it for an OID4VP presentation
    is that spec's own "Handover" concern, not ISO/IEC 18013-5's
    proximity-flow one; see `oid4vpmdoc` for that caller.
    `DeviceSigned.Marshal`/`UnmarshalDeviceSigned` handle the actual
    §10.3.3 CBOR wire form.
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
  - MSO revocation (the optional `status` member, §12.3.6) is wired in
    for both of its mechanisms: `Status` on
    `MobileSecurityObject` now carries either `StatusListRef`
    (status_list, matching draft-ietf-oauth-status-list's own
    `StatusListInfo` `{idx, uri}` shape plus §12.3.6.2's own additional
    optional `certificate` field) or the new `IdentifierListRef`
    (identifier_list, §12.3.6.4's ISO-specific alternative — `{id, uri,
    ?certificate}`, revoking by ID membership in an externally-hosted
    list rather than a bit index), each flattened onto `Claims`
    (`Claims.Status`/`Claims.IdentifierList`) and surfaced on
    `VerifiedMSO.Status *Status` the same way. §12.3.6 itself presents
    these as two alternative ways to implement MSO revocation, not a
    pair whose simultaneous use it explicitly forbids (the CDDL marks
    both members independently optional, with no stated exclusivity);
    `Issue` nonetheless rejects a `Claims` value that sets both, as
    this package's own conservative default. This package still never
    imports
    `statuslist` — resolving a `Status` pointer into an actual fetch
    and bit/identifier check against the referenced list is entirely
    the caller's own job, the same split `credential/sdjwtvc.Claims.Status`
    already draws; for status_list, `statuslist` has the CWT/COSE
    encoding that needs (`StatusListRef.CWTStatusClaim`/
    `ParseCWTStatusClaim`), while identifier_list has no equivalent
    library support here, since it's an ISO-specific extension to Token
    Status List rather than part of the base spec.
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
- **`issuer`** (done) — the OID4VCI Credential Issuer role (server
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
  example), and `credential_request_encryption`/`credential_response_encryption`
  (§10, §12.2.4 — `Config.RequestEncryption`/`Config.ResponseEncryption`,
  see below), `batch_credential_issuance` (§12.2.4 —
  `Config.BatchCredentialIssuance`): besides what `Metadata` advertises,
  `RequestCredential`'s own `checkBatchSize` now enforces `BatchSize` as
  an actual cap on a Credential Request's own `proofs` array size —
  nil caps at exactly 1 (reading §12.2.4's own "the presence of this
  parameter means the issuer supports more than one key proof" as
  implying absence means it doesn't), a set value caps at `BatchSize`.
  The cap is on the array's own size, not the number of Credentials
  ultimately issued: an attestation proof's own `attested_keys` can
  still fan out to more Credentials than that, since the fan-out
  happens *within* one array entry, not across it (confirmed by a
  dedicated test sending one attestation proof with two attested keys
  against an issuer with no `BatchCredentialIssuance` configured at
  all, which still succeeds). Top-level `display` (§12.2.4 —
  `Config.Display`), and
  `credential_metadata` (Appendix A — `CredentialConfiguration.CredentialMetadata`,
  covering its own `display` and `claims` arrays, shared verbatim by
  both formats — mdoc's own claims use the same `credential_metadata`
  mechanism, just with a two-element `path` of `[namespace, element]`
  per Appendix A.2.2's own example, not a separate mdoc-specific
  member; the `path`'s own Claims Path Pointer, per Appendix C, is kept
  as a plain `[]any` rather than reusing `dcql.Path`, since describing
  display metadata never needs that OID4VP-specific package's own
  `Select`/evaluation behavior); and `RequestCredential` implementing the
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
  their own doc comments. A jwt-type proof's own binding key may be
  conveyed as `jwk` (always available, resolved inline), or as `kid`/
  `x5c` when the new `Dependencies.ProofBindingKeys`
  (`ProofBindingKeyResolver`) is configured — this package takes no
  position on how a `kid` or `x5c` header actually maps to a trusted
  key (DID resolution, an x5c chain's own trust anchor, a private
  registry, ...), the same "resolving trust is the caller's job" split
  `AttestationVerifier` already draws for a Key Attestation's own
  `kid`/`x5c`/`trust_chain`; a resolved key is re-marshaled as a JWK for
  `cnf.jwk` regardless of how it was conveyed, since RFC 7800 binding
  needs a JWK either way. `DecryptRequestBody`/`EncryptResponseBody`
  implement §10's Encrypted Requests/Responses on top of `internal/jwe`,
  shared verbatim by both the Credential Endpoint and Deferred
  Credential Endpoint (§9.1's own "using the parameters from the
  credential_request_encryption object" — the same
  `Config.RequestEncryption` governs both). `DecryptRequestBody`
  resolves which of `Config.RequestEncryption.Keys` to decrypt an
  incoming request with from the JWE header's own `kid`, rejecting an
  unencrypted request when `Required` is set (§10's own "SHOULD be
  rejected"); its second return value, `wasEncrypted`, must be passed
  through to `CredentialRequest.RequestWasEncrypted` (or
  `DeferredCredentialRequest`'s own field), which `RequestCredential`/
  `RequestDeferredCredential` check against `ResponseEncryption` being
  set, enforcing §8.2-18's own "Credential Request encryption MUST be
  used if the credential_response_encryption parameter is included, to
  prevent it being substituted by an attacker." `EncryptResponseBody`
  encrypts a marshaled Response per the Wallet's own
  `credential_response_encryption` object (a single `jwk`/`enc`/`zip`),
  validating both against `Config.ResponseEncryption`'s own declared
  support — Metadata's own `alg_values_supported` is always exactly
  `["ECDH-ES"]`, the only alg `internal/jwe` implements, so there's no
  Go field to set it from. Both functions operate purely on bytes/
  Content-Type, deliberately not on `http.ResponseWriter` — this
  package still doesn't own the HTTP handler; a caller's own glue calls
  `DecryptRequestBody` before unmarshaling a request and
  `EncryptResponseBody` after marshaling a Response, the same
  "expose the pieces, don't own the transport" boundary
  `AuthorizedRequest`'s own doc comment already draws for access token
  verification. New error type `Error` (§8.3.1.2's own closed
  set of Credential Request/Response error codes, all HTTP 400) with a
  `WriteJSON` mirroring `fapigo/resource.Error`'s own shape (Code/
  PublicDescription safe to expose, Unwrap for logs only). See
  `CredentialRequest`'s own doc comment for what's deliberately out of
  scope (`di_vp`, unbound credentials — add each when a concrete
  consumer needs it; `RequestCredential` itself never defers issuance,
  see the Deferred Credential Endpoint below for that half).
  `credential_identifier`-based requests (§8.2, RFC 9396's own
  `authorization_details` mechanism) are supported too: a new
  `AuthorizedRequest.AuthorizationDetails []oid4vci.AuthorizationDetail`
  (parsed by the caller from the verified access token's own
  `authorization_details` claim — see `resource_verifier.go`'s own
  updated recipe) and `CredentialRequest.CredentialIdentifier`, resolved
  by a new private `resolveCredentialConfiguration`/
  `resolveCredentialIdentifier` pair — exactly one of
  `CredentialConfigurationID`/`CredentialIdentifier` may be set; the
  latter bypasses the `Scopes` check entirely, since the matched
  `AuthorizationDetail` is itself the grant.
  `oid4vci.AuthorizationDetail` (RFC 9396 §2/§5.1.1/§6.2's own
  `openid_credential` type) lives in the root package, not here — once
  `wallet` needed the exact same wire shape too (see its own bullet
  below), this became the same "shared value types only where
  semantics match" split `CredentialOffer` and friends already live
  there for; it started out as `issuer`'s own type in the PR that added
  this, moved here immediately after.
  *Minting* `credential_identifier` values into a Token Response is the
  Authorization Server's own job: for the Authorization Code Flow
  that's `fapigo/server`, already RAR-capable; for the Pre-Authorized
  Code Flow, `ExchangePreAuthorizedCode` does it itself, via a new
  `PreAuthorizedCodeRecord.CredentialConfigurationIDs` — when
  non-empty, a new private `mintAuthorizationDetails` generates one
  fresh `credential_identifier` per entry (the same `randomID` helper
  `RequestNonce`/`issueDPoPNonce` already used, factored out of both
  once a third near-identical inline copy would otherwise have existed)
  and embeds the result both in the issued access token's own claims
  (`AccessTokenParams.Claims["authorization_details"]`, for a later
  `RequestCredential` call to recover via a caller's own
  `AuthorizedRequest.AuthorizationDetails` adaptation) and directly on
  `ExchangePreAuthorizedCodeResult.AuthorizationDetails`, which
  `WriteJSON` echoes in the Token Response (§6.2) — this package never
  round-trips a self-contained token's own claims back out of itself,
  so the result carries the same value independently.
  Also implements the
  Credential Offer (§4): `CreateCredentialOffer` builds and validates a
  `CredentialOffer` (`credential_issuer`, `credential_configuration_ids`,
  and `Grants` — the `authorization_code` and pre-authorized_code Grant
  Types, including `tx_code`) and returns it either embedded by value in
  an `openid-credential-offer://` deep-link URI, or — when
  `CreateCredentialOfferRequest.ByReference` is set — stored via a new
  `Dependencies.CredentialOffers` (`CredentialOfferStore`) and returned
  as a `credential_offer_uri` reference, mirroring FAPIgo's own PAR
  request_uri pattern (random 256-bit reference, `Config.Limits.CredentialOfferLifetime`-bounded).
  `GetCredentialOffer` is the domain method behind the HTTP GET request
  a Wallet makes to dereference one (§4.1.3) — served at
  `Config.CredentialOfferEndpoint`, deliberately not part of `Endpoints`
  since, unlike Credential/Nonce, this URL is never advertised in
  Credential Issuer Metadata. A pre-authorized_code grant's own code
  (and an authorization_code grant's own issuer_state) remain
  caller-supplied at offer-construction time — issuing one is still the
  caller's job (see `PreAuthorizedCodeStore`'s own doc comment) — but
  redeeming a pre-authorized_code is now this package's own job too,
  via `ExchangePreAuthorizedCode` (see below); redeeming issuer_state
  is still the Authorization Endpoint's job, via
  `oid4vci.IssuerStateExtension`.
  Also implements the Deferred Credential Endpoint's own polling
  protocol (§9): `RequestDeferredCredential` retrieves a
  `DeferredTransactionRecord` by its `transaction_id` from a new
  `Dependencies.DeferredTransactions` (`DeferredTransactionStore`),
  checks it's bound to the requesting client (when both the record and
  the request carry a `ClientID`), and either returns the finished
  `credentials` (invalidating the transaction per §9.1's own MUST), a
  `transaction_id`/`interval` pair (`Config.Limits.DeferredIssuancePollInterval`)
  when still pending, or `credential_request_denied` when this issuer
  can no longer issue it. `Endpoints.DeferredCredential` is now
  advertised in Metadata's own `deferred_credential_endpoint`, unlike
  `CredentialOfferEndpoint`. This package never creates or resolves a
  Deferred Issuance transaction itself — deciding a Credential isn't
  ready yet, and later deciding it is, is an entirely deployment-
  specific business process that writes directly to the store; see
  `DeferredTransactionRecord`'s own doc comment. Also implements the
  Notification Endpoint (§11): `RequestNotification` validates a
  Notification Request's shape (`notification_id`, one of the three
  `NotificationEvent` values, and an `event_description` restricted to
  §11.1's own character set), retrieves its `NotificationRecord` from a
  new `Dependencies.Notifications` (`NotificationStore`), checks it's
  bound to the requesting client the same way Deferred Issuance does,
  and — only if `Dependencies.NotificationHandler` is configured, since
  §11 makes reacting to an event optional even for a Credential Issuer
  that supports the endpoint — hands the event off to it; this package
  has no notification-triggered business logic of its own. Unlike
  `NonceStore`/`DeferredTransactionStore`, `NotificationStore` has no
  `Consume`/`Invalidate`: §11's own idempotency requirement means a
  repeated Notification Request for the same `notification_id` must
  keep succeeding. `IssueNotificationID` generates and persists a fresh
  `notification_id` (256-bit, matching this package's other reference
  values) bound to the requesting client; `RequestCredential` now calls
  it once per issuance flow when `Endpoints.Notification` is
  configured, setting `CredentialResponse.NotificationID` — a caller
  resolving a Deferred Issuance transaction should call it too, before
  setting `DeferredTransactionRecord.NotificationID`, since an
  unregistered value fails validation at `RequestNotification`.
  `Endpoints.Notification` is advertised in Metadata's own
  `notification_endpoint`. With this, every OID4VCI 1.0 Credential
  Issuer endpoint this repo scoped in exists. `issuer/authorization_server.go`
  is documentation only (no exported types/functions): this package
  deliberately doesn't wrap `fapigo/server`'s own Authorization/Token
  Endpoints — the same "never wraps the core FAPI/OAuth flow" stance
  `wallet` already takes on `fapigo/client`'s `BeginAuthorization`/
  `ExchangeCode` — so a deployment pairing `issuer` with a real FAPI 2.0
  Authorization Server constructs and drives a `*fapigo/server.Server`
  directly, using `oid4vci.IssuerStateExtension` to register OID4VCI
  1.0 §4.1.1's own `issuer_state` parameter in that Server's own
  `Config.Extensions` (see that file's doc comment for the full recipe,
  including why `issuer_state` never resurfaces through
  `BeginAuthorization`'s own `InteractionRequest` and must be captured
  by the caller directly off the incoming HTTP request instead).
  `issuer/resource_verifier.go` is the matching documentation-only
  recipe for the other side of that same handshake: adapting
  `fapigo/resource.Verifier.Verify`'s own `AuthorizationContext` — not
  `ExchangeAuthorizationCode`'s result, which mints the token rather
  than verifies one presented back to the Credential/Deferred
  Credential/Notification Endpoint, where DPoP/mTLS proof-of-possession
  actually gets checked — into `RequestCredential`'s own
  `AuthorizedRequest`.
  `ExchangePreAuthorizedCode` (done) implements the Pre-Authorized Code
  Flow's own Token Request/Response (§6.1/§6.2) — the one grant type
  entirely outside `fapigo/server`'s scope, the same way it's outside
  `fapigo/client`'s (see `wallet.RequestPreAuthorizedCodeToken`'s own
  doc comment for the client-side half of that same boundary), so this
  is genuinely new code rather than a wrapper. It consumes a
  `PreAuthorizedCodeRecord` via a new `Dependencies.PreAuthorizedCodes`
  (single-use, the same shape `NonceStore` already establishes), checks
  expiry and a `tx_code` match, verifies the presented DPoP proof via
  `internal/dpop.Verify` (`Config.Limits.MaxDPoPProofAge`/
  `MaxDPoPClockSkew`, a new `Dependencies.DPoPReplay` for jti-replay
  detection), and mints an access token via a new
  `Dependencies.AccessTokens` (`AccessTokenIssuer`) bound to the proof's
  own key by its RFC 7638 thumbprint. `AccessTokenIssuer` is this
  package's own independent interface rather than a reuse of
  `fapigo/server.AccessTokenIssuer` directly — Go interface satisfaction
  needs an exact parameter-type match, so a deployment already using
  `server.JWTAccessTokens` for its paired Authorization Server writes a
  thin adapter (shown in `AccessTokenIssuer`'s own doc comment) rather
  than this package importing `fapigo/server`. DPoP nonce-challenge
  support (RFC 9449 §8, an optional hardening — `ExchangePreAuthorizedCode`
  is an Authorization Server's own Token Endpoint, so §8 applies here,
  not §9's resource-server-only `WWW-Authenticate` variant) is done: a
  new `Dependencies.DPoPNonces` (`DPoPNonceStore`, optional — nil
  disables it entirely, mirroring `fapigo/server.Dependencies.Nonces`'s
  own opt-in shape) plus `Config.Limits.DPoPNonceLifetime`. The check
  happens *before* `PreAuthorizedCodes.Consume` — a Wallet's first
  attempt necessarily carries no nonce, so consuming the single-use
  code first would burn it before the Wallet could ever retry — the
  same ordering `fapigo/server.ExchangeAuthorizationCode` itself takes
  (confirmed by reading its own `TestExchangeAuthorizationCodeNonceCheckedBeforeCodeRedemption`).
  A successful exchange also proactively issues the next nonce
  (`ExchangePreAuthorizedCodeResult.NextDPoPNonce`), the same RFC 9449
  §8 recommendation `fapigo/server.TokenResult.NextDPoPNonce` already
  follows. Fixing this surfaced a real wire-format bug in
  `wallet.RequestPreAuthorizedCodeToken`'s own retry logic — see the
  `wallet` bullet below.
- **`wallet`** (done) — the Wallet's OID4VCI role (client side): credential-offer
  resolution, proof-of-possession generation, deferred/notification
  handling. Built on `fapigo/client`. `ResolveCredentialOffer` decodes a
  Credential Offer either by value or by reference (§4.1.2/§4.1.3), the
  latter via `fapigo/fapihttp.Client.Fetch`'s own SSRF/size/redirect
  hardening — appropriate given §13.5's own warning that an offer is
  unauthenticated, untrustworthy input regardless of how it arrived.
  `GenerateProof` signs a jwt-type key proof (Appendix F.1), binding it
  via a "jwk" header — the common case, embedding the key material
  inline. `GenerateProofWithKeyID`/`GenerateProofWithX5C` sign the same
  proof shape but bind via "kid"/"x5c" instead, for a Credential Issuer
  that already trusts a key by identifier or certificate rather than
  needing it conveyed inline; this package takes no position on how
  kid/x5c resolve to a trusted key on `issuer`'s own side (see
  `issuer.ProofBindingKeyResolver`'s doc comment above). Since
  `RequestCredential`'s own `Keys` field only ever builds jwk-conveyed
  proofs, a caller wanting kid/x5c passes either method's result
  through the new `CredentialRequest.JWTProofs` field instead — appended
  alongside `Keys`' own generated proofs in the outbound "jwt" array, so
  a request may mix both binding styles in one batch.
  `GenerateAttestationProof`
  builds the other key proof this package supports: a Key Attestation
  JWT (Appendix D.1) for the attestation proof type (Appendix F.3), by
  delegating to `attestation.Issue` — the same package `issuer`'s
  Credential Endpoint already verifies an attestation proof against —
  after setting `iat` and, when a c_nonce is given, `nonce` (Appendix
  F.3's own "the c_nonce value provided by the Credential Issuer MUST
  be provided in the key attestation's nonce parameter"). Unlike a
  jwt-type proof, `RequestCredential` doesn't build this one itself
  (the nonce must already be baked into the signed attestation before
  the Credential Request goes out), so a caller drives `RequestNonce`,
  then `GenerateAttestationProof`, then `RequestCredential` — passing
  the result as `CredentialRequest.Attestation` — in that order.
  Building a Key Attestation is, in most real deployments, a secure
  element's or an OS attestation service's job rather than pure
  application logic; `GenerateAttestationProof` exists for the cases
  where the caller's own signer can produce one directly (e.g.
  testing, or a software-only wallet). `RequestCredential` accepts
  either or both of `CredentialRequest.Keys`/`.JWTProofs` (jwt proof
  type — one generated proof per `crypto.Signer` in `Keys`, plus
  `JWTProofs`' own pre-built proofs, concatenated into one batch) or,
  mutually exclusive with both, `.Attestation` (attestation proof
  type — a single pre-built Key Attestation JWT, itself requesting a
  batch whenever it attests multiple keys, per Appendix F-5.2's "SHOULD
  issue a Credential for each cryptographic public key"), POSTs the
  Credential Request, and parses the Credential Response — completed
  Credentials (HTTP 200) or, if the Issuer instead defers issuance at
  this very first response (HTTP 202, transaction_id/interval — §8.3's
  own deferred-at-first-response case), a polling hint to pass to
  `RequestDeferredCredential`. `CredentialRequest.CredentialIdentifier`
  is §8.2's own alternative to `CredentialConfigurationID` — exactly
  one of the two may be set — for presenting a
  `credential_identifier` a prior Token Response's own
  `authorization_details` (RFC 9396 §6.2) granted; for the
  Pre-Authorized Code Flow, `RequestPreAuthorizedCodeToken`'s own
  `PreAuthorizedCodeTokenResult.AuthorizationDetails` parses that
  parameter out (`issuer.ExchangePreAuthorizedCode`'s own
  counterpart, see the `issuer` bullet above); for the Authorization
  Code Flow, parsing it out of whatever `fapigo/client` returns is the
  caller's own job, the same split this package already draws for
  acquiring that token in the first place. This closes the loop a
  same-session `issuer`-side PR left open (client-side support was
  its own explicitly flagged follow-up) — proven with a genuine
  mint-then-consume round trip, not just each side's own unit tests,
  in `TestWalletPreAuthorizedCodeRoundTrip_WithCredentialIdentifier`.
  `RequestCredential` POSTs the request and parses the response via a
  narrow `ProtectedResourceClient` interface
  (`Do(ctx, *http.Request) (*http.Response, error)`) rather than
  importing `fapigo/client`'s own `*client.ResourceClient` type by
  name — satisfied by it directly (identical method signature), but
  this package's own tests don't need `fapigo/client`'s TokenSet/DPoP
  machinery just to exercise the wire format. `RequestNonce` covers the
  Nonce Endpoint's own client side (§7.1). `BuildAuthorizationRequest`
  translates a resolved Credential Offer's own `authorization_code`
  grant (its `issuer_state`, via `fapigo/extension.Set`) and the
  caller's own resolved scope(s) into a `client.BeginAuthorizationRequest`
  — the only Authorization Code Flow wiring this package adds, since
  driving `BeginAuthorization`/`HandleAuthorizationResponse`/`ExchangeCode`
  themselves, and turning the result into a sender-constrained client
  via `(*client.Client).ProtectedResource`, is squarely `fapigo/client`'s
  own public API (the `issuer`-side mirror of never wrapping
  `fapigo/server`'s own Authorization/Token Endpoints).
  `fapigo/client`'s own defaults already satisfy HAIP 1.0 §4's
  Authorization Code Flow requirements with no override needed
  (`ProfileFAPISecurity` always uses PAR+PKCE; its `SenderConstrain`
  zero value is already DPoP; `client.RecommendedAlgorithms` already
  picks ES256), and HAIP §4.4.1's Wallet Attestation client
  authentication is now supported too: `storage.ClientAuthMethodAttestation`
  (added so `fapigo/server` can verify one — see "Relationship to
  FAPIgo" above) is paired with `fapigo/client`'s own
  `Dependencies.Attestation`/`Config.Algorithms.ClientAttestationPoP`,
  which build and sign the Client Attestation + PoP JWT pair per
  request. Proven end to end (a real `fapigo/client` wallet against a
  real `fapigo/server` Authorization Server) by
  `cmd/conformance-issuer`'s own `TestFullFlow_RealClientDrivesAttestationAuth`.
  `RequestDeferredCredential` polls the Deferred Credential Endpoint
  (§9.1/§9.2) via the same `ProtectedResourceClient` and access token
  as `RequestCredential`. Both share one result type, `CredentialResult`,
  and one parsing helper, `parseCredentialResult` — §9.2's own text
  ("the Deferred Credential Response MUST use the credentials parameter
  as defined in Section 8.3 ... MUST use the interval and transaction_id
  parameters as defined in Section 8.3") means the two endpoints'
  responses are one wire shape, not two; a caller inspects which of
  `CredentialResult`'s own fields are set to know whether a result is
  the completed Credentials or a `transaction_id`/`interval` polling
  hint — `interval` arrives as a plain JSON number of seconds,
  converted to `time.Duration`. `RequestCredential`/`RequestDeferredCredential`
  both also implement §10's Encrypted Requests/Responses, symmetric
  with `issuer`'s own `DecryptRequestBody`/`EncryptResponseBody`:
  setting the new `CredentialRequest.RequestEncryption` (or
  `DeferredCredentialRequest`'s own field) encrypts the outbound
  request body to the Issuer's own published
  `credential_request_encryption` key — this package doesn't fetch or
  parse Issuer metadata itself, so the caller supplies one JWK from it
  via `RequestEncryption.RecipientJWK` — and setting
  `.ResponseEncryption` additionally requests an encrypted Response:
  `prepareResponseEncryption` generates a fresh ephemeral P-256 key
  pair per call, and `postCredentialResult` (the shared POST/parse
  helper both endpoints already used) decrypts the Response
  transparently, so the `CredentialResult` a caller receives is always
  plaintext regardless. Setting `ResponseEncryption` without
  `RequestEncryption` is rejected client-side (§8.2-18's own
  substitution-attack-prevention MUST), and so is a Response that
  doesn't honor a requested encryption, or one that arrives encrypted
  when none was requested — §8.3's own "this is done regardless of the
  content" means the Issuer must always follow through either way. A
  Credential Error Response is never decrypted (§8.3.1.2's own
  "Credential Error Responses are never encrypted, even if a valid
  Credential Response would have been"), so `postCredentialResult` only
  attempts decryption for a 200/202 status.
  `RequestNotification` implements the
  Notification Endpoint's own client side (§11.1): naturally
  repeatable, matching §11's own idempotency requirement, so there is
  nothing here to track as "already sent" — a `NotificationHandler`-style
  callback belongs to `issuer`'s own side, not a Wallet's.
  `RequestPreAuthorizedCodeToken` implements the Pre-Authorized Code
  Flow's own Token Request/Response (§6.1/§6.2) directly, rather than
  through `fapigo/client`: that grant type
  (`urn:ietf:params:oauth:grant-type:pre-authorized_code`) is entirely
  outside `fapigo/client`'s own scope (OID4VCI-specific, not a FAPI 2.0
  or base OAuth 2.0 grant), and `fapigo/client` exposes no generic
  DPoP-signed Token Request primitive for a grant type it doesn't itself
  implement. It builds the RFC 9449 DPoP proof itself via the new
  `GenerateDPoPProof`, reusing the same `internal/jose`/`internal/jwk`
  primitives `GenerateProof` already relies on, and retries exactly once
  on a DPoP nonce challenge — the same one-retry behavior
  `(*client.ResourceClient).Do` applies for its own resource requests.
  `dpopNonceChallenge` originally checked for a `WWW-Authenticate:
  ... use_dpop_nonce` header, RFC 9449 §9's own resource-server-only
  challenge shape; §8's Authorization-Server-side challenge (what a
  Token Request actually gets) is HTTP 400 plus a plain JSON
  `{"error":"use_dpop_nonce",...}` body instead, no `WWW-Authenticate`
  at all. This went undetected until `issuer.ExchangePreAuthorizedCode`
  actually implemented nonce-challenge support (see the `issuer` bullet
  above) and its real `Error.WriteJSON` output was fed through this
  same retry logic in a genuine round-trip test — the two test fixtures
  that had hand-crafted a `WWW-Authenticate` header to exercise this
  path were themselves testing the bug, not real Authorization Server
  behavior. Fixed to check the JSON body's own `"error"` member
  (reusing `parseError`) instead. Client authentication isn't
  supported (§6.1 makes it OPTIONAL for this grant, and Wallet
  Attestation client auth isn't buildable yet, per the note above), and
  neither is `authorization_details`, matching this package's own
  `credential_configuration_id`-only scope. `GenerateDPoPProof` and
  `DPoPAccessTokenHash` are exported beyond this one call: this package
  builds the Token Request's own DPoP proof, but deliberately doesn't
  build a full sender-constrained resource client for the access token
  it returns (unlike the Authorization Code Flow, whose resource
  requests go through `fapigo/client`'s already-hardened
  `(*client.Client).ProtectedResource`) — a caller wiring a
  pre-authorized_code-obtained token into `RequestCredential`/
  `RequestDeferredCredential`/`RequestNotification`'s own
  `ProtectedResourceClient` needs these two primitives to do that
  itself, rather than reimplementing DPoP proof construction a second
  time.
- **`dcql`** (done) — the Digital Credentials Query Language
  (OID4VP §6/§7): `Query`/`CredentialQuery`/`CredentialSetQuery`/
  `ClaimsQuery`/`TrustedAuthoritiesQuery`, each with a `Validate()`
  checking the spec's own structural MUSTs (non-empty arrays, `id`
  uniqueness, `meta` presence as an object, `claim_sets` referencing
  only declared claim ids, no two `claims` entries addressing the same
  `path`), `SDJWTVCMeta`/`MdocMeta` (Appendix B.3.5/B.2.3, the two
  Credential Format Identifiers this repo issues), and `Path`/
  `PathElement` (§7's own Claims Path Pointer: string/wildcard/
  non-negative-integer components, custom JSON marshaling for the
  string-or-null-or-integer wire form). Deliberately a *shared* package
  rather than living inside `verifier` — both `verifier` (construction)
  and `wallet` (evaluation — matching a Query against held credentials)
  need the identical wire shape, the same split the root `oid4vci`
  package already draws for OID4VCI's own wire types. `Path.Select`
  implements §7.1's own JSON-based evaluation semantics
  (object-key/wildcard/array-index selection, left to right, tested
  against §7.3's own worked "Arthur Dent" example verbatim) — the one
  shared low-level primitive both `verifier.VerifyResponse` (checking a
  returned Presentation actually carries what a Claims Query asked for)
  and `wallet.MatchDCQLQuery` (deciding which held credential satisfies
  a whole Query) need identically; the higher-level decision each makes
  with its result stays role-specific. mdoc's §7.2 form has no
  `Select` equivalent — `MdocNamespaceAndElement` already reports its
  only two possible components; looking those up is a plain map access
  once a caller has decoded the mdoc's own namespace structure.
  `CredentialQuery.SatisfiedBySDJWTVCClaims` goes one level up from
  `Path.Select` itself: given a "dc+sd-jwt" credential's own already-
  resolved claims, it checks the *whole* Credential Query is satisfied
  (`vct` among `SDJWTVCMeta`'s own `VCTValues`, plus `Claims`/
  `ClaimSets` per §6.4.1's own "Selecting Claims" rule — see
  `selectedClaimPaths` below) — again one shared check both `verifier`
  (does a returned Presentation satisfy what was asked) and `wallet`
  (does a held credential satisfy a Credential Query at all) need
  identically, factored out after the two were caught duplicating it.
  It's now a thin wrapper around `SelectedSDJWTVCClaimPaths`, its own
  richer twin: on success, that one also returns exactly which
  `Claims` entries' own `Path`s the winning combination resolved (the
  no-`ClaimSets` case's own `Claims`, or the first satisfiable
  `ClaimSets` option's own `Path`s) — `wallet.PresentSDJWTVC`'s own
  minimal-disclosure trimming (see the `wallet` bullet below) needs
  precisely this to know which Disclosures to keep, not just whether
  the Credential Query is satisfiable at all.
  `CredentialQuery.SatisfiedByMdocClaims`/`SelectedMdocClaimPaths` are
  the "mso_mdoc" twins: `docType` must match `MdocMeta`'s own
  `DoctypeValue`, and `Claims`/`ClaimSets` the same way, each `Claims`
  entry a `Path.MdocNamespaceAndElement`-shaped two-component path
  checked against the given namespace/element-value map — its own
  consumer is `wallet.presentMdocSelectively` (see the `wallet` bullet
  below), the mdoc-side counterpart to `SelectedSDJWTVCClaimPaths`'s
  own `wallet.PresentSDJWTVC` consumer.
  `selectedClaimPaths` (private, shared by both `Selected*` methods via
  a format-specific `present(Path) error` closure) implements §6.4.1
  exactly: when `ClaimSets` is empty, every `Claims` entry must
  resolve (and every one of their own `Path`s is returned); when both
  are set, at least one `ClaimSets` option must resolve *in full*,
  checked in the given order and returning satisfied as soon as one
  does (§6.4.1's own "the Wallet SHOULD return the first option that
  it can satisfy"), returning exactly that option's own `Path`s.
- **`oid4vpmdoc`** (done) — the OID4VP-specific wire structures the
  "mso_mdoc" Credential Format's own Presentation needs on top of
  `credential/mdoc`'s own ISO/IEC 18013-5 primitives:
  `BuildSessionTranscriptBytes` implements Appendix B.2.6.1's own
  `OpenID4VPHandover`/`SessionTranscript` construction (redirect flow
  only — `DeviceEngagementBytes`/`EReaderKeyBytes` both CBOR null,
  `Handover = ["OpenID4VPHandover", sha256(CBOR(OpenID4VPHandoverInfo))]`
  where `OpenID4VPHandoverInfo = [client_id, nonce, jwkThumbprint,
  response_uri]`) — checked byte-for-byte against Appendix B.2.6.1's
  own published worked hex example, not just round-tripped.
  `MarshalDeviceResponse`/`UnmarshalDeviceResponse` implement ISO/IEC
  18013-5 §10.3.2/§10.3.3's own `DeviceResponse`/`Document` CBOR
  structures (a thin wrapper around `credential/mdoc.IssuerSigned`/
  `DeviceSigned`, which already handle their own inner CBOR forms),
  always exactly one `Document` per `DeviceResponse` (HAIP §5.3.1's own
  MUST for multiple returned mdocs: "each ISO mdoc MUST be returned in
  a separate DeviceResponse") and `status` always `0` ("OK").
  Deliberately a **shared** package (imported by both `verifier` and
  `wallet`) rather than duplicated per role, for a stronger reason than
  `dcql`'s own shared checks: `DeviceSigned` is a cryptographic
  signature/MAC *over* `SessionTranscriptBytes`, so the Wallet building
  a Presentation and the Verifier checking it MUST compute byte-for-byte
  identical bytes or verification fails outright — a drift here isn't
  just an inconsistency, it silently breaks interop.
  `BuildDCAPISessionTranscriptBytes` implements Appendix B.2.6.2's own
  `OpenID4VPDCAPIHandover`/`SessionTranscript` construction for the DC
  API flow — same null `DeviceEngagementBytes`/`EReaderKeyBytes`,
  `Handover = ["OpenID4VPDCAPIHandover", sha256(CBOR(OpenID4VPDCAPIHandoverInfo))]`
  where `OpenID4VPDCAPIHandoverInfo = [origin, nonce, jwkThumbprint]` —
  an Origin/nonce/response-encryption-key-thumbprint triple instead of
  `BuildSessionTranscriptBytes`'s own client_id/nonce/thumbprint/
  response_uri quadruple, since Appendix A.2's own supported-parameter
  list for the DC API drops `response_uri` entirely (the response comes
  back through the DC API's own platform transport, never an HTTP
  POST) and unsigned DC API requests drop `client_id` too (Appendix
  A.2's own "the client_id parameter MUST be omitted in unsigned
  requests") — checked byte-for-byte against Appendix B.2.6.2's own
  published worked hex example, the same rigor
  `BuildSessionTranscriptBytes` was held to. Wired into both
  `verifier` (`buildMdocSessionTranscriptBytes`) and `wallet`
  (identically named) — see their own bullets below.
- **`verifier`** (done, `dc+sd-jwt`+`mso_mdoc`) — the OID4VP Verifier role.
  `BuildAuthorizationRequest` builds and signs a HAIP-§5-profiled
  redirect-flow Authorization Request: a JAR Request Object
  (`"typ":"oauth-authz-req+jwt"`, RFC9101) carrying `response_type:
  "vp_token"`, `response_mode: "direct_post.jwt"` (HAIP §5.1's own
  mandatory response encryption for the redirect flow — plain
  `direct_post` isn't HAIP-conformant here), the `x509_hash` Client
  Identifier Prefix (HAIP §5's own mandated prefix for a signed
  request — the only one this package supports; `Config.ClientCertificate`'s
  SHA-256 becomes the Client ID, its DER becomes the JWS `x5c` header
  entry), `aud: "https://self-issued.me/v2"` (§5.8's own Static
  Discovery value — this package does no Dynamic Discovery of its own
  metadata), a fresh `nonce`, the caller's own `dcql.Query`, and a
  `client_metadata.jwks` advertising a fresh ephemeral P-256 ECDH-ES
  response-encryption key (a new `kid`/`use`/`alg` wrapper around
  `internal/jwk.JWK`, since that shared type carries no such fields)
  plus `encrypted_response_enc_values_supported` (`Config.EncValuesSupported`
  — HAIP §5 requires both `jwe.A128GCM` and `jwe.A256GCM`). Notably,
  **the presentation flow touches no FAPIgo package at all** — no PAR,
  no Token Endpoint, no client authentication handshake in the
  OAuth-grant sense (confirmed by grepping HAIP's full text for
  `PAR`/`DPoP`: every hit is inside §4, issuance) — so `verifier`,
  unlike `issuer`/`wallet`'s OID4VCI roles, has no FAPIgo dependency
  whatsoever, built entirely on this repo's own `internal/jose`/
  `internal/jwe`/`internal/jwk`. `TestBuildAuthorizationRequest` drives
  a real round trip: build the signed Request Object, then parse and
  verify it via `internal/jose.Verify`'s own production path, the same
  "real round trip, not a simulation" discipline every other
  cross-package wire-format claim in this repo is held to.
  `BuildDCAPIAuthorizationRequest` builds the DC API flow's own signed
  request (Appendix A.3.2.1, JWS Compact Serialization) instead:
  `response_mode: "dc_api.jwt"` (HAIP §5.2's own mandatory encryption
  for the DC API flow) rather than `direct_post.jwt`, a new REQUIRED
  `expected_origins` in place of `response_uri` (dropped entirely —
  Appendix A.2's own supported-parameter list for the DC API never
  lists it, since the response comes back through the DC API's own
  platform transport, never an HTTP POST to a Verifier-controlled
  endpoint), same `x509_hash` Client Identifier Prefix/`aud`/`nonce`/
  `dcql_query`/`client_metadata` mechanics as the redirect flow.
  Deliberately signed-only, mirroring `BuildAuthorizationRequest`'s own
  posture: unsigned requests (Appendix A.3.1) and multi-signed JWS JSON
  Serialization requests (Appendix A.3.2.2, multiple Client Identifiers
  each with their own signature) aren't offered. The two Build methods
  share `buildResponseEncryptionMetadata` (the ephemeral P-256 key/
  `client_metadata.jwks` construction) and `signRequestObject` (the
  JAR-signing mechanics) — factored out once a second caller needed
  them identically, the same "extract once genuinely reused" restraint
  this repo applies everywhere else. `TestBuildDCAPIAuthorizationRequest`
  checks exactly what differs from the redirect flow (`response_mode`,
  `expected_origins` present, `response_uri` absent); the shared
  mechanics already have their own coverage via
  `TestBuildAuthorizationRequest`'s own assertions, so they aren't
  re-proven a second time.
  `ParseDirectPostJWTResponse` decrypts a Wallet's own `direct_post.jwt`
  response body (`internal/jwe.Decrypt`, using the ephemeral private
  key `BuildAuthorizationRequestResult.ResponseDecryptionKey` returned
  for that same request) and parses its own `vp_token`/`state`, or
  returns a new `*ResponseError` when the Wallet reported one instead
  (§8.1) — reusable as-is for a `dc_api.jwt` response too (its own
  `BuildDCAPIAuthorizationRequestResult.ResponseDecryptionKey`), since
  both response modes carry the exact same encrypted-JWT-wrapping-a-
  vp_token shape; only the transport differs (an HTTP POST body vs. the
  DC API's own resolved `data` object), a caller-side concern this
  function's own byte-in/byte-out signature never touches. This package
  still doesn't host the built Request Object at a `request_uri`
  itself, or invoke the Digital Credentials API — the same "expose the
  pieces, don't own the transport" split `issuer.CreateCredentialOffer`'s
  own by-reference mode already draws.
  `VerifyResponse` implements §8.6's own VP Token Validation for the
  `dc+sd-jwt` format: for each `dcql.CredentialQuery` in the original
  `dcql.Query`, it locates the matching Presentation by id, resolves
  the Issuer key via a new caller-supplied `SDJWTVCIssuerKeyResolver`
  (trust — validating the credential's own x5c chain against
  `trusted_authorities`, DID resolution, VCT metadata lookup — stays a
  deployment policy decision, the same split
  `issuer.AttestationVerifier`/`ProofBindingKeyResolver` already draw
  on the issuance side; `X5CIssuerKeyResolver` implements the x5c-chain
  half of that policy for a deployment that just needs a trust anchor
  set — extracts and parses `x5c` (rejecting a missing/empty header,
  HAIP 1.0 §5.3's own MUST), rejects a self-signed leaf outright even
  if that exact certificate is itself a configured root, then verifies
  the chain via `x509.Certificate.Verify`; confirmed against a real
  `credential/sdjwtvc.IssueOptions.IssuerCertificate`-issued credential
  in `cmd/conformance-wallet-vp`'s own
  `TestHandleAuthorize_FullRoundTripAgainstARealVerifier`, and against
  the OIDF conformance suite's own two live checks on this exact
  requirement), derives the Holder Binding key **only** from
  the credential's own already-cryptographically-verified `cnf` claim
  (RFC 7800) — never from an externally supplied value, since accepting
  one without deriving it from the credential itself would make the
  binding check meaningless — verifies via
  `credential/sdjwtvc.Verify` (checking the Key Binding JWT's own
  `aud`/`nonce` against a new `expectedAudience(req.Origin)`/the
  caller's `ExpectedNonce` per §14.1.2 — this Verifier's own `ClientID`
  when `req.Origin` is empty (the redirect flow), or Appendix A.4's own
  `"origin:"`-prefixed value when set (the DC API flow) — requiring it
  exactly when `dcql.CredentialQuery.RequiresCryptographicHolderBinding`
  is true), and checks every one of the Credential Query's own `Claims`
  is actually present via the new `dcql.Path.Select` (§7.1) plus that
  the credential's own `vct` is among `SDJWTVCMeta.VCTValues` (§8.6
  point 3). `TestVerifyResponse`/`TestVerifyResponseDCAPI` are real
  end-to-end round trips, one per flow: build a real Authorization/DC
  API Request, issue and present a real SD-JWT VC bound to its exact
  `aud`/`nonce`, and verify it.
  For `mso_mdoc`, `VerifyResponse` base64url-decodes the Presentation
  into an `oid4vpmdoc.Document`, resolves the Issuer key via a new
  caller-supplied `MdocIssuerKeyResolver` (from the credential's own
  unverified `IssuerAuth` x5chain — `internal/cose.DecodeUnverified`,
  the COSE analog of `jose.DecodeUnverified`; `X5ChainIssuerKeyResolver`
  implements it for real, mirroring `X5CIssuerKeyResolver`'s own
  reject-self-signed-leaf/verify-against-Roots logic exactly, added
  proactively alongside the SD-JWT VC one even though no live mdoc
  conformance run has exercised this path yet — see its own tests),
  cryptographically
  verifies `IssuerSigned` (`credential/mdoc.Verify`), rebuilds
  `SessionTranscriptBytes` *exactly* as the Wallet did — a new private
  `buildMdocSessionTranscriptBytes` dispatches to
  `oid4vpmdoc.BuildSessionTranscriptBytes` (redirect flow) or
  `BuildDCAPISessionTranscriptBytes` (DC API flow) on the same
  `req.Origin` check `expectedAudience` uses, both using a new
  `VerifyResponseRequest.ResponseEncryptionKey` — the same ephemeral
  key `BuildAuthorizationRequestResult`/`BuildDCAPIAuthorizationRequestResult`'s
  own `ResponseDecryptionKey` already returned — to recompute its own
  public key's RFC 7638 thumbprint), verifies `DeviceSigned` against
  the now-trusted `DeviceKeyInfo.DeviceKey`
  (`credential/mdoc.VerifyDeviceSignature` — `DeviceAuthMAC` isn't
  supported: it needs an `EReaderKey` for ECDH agreement, but neither
  flow's own `SessionTranscript` ever sets one, so there's no in-band
  reader ephemeral key to agree a MAC key from), checks §12.8.2's own
  key-authorization rule (`credential/mdoc.CheckKeyAuthorizations`),
  and checks the result via
  `dcql.CredentialQuery.SatisfiedByMdocClaims`.
  `TestVerifyMdocResponse`/`TestVerifyMdocResponseDCAPI` are the same
  real end-to-end round trip, for this format, one per flow.
  Scope, explicitly: DCQL's own selection rules are now all
  implemented. `multiple` (§6.1): `verifyCredentialQuery` verifies
  *every* Presentation `req.Response.VPToken` carries for a Credential
  Query's own id — one when `Multiple` is false (§8.1's own "the array
  MUST contain only one Presentation" — more than one is a hard
  error), any number when true — and `VerifyResponse` flattens them
  all into `VerifyResponseResult.Credentials` (several entries can
  share one `CredentialQueryID`). `credential_sets` (§6.4.2): a private
  `satisfiableCredentialSetOption` tries each
  `dcql.CredentialSetQuery.Options` entry in order (most-preferred
  first), returning the first one whose every referenced Credential
  Query id actually verifies; a required
  (`dcql.CredentialSetQuery.IsRequired`) Credential Set with no
  satisfiable option fails `VerifyResponse` entirely, per §6.4.2's own
  "MUST NOT return any Credential(s)", while an optional one is
  silently omitted from `VerifyResponseResult` — and a Credential Query
  not referenced by any Credential Set Query is never checked at all,
  matching §6.4.2's own "otherwise, the Verifier requests presentations
  satisfying credential_sets" (i.e. *only* what `credential_sets`
  references, once it's present). When `req.Query.CredentialSets` is
  empty, behavior is unchanged: every Credential Query in
  `req.Query.Credentials` is required. `claim_sets` (§6.4.1): see the
  `dcql` bullet's own `claimsSatisfiedBy`. `VerifyResponse` now
  verifies either flow: a new `VerifyResponseRequest.Origin` (empty
  for the redirect flow, set for the DC API flow) drives both
  `expectedAudience` (the Key Binding JWT `aud` check) and
  `buildMdocSessionTranscriptBytes` (which Handover to rebuild) — see
  its own doc comment above. This completes the DC API flow's own
  request-building and response-verification halves
  (`BuildDCAPIAuthorizationRequest` plus this). HAIP formally allows an
  Ecosystem to choose redirect-only, DC-API-only, or both (HAIP §9.3);
  actually *invoking* the W3C Digital Credentials API is still a
  browser/OS platform concern outside a Go library's own transport
  responsibilities regardless.
- **`wallet`** (extended, done for `dc+sd-jwt`+`mso_mdoc`) — the naming
  question above is now resolved: OID4VP's Wallet role lives in the
  existing `wallet` package rather than a distinct one — "Wallet" is
  genuinely one real-world actor across both OID4VCI and OID4VP (the
  same app holds credentials and presents them), the same way `issuer`
  already covers everything the Credential Issuer role does in one
  package regardless of internal protocol-section boundaries. New
  exported surface, all free functions (no `*Wallet` state is actually
  needed, the same precedent `BuildAuthorizationRequest`/
  `DPoPAccessTokenHash` already set): `HeldCredential` (a credential
  this Wallet holds — `Format`/`Credential`/`HolderKey`/
  `HolderKeyAlg`/`MdocDocType`, the last two format-specific — paired
  with the key its own proof-of-possession is bound to; this package
  never verifies a held credential's own Issuer signature itself, the
  same "resolving trust is a caller's own job" split
  `RequestCredential`'s own `CredentialResult` already establishes at
  receipt time), `MatchDCQLQuery` (evaluates a `dcql.Query` against
  `[]HeldCredential` via `dcql.CredentialQuery.SatisfiedBySDJWTVCClaims`/
  `SatisfiedByMdocClaims` — the exact same shared checks
  `verifier.VerifyResponse` uses, so a credential that would satisfy a
  Verifier is also what this package picks; this is the `dcql.Path`
  *evaluation* half `dcql` itself deliberately doesn't own — for
  `mso_mdoc`, matching reads `IssuerSigned.NameSpaces` directly, no
  cryptographic verification needed for that, the same "trust by
  possession" stance the `dc+sd-jwt` side already takes), `PresentSDJWTVC`
  (builds one Presentation: a fresh Key Binding JWT bound to the
  caller's own aud/nonce, reusing every one of the held credential's
  own Disclosures — full disclosure, for a caller with no DCQL query
  context to trim against) and its own minimal-disclosure twin
  `PresentSDJWTVCSelective` (RFC 9901 §7.2, §6.4.1's own "the Wallet
  MUST NOT send selectively disclosable claims that have not been
  selected"): given the `[]dcql.Path` a Credential Query's own
  `SelectedSDJWTVCClaimPaths` says are needed, it walks the credential's
  own not-yet-resolved Issuer JWT payload
  (`credential/sdjwtvc.SelectDisclosures`, new) and keeps only the
  Disclosures actually reachable from those paths — including every
  one transitively referenced *below* a selected path (RFC 9901 §4.2.6's
  own "recursive Disclosures": disclosing `address` also discloses
  whatever `address` itself further selectively discloses internally,
  in full) but never a sibling claim that wasn't asked for. A `Path`
  with a Wildcard/Index component (selecting into an array, not an
  object property) isn't supported for trimming yet — falls back to
  full disclosure for that whole credential rather than guessing which
  array elements matter; no Claims Path Pointer either format's own
  DCQL fixtures in this repo actually uses today has one, so this cut
  costs nothing in practice yet. `PresentMdoc`
  (builds one Presentation: `oid4vpmdoc.MarshalDeviceResponse` wrapping
  the held `IssuerSigned` plus a fresh `DeviceSigned` — ECDSA/EdDSA
  device signature only, over `SessionTranscriptBytes` built via a new
  private `buildMdocSessionTranscriptBytes`, this package's own
  counterpart to `verifier`'s identically-named helper: dispatches to
  the *same shared* `oid4vpmdoc.BuildSessionTranscriptBytes`/
  `BuildDCAPISessionTranscriptBytes` the Verifier reconstructs, on
  whether the new `PresentMdocParams.Origin` is set — with an empty
  self-asserted `NameSpaces` either way — this package only ever proves
  device-key possession, not additional Holder-asserted claims) and its
  own minimal-disclosure twin `PresentMdocSelective` (ISO/IEC 18013-5's
  own namespace/data-element selective disclosure, §10.3.3 — the mdoc
  analog of `PresentSDJWTVCSelective`): trims held's own `IssuerSigned`
  to exactly `requiredPaths` via a new
  `credential/mdoc.IssuerSigned.SelectNameSpaces([][2]string)` before
  wrapping it. That method lives in `credential/mdoc`, not here, because
  `IssuerSigned`'s own cached `IssuerSignedItemBytes` (`rawItems`, kept
  index-aligned with `NameSpaces` — see that type's own doc comment on
  why `Marshal`/`Verify` must never re-derive an item's bytes from its
  decoded `ElementValue`) is a private field only that package can keep
  correctly aligned while filtering; a `Path` that isn't exactly the
  two-component mdoc form (`dcql.Path.MdocNamespaceAndElement`) falls
  back to full disclosure, the same narrow, currently-costless cut
  `PresentSDJWTVCSelective` takes for a Wildcard/Index component. And
  `PresentCredentials` (dispatches by format, combining `MatchDCQLQuery`
  with a new private `presentSDJWTVCSelectively` (calling
  `SelectedSDJWTVCClaimPaths` then `PresentSDJWTVCSelective`, so its
  own `vp_token` is §6.4.1-compliant by construction rather than by a
  caller remembering to trim)/`presentMdocSelectively` (calling
  `SelectedMdocClaimPaths` then `PresentMdocSelective`, the same way)
  into a ready-to-encrypt `vp_token` map, §8.1's own shape — a new
  `PresentationRequest.Origin`, when set, presents for the DC API flow
  instead of the redirect flow: each Presentation is bound to Appendix
  A.4's own `"origin:"`-prefixed audience rather than `Audience`, and
  `PresentMdocParams.Origin` is threaded through the same way). Same
  scope as
  `verifier.VerifyResponse`, now that both packages implement DCQL's
  selection rules fully: `MatchDCQLQuery` returns `map[string][]HeldCredential`
  (a breaking change from the single-`HeldCredential`-per-id shape
  earlier phases had) — `matchCredentialQuery` collects *every*
  candidate satisfying a Credential Query via the new
  `matchAllSDJWTVCQuery`/`matchAllMdocQuery`, trimming to the first
  when `Multiple` is false (§6.1's own default); `PresentCredentials`
  presents each one, so a `Multiple: true` query's own `vp_token` entry
  naturally carries more than one Presentation. `credential_sets`
  (§6.4.2) orchestration is the same private `satisfiableCredentialSetOption`
  structured identically to `verifier`'s own (matching `HeldCredential`s
  against `candidates` rather than verifying Presentations against a
  response) — so `PresentCredentials`' own `vp_token` naturally omits
  an unsatisfied optional Credential Set without any change to its own
  dispatch logic.
  `TestWalletVerifierPresentationRoundTrip`/
  `TestWalletVerifierDCAPIPresentationRoundTrip`/
  `TestWalletVerifierMdocPresentationRoundTrip` drive the full OID4VP
  flow between this repo's own two independently-built halves, one per
  format/flow — build a real Authorization/DC API Request, match and
  present a real held credential, encrypt the response exactly as a
  real Wallet would (`internal/jwe.Encrypt` against the Verifier's own
  advertised key), then parse/decrypt/verify it — the same "real round
  trip, not a simulation" discipline `TestWalletIssuerRoundTrip`
  already holds OID4VCI to. With this, the DC API flow (Appendix A/HAIP
  §5.2) is done end to end across `oid4vpmdoc`/`verifier`/`wallet` — the
  one remaining piece is actually invoking the W3C Digital Credentials
  API itself, a browser/OS platform concern outside any Go library's
  own transport responsibilities (see the `verifier` bullet above).
- **`haip`** (done) — the profile layer: wires HAIP's own specific
  overrides on top of `issuer`/`wallet`/`verifier` — mirrors
  FAPIgo's `server.RecommendedLimits()`/`RecommendedAlgorithms()` pattern:
  every value traceable to a specific HAIP section, nothing applied
  automatically. `RecommendedJOSEAlgorithm`/`RecommendedCOSEAlgorithm`
  (HAIP §7's minimum: ES256/COSE -7) back `RecommendedJWTProofType()`/
  `RecommendedAttestationProofType()`, two `issuer.ProofTypeConfiguration`
  builders — the latter requiring a Key Attestation with no further
  constraint, §4.5.1's own recommended posture for Ecosystems that want
  key-attestation-level interoperability. §4.5.1's other combination,
  "jwt proof type using key_attestation," is deliberately not offered:
  `issuer`'s own `resolveJWTProofKeys` rejects
  `KeyAttestationsRequired` on the jwt proof type outright, so
  recommending it would describe a configuration `issuer` can't
  actually serve. `RecommendedIssuerConfig()` bundles both proof types
  into an `IssuerRecommendations`, deliberately not a complete
  `issuer.Config` — an Issuer's own identifier/endpoint URLs, a
  Credential Configuration's own Format/VCT/DocType/Scope, and every
  `issuer.Limits` duration are all deployment-specific values neither
  OID4VCI nor HAIP number, so padding them with an unlabeled guess
  would violate this package's own "every value traceable" rule.
  `ValidateIssuerConfig(cfg)` separately checks `issuer.Config` against
  §4.1's own two additional MUSTs on top of plain OID4VCI (a `Scope` on
  every Credential Configuration; `Endpoints.Nonce` configured whenever
  any Credential Configuration requires cryptographic key binding) —
  `issuer.New` never runs these itself, since they're HAIP-specific
  profiling, not something the protocol-generic `issuer` package can
  assume every deployment wants. `RecommendedWalletConfig()` bundles
  the one part of a `wallet.Config` HAIP actually grounds a value for —
  `ProofSigningAlg`, the same §7 ES256 minimum — into a
  `WalletRecommendations`; `wallet.Config`'s other field, `Fetch`
  (SSRF/redirect/timeout policy), is deployment-specific and HAIP has
  nothing to say about it, so it's left out the same way
  `IssuerRecommendations` leaves out `issuer.Config`'s own ungrounded
  fields. No `ValidateWalletConfig` — HAIP's substantive Wallet-facing
  requirements (§4's PAR+PKCE+DPoP, §4.4.1's Wallet Attestation client
  authentication) are entirely `fapigo/client`-level concerns
  `wallet.Config` doesn't touch at all (see the `wallet` bullet above
  and its own doc comment), so there's nothing in `wallet.Config`
  itself left to structurally validate. `RecommendedVerifierConfig()`
  bundles the two parts of a `verifier.Config` HAIP actually grounds a
  value for — `SigningAlg` (the same §7 ES256 minimum, this time citing
  "signed presentation requests" on the Wallet's own validating side)
  and `EncValuesSupported` (§5's own explicit "MUST be supported by
  Verifiers" pair, `jwe.A128GCM`+`jwe.A256GCM` — unlike a Wallet, which
  HAIP only requires to support one or the other, a Verifier has no
  choice here) — into a `VerifierRecommendations`;
  `verifier.Config`'s other two fields, `ClientCertificate`/
  `ResponseURI`, are deployment-specific (an Ecosystem's own Verifier
  identity and endpoint URL) the same way `issuer.Config`'s/
  `wallet.Config`'s own ungrounded fields are. No `ValidateVerifierConfig`
  either, for the same reason there's no `ValidateWalletConfig`:
  `verifier.Config` has nothing else HAIP §5 substantively constrains
  beyond what `New` itself already enforces (JAR signing,
  `direct_post.jwt`, both are load-bearing in `verifier`'s own
  implementation, not optional profiling on top of it).
- **`storage`** (done) — in-memory implementations of every store `issuer`
  defines (`NonceStore`, `CredentialOfferStore`, `DeferredTransactionStore`,
  `NotificationStore`, `PreAuthorizedCodeStore`, `DPoPNonceStore`,
  `DPoPReplayChecker`), for local dev/testing only — never production;
  mirrors FAPIgo's `storage/memstore` down to the same non-durable,
  no-garbage-collection caveats and the same M-5 no-aliasing discipline
  (deep-copying every slice/pointer that crosses a Store/Get boundary,
  in both directions — see its own `clone.go` and `aliasing_test.go`).
  `DeferredTransactionStore` has one method beyond
  `issuer.DeferredTransactionStore` itself, `Put`: since `issuer` never
  creates or resolves a Deferred Issuance transaction on its own (see
  `issuer.DeferredTransactionRecord`'s own doc comment), this package's
  reference store needs some way for a caller to actually create one
  and later mark it Issued/Denied. `DPoPNonceStore` mirrors `NonceStore`'s
  own Issue/Consume, single-use-on-consume shape exactly, for the
  distinct RFC 9449 §8 nonce this package now defines. `DPoPReplayChecker`
  is `issuer.DPoPReplayChecker`'s own reference implementation — every
  "jti" `UseOnce` sees is remembered forever (never evicted, even past
  its own `expiresAt`), the simplest reading of RFC 9449 §11.1's literal
  "MUST reject any DPoP proof in which the jti has been seen before",
  and consistent with this package's own no-garbage-collection caveat.
- **`conformance`** (started) — OIDF HAIP conformance suite harness,
  mirroring FAPIgo's own `conformance/` structure (`cmd/conformance-*`
  binaries wiring the real production package behind real HTTP, Docker
  attaching to the suite's own network, a config generator producing
  throwaway key material rather than committing any) and its own
  AGENTS.md documentation convention. `cmd/conformance-verifier` (OID4VP
  1.0 Final/HAIP Verifier role) and `cmd/conformance-wallet-vp` (OID4VP
  Wallet role, direct_post.jwt module list only) exist, compile, are
  unit-tested, and were confirmed live against each other end to end
  (a real cryptographic round trip). `cmd/conformance-issuer` (OID4VCI
  1.0 Final/HAIP Issuer role) pairs a real `fapigo/server.Server`
  (`AttestationBasedClientAuthentication` enabled — the first real
  exercise of that mode anywhere) with a real `issuer.Issuer` via
  `issuer/resource_verifier.go`'s own recipe (also its first real
  exercise); confirmed live end to end (PAR → consent → token → nonce →
  credential, with a real Client Attestation + PoP JWT pair and DPoP
  throughout), surfacing and fixing three real bugs along the way —
  see `conformance/issuer/README.md`'s own "Status". None of the three
  has run against the live OIDF suite itself yet. See `conformance/README.md` for current
  status per role, and the approved roadmap for the remaining phases
  (OID4VP Wallet's own dc_api.jwt module lists, and OID4VCI Wallet —
  blocked on a FAPIgo-side change, see AGENTS.md's "Relationship to
  FAPIgo").

## Design rules carried over from FAPIgo

These are the rules FAPIgo's own ARCHITECTURE.md establishes that this
repo inherits by construction (building on FAPIgo's role split); restate
them here as OID4VCgo-specific packages land, don't assume they transfer
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
  packages. `CredentialOffer` (and `Grants`/`GrantAuthorizationCode`/
  `GrantPreAuthorizedCode`/`TxCode`), `IssuedCredential`/
  `CredentialResponse`, `ProofTypeJWT`/`ProofTypeAttestation`, and
  `NotificationEvent` moved here from `issuer` once `wallet` needed the
  exact same wire semantics for each; `IssuerStateExtension` — a
  `fapigo/extension.Definition[string]` for OID4VCI 1.0 §4.1.1's own
  `issuer_state` authorization parameter — lives here for the same
  reason, since a real deployment needs the identical value on both
  sides of the Authorization Code Flow: `wallet.BuildAuthorizationRequest`
  attaches it client-side, and a `fapigo/server.Server` paired with
  `issuer` must register it in its own `Config.Extensions` server-side,
  or Pushed Authorization Request validation rejects it outright as
  unregistered — see `issuer/authorization_server.go`'s own doc comment
  for the full integration recipe, including the non-obvious finding
  that it doesn't resurface through `BeginAuthorization`'s own
  `InteractionRequest`. Each type's own `Validate` method
  (where it has one) checks
  only §4/§8's own structural requirements; a role package's additional,
  role-specific constraints (e.g. `issuer`'s own check that
  `credential_configuration_ids` are actually known to it) stay in that
  role package as a free function over these types, not a method here —
  Go methods can only be defined where a type is declared, and a
  role-specific rule doesn't belong in a package every role imports.

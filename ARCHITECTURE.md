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
> DPoP proof generation, not yet wired into `issuer`), the root
> `oid4vci` package (wire value
> types shared by
> `issuer` and `wallet`: `CredentialOffer` and its `Grants` family,
> `IssuedCredential`/`CredentialResponse`, `ProofTypeJWT`/
> `ProofTypeAttestation`, `NotificationEvent`, `IssuerStateExtension`),
> `issuer` (Nonce Endpoint,
> Metadata, the Credential Endpoint for immediate issuance of both
> formats with §10 Encrypted Request/Response support, Credential Offer
> construction/dereferencing, the Deferred Credential Endpoint's polling
> protocol, and the Notification Endpoint)
> — every OID4VCI 1.0 Credential Issuer endpoint — `storage` (in-memory
> reference implementations of every store `issuer` defines, for local
> dev/testing only), `haip` (the profile layer's own
> `RecommendedIssuerConfig`/`ValidateIssuerConfig`/`RecommendedWalletConfig`),
> and `wallet`
> (Credential Offer resolution, jwt-type and attestation-type key proof
> generation, the Authorization Code Flow's own OID4VCI-specific
> request shape, the pre-authorized_code Flow's own
> DPoP-sender-constrained Token Request, the Credential/Deferred
> Credential/Notification Endpoints' client sides given an
> already-obtained access token, and §10 Encrypted Request/Response
> support) are implemented and tested;
> everything else below is still just the
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
  `GenerateDPoPProof`, built for `issuer`'s own future
  pre-authorized_code Token Request handling (§6.1), the one grant type
  entirely outside `fapigo/server`'s scope, the same way it's outside
  `fapigo/client`'s (see `wallet.RequestPreAuthorizedCodeToken`'s own
  doc comment for that boundary's client-side half).
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
  example), and `credential_request_encryption`/`credential_response_encryption`
  (§10, §12.2.4 — `Config.RequestEncryption`/`Config.ResponseEncryption`,
  see below) — deliberately not yet `batch_credential_issuance`,
  `display`, or `credential_metadata` (including mdoc's own `claims`
  array, which lives under `credential_metadata`); and `RequestCredential` implementing the
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
  scope (`credential_identifier`, `di_vp`, unbound credentials — add
  each when a concrete consumer needs it; `RequestCredential` itself
  never defers issuance, see the Deferred Credential Endpoint below for
  that half).
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
  (and an authorization_code grant's own issuer_state) are
  caller-supplied: issuing and later redeeming them is the Token/
  Authorization Endpoint's job, which doesn't exist in this repo yet.
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
  by the caller directly off the incoming HTTP request instead). Still
  to come: adapting a successful `ExchangeAuthorizationCode` result into
  `RequestCredential`'s own `AuthorizedRequest` (today documented only
  as a 2-line inline adaptation a caller does itself), and the
  pre-authorized_code grant's own server-side Token Request handling —
  entirely `issuer`'s own new code, since that grant type is outside
  `fapigo/server`'s scope the same way it's outside `fapigo/client`'s
  (see `wallet.RequestPreAuthorizedCodeToken`'s own doc comment for the
  client-side half of that same boundary).
- **`wallet`** — the Wallet's OID4VCI role (client side): credential-offer
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
  `RequestDeferredCredential` — via a narrow `ProtectedResourceClient`
  interface
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
  picks ES256) — except HAIP §4.4.1's Wallet Attestation client
  authentication: `storage.ClientAuthMethodAttestation` exists (added so
  `fapigo/server` can verify one — see "Relationship to FAPIgo" above),
  but `fapigo/client` has no logic of its own yet to construct or send
  the Client Attestation + PoP JWT pair, so a HAIP-profile wallet must
  use `ClientAuthMethodPrivateKeyJWT` until that lands upstream.
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
  on a DPoP nonce challenge (§9: HTTP 400 +
  `WWW-Authenticate: ... use_dpop_nonce` + `DPoP-Nonce` response
  header) — the same one-retry behavior `(*client.ResourceClient).Do`
  applies for its own resource requests. Client authentication isn't
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
- **`verifier`** — the OID4VP Verifier role: DCQL query construction,
  Authorization Request via JAR, response modes (`direct_post`,
  `direct_post.jwt`, DC API), response verification.
- **`wallet`** (extended) or a distinct presentation package — the
  Wallet's OID4VP role: DCQL evaluation against held credentials, VP Token
  construction per format. Naming TBD once `verifier` exists and the
  shared/duplicated surface with the OID4VCI wallet role is clearer.
- **`haip`** — the profile layer: wires HAIP's own specific overrides on
  top of `issuer` (and, once they exist, `wallet`/`verifier`) — mirrors
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
  itself left to structurally validate. Still to come:
  `RecommendedVerifierConfig()`, once `verifier` itself exists.
- **`storage`** — in-memory implementations of every store `issuer`
  defines (`NonceStore`, `CredentialOfferStore`, `DeferredTransactionStore`,
  `NotificationStore`), for local dev/testing only — never production;
  mirrors FAPIgo's `storage/memstore` down to the same non-durable,
  no-garbage-collection caveats and the same M-5 no-aliasing discipline
  (deep-copying every slice/pointer that crosses a Store/Get boundary,
  in both directions — see its own `clone.go` and `aliasing_test.go`).
  `DeferredTransactionStore` has one method beyond
  `issuer.DeferredTransactionStore` itself, `Put`: since `issuer` never
  creates or resolves a Deferred Issuance transaction on its own (see
  `issuer.DeferredTransactionRecord`'s own doc comment), this package's
  reference store needs some way for a caller to actually create one
  and later mark it Issued/Denied.
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

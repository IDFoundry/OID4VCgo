# Specification baseline

OID4VCgo implements the **full OpenID4VC High Assurance Interoperability
Profile (HAIP) 1.0** — both the issuance half (OID4VCI, profiled by HAIP §4)
and the presentation half (OID4VP, profiled by HAIP §5) — built on FAPIgo's
FAPI 2.0 Security Profile Final core.

Every version below was confirmed against the specification's own text
(published date + `Status:` header, and, for Internet-Drafts, the exact
`draft-…-NN` string in the citing document's References section) rather than
assumed — see the dated entries. Re-verify before bumping any of these; OID4VCI
and HAIP each pin specific Internet-Draft revisions that are not the latest
available draft at any given time, deliberately (a Final OIDF spec doesn't
track a moving IETF draft).

## Primary

| Spec | Status | Published |
|---|---|---|
| [OpenID for Verifiable Credential Issuance 1.0][oid4vci] | Final | 2025-09-16 |
| [OpenID for Verifiable Presentations 1.0][oid4vp] | Final | 2025-07-09 |
| [OpenID4VC High Assurance Interoperability Profile 1.0][haip] | Final | 2025-12-24 |

## Security profile

HAIP §4 requires compliance with the applicable provisions of FAPI 2.0
Security Profile Final, with explicit overrides — see "HAIP's deviations from
plain FAPI 2.0" below.

| Spec | Status | Published |
|---|---|---|
| [FAPI 2.0 Security Profile][fapi2] | Final | 2025-02-22 |
| [RFC 9449 — DPoP][dpop] | Standards Track | — |
| [RFC 9126 — Pushed Authorization Requests (PAR)][par] | Standards Track | — |
| [RFC 7636 — PKCE][pkce] | Standards Track | — |
| [RFC 9207 — Authorization Server Issuer Identification][iss] | Standards Track | — |
| [RFC 8414 — OAuth Authorization Server Metadata][asmeta] | Standards Track | — |
| [RFC 7009 — OAuth 2.0 Token Revocation][revocation] (a public client's refresh token, outside HAIP) | Standards Track | — |
| [RFC 6750 — Bearer Token Usage][bearer] (an Authorization Server's Bearer access token, outside HAIP) | Standards Track | — |

## Credential formats (HAIP requires at least one; OID4VCgo supports both)

| Spec | Pinned by | Draft |
|---|---|---|
| [SD-JWT-based Verifiable Credentials (SD-JWT VC)][sdjwtvc] | HAIP 1.0 §9.4 (overriding OID4VCI 1.0 §14.7's draft-11) | `draft-ietf-oauth-sd-jwt-vc-13` (2025-11-06) |
| [ISO/IEC 18013-5:2021 — mdoc][iso18013-5] | OID4VCI 1.0 Appendix A.2, HAIP §5.3.1 | — |
| ISO/IEC 23220 series | HAIP §5.3.1 (mdoc presentation specifics) | — |
| [ISO/IEC TS 18013-7:2025 — mdoc online presentation][iso18013-7], Annex C (`org-iso-mdoc` over the Digital Credentials API) | — (`mdocdcapi`; outside HAIP, which uses OpenID4VP over the DC API) | — |
| ISO/IEC 18013-5 second edition: `ReaderAuthAll`, DeviceRequest version "1.1" | — (`mdocdcapi`, which Apple's implementation expects, signs and verifies it; `proximity`'s holder side, `DecodeDeviceRequest`/`VerifyDeviceRequest`, verifies it and decodes `DeviceRequestInfo` use cases, document sets and purpose hints in Multipaz 0.102.0's working representation, which `walletflow` and the mobile libraries expose; `proximity`'s reader still sends the first edition's per-`DocRequest` `ReaderAuth`) | CD ballot resolution draft. The `DeviceRequestInfo` representation and the proximity validity profile are checked against Multipaz 0.102.0 (interop cases and a checked-in fixture bundle), not yet against the ballot text: the ballot revision and clauses remain to be identified before a release describes it as conformant |
| ISO/IEC TS 23220-2 and the 23220-4 draft — Photo ID (`org.iso.23220.photoid.1`) | — (`examples/passport-vdc` only; checked against open implementations, not 23220-4 itself) | — |

## Beyond HAIP

HAIP covers OpenID4VCI and OpenID4VP. These are the other protocols
the library implements, for a wallet's presentations outside the
redirect flow.

| Spec | Used by | Version |
|---|---|---|
| [ISO/IEC 18013-5:2021][iso18013-5] §8.2–§8.3 (device engagement by QR or NFC, §8.2.2; BLE GATT and NFC data retrieval, §8.3.3.1.2), §9.1 (session encryption, §9.1.4 reader authentication), Annex B (reader authentication EKU 1.0.18013.5.1.6), Annex D (test vectors) | `proximity`, `proximity/nfcapdu`, `internal/readerauth` | First edition |
| ISO/IEC 7816-4 command APDUs, and the NFC Forum's Type 4 Tag NDEF application, Connection Handover and TNEP, as ISO/IEC 18013-5 §8.2.2 and §8.3.3.1.2 use them | `proximity/nfcapdu` | As ISO/IEC 18013-5 references them |
| OpenID4VP 1.0 Appendix A — the Digital Credentials API | `verifier`, `wallet`, `walletflow` (HAIP §5.2 profiles it: unsigned, signed and multi-signed requests) | Final |
| OpenID4VP 1.0 §5.9.3 — the `x509_san_dns` Client Identifier Prefix | `wallet`, `walletflow`, `mobile`, opt-in (`AcceptX509SANDNS`, `accept_x509_san_dns`), never `verifier`. HAIP 1.0 §5 has a Verifier use, and a Wallet accept, `x509_hash` for signed requests, and doesn't forbid a Wallet another prefix; the Wallet accepts `x509_hash` either way | Final |
| [W3C Digital Credentials][dcapi] | The browser API the DC API flows run over; this library builds and answers the requests, the platform invokes the API | Not pinned: what Safari and Chrome ship |
| [RFC 9180 — HPKE][hpke] | `mdocdcapi` (ISO/IEC TS 18013-7 Annex C's response encryption) | Informational |

Platform APIs the mobile wallets use, not specifications: Apple's
IdentityDocumentServices (an iOS document provider for `org-iso-mdoc`)
and Android's Credential Manager (`androidx.credentials` registry
providers for OpenID4VP). See [mobile/MOBILE.md](mobile/MOBILE.md).

## Attestation

| Spec | Pinned by | Draft |
|---|---|---|
| [OAuth 2.0 Attestation-Based Client Authentication][attclientauth] | OID4VCI 1.0 §14.7, Appendix E | `draft-ietf-oauth-attestation-based-client-auth-07` (2025-09-15) |
| OID4VCI 1.0 Appendix D — Key Attestation | OID4VCI 1.0, HAIP §4.5.1 | — |
| OID4VCI 1.0 Appendix E — Wallet Attestation | OID4VCI 1.0, HAIP §4.4.1 | — |

Wallet Attestation's format is the Client Attestation JWT of §5.1 of the
attestation-based-client-auth draft, plus OID4VCI-specific claims (Appendix
E). This is the client authentication mechanism HAIP requires in place of
FAPI 2.0's normal `private_key_jwt`/mTLS — implemented by FAPIgo's
`server` and `client` (`storage.ClientAuthMethodAttestation`); see
AGENTS.md's "Relationship to FAPIgo". Since FAPIgo v0.66.0,
`server.X5CAttesterChain` refuses a Wallet Attestation whose `x5c`
carries the trust anchor (HAIP 1.0) or whose signer certificate was
issued for another role, and production holds a Client Attestation
PoP's age to 5 minutes.

## Status

| Spec | Pinned by | Draft |
|---|---|---|
| [Token Status List (TSL)][statuslist] | HAIP 1.0 §9.4 (overriding OID4VCI 1.0 §14.7's draft-12), Appendix D/E `status` claim | `draft-ietf-oauth-status-list-14` (2025-12-10) |
| ISO/IEC 18013-5 second edition §12.3.6.4 — identifier list (an mdoc's `status.identifier_list`), its Annex D.6 example; [RFC 9360][x5chain] x5chain | — (`identifierlist`; outside HAIP, which names only Token Status List) | CD ballot resolution draft |

HAIP 1.0 §9.4 pins SD-JWT VC draft-13 and Token Status List draft-14,
and states that its versions "overwrite the versions previously
mentioned in" OID4VCI and OID4VP. This library targets HAIP, so it
follows HAIP's. Relative to the drafts OID4VCI names, the changes that
reach this code are SD-JWT VC Type Metadata's (no JSON Schema, `locale`
instead of `lang`, `mandatory` claims, `vct` required) and a Status List
Token CWT that may be untagged; the credential formats and verification
rules are otherwise unchanged.

Section numbers this repository cites for SD-JWT VC and Token Status
List, in code and documentation, are those of the pinned drafts
(draft-13 and draft-14), unless another draft is named alongside them.
Later drafts renumber sections.

One later SD-JWT VC addition is implemented ahead of HAIP: draft-19
§2.2.2.2's `aka_vcts`, the other types a credential is of. It's
optional, and draft-13 permits a claim it doesn't define. An Issuer can
set it (`sdjwtvc.Claims.AkaVCTs`). It's always plaintext, and `Verify`
refuses one that's disclosable, empty, or contains the credential's own
`vct`. DCQL `vct_values` matching, in both the wallet and the verifier,
accepts a credential whose `vct` or any `aka_vcts` value is requested;
that is the derived-type answer OpenID4VP 1.0 §B.3.5 allows. A type
matched this way is still no evidence that the Issuer may issue it
(draft-19 §7.7): trusting the Issuer for the type stays the verifier's
own check.

## Query language (OID4VP)

OID4VP 1.0 Final uses **DCQL** (Digital Credentials Query Language, §6) as
its sole credential-request query mechanism — the older Presentation
Exchange draft mechanism is not part of the Final spec and is not
implemented here.

## JOSE / crypto foundations

- [RFC 7515 — JWS][jws], [RFC 7516 — JWE][jwe], [RFC 7517 — JWK][jwk],
  [RFC 7518 — JWA][jwa], [RFC 7519 — JWT][jwt]
- [RFC 9052 — CBOR Object Signing and Encryption (COSE)][cose] — mdoc's
  `IssuerSigned`/`DeviceSigned` structures (ISO 18013-5) are COSE_Sign1-based.

## Known leniencies

Where this library (or FAPIgo, for the OAuth layer) accepts input a
specification says to refuse, or doesn't implement all a specification
asks of a reader, deliberately or not yet. None lets a credential,
presentation or client authentication through that fails a signature or
trust check.

- **Client Attestation PoP without `iss`.** The pinned
  attestation-based-client-auth draft-07 §5.2 makes the PoP JWT's `iss`
  required. FAPIgo's `server`, which verifies Wallet Attestations for
  this library's Authorization Server, accepts a PoP without one,
  checking `aud`, `jti`, `iat` and the signature by the attested key as
  usual; a PoP with an `iss` must name the client. This is FAPIgo's to
  change.
- **Encryption JWKs without `alg`.** OpenID4VP 1.0 §8.3 requires the
  Verifier's response encryption JWK to carry `alg`. The wallet accepts
  an EC P-256 key with `alg` absent and uses it for ECDH-ES, as it does
  for an Issuer's credential request encryption key (OpenID4VCI 1.0
  §10): a key whose `alg` names another algorithm is still passed over.
- **A Verifier's `request_uri_method=post`.** With
  `TransactionsConfig.RequestURIMethodPost`, `verifier.Transactions`
  answers a request_uri POST (OpenID4VP 1.0 §5.10) with a Request
  Object carrying its `wallet_nonce`, and still serves `GET` to a
  Wallet that doesn't support POST (§5.1). Where it reads the spec
  loosely: its links carry no `client_metadata`, which §5.1 says a
  Verifier asking for `post` SHOULD add when it has no other means to
  convey its capabilities (the Request Object carries them, and §5.10.1
  has the Wallet use only its parameters; a link with the response key
  and formats in it makes a denser QR code); a `wallet_metadata`
  without `vp_formats_supported`, which §10.1 makes REQUIRED, is
  accepted and narrows nothing, as is one without
  `client_id_prefixes_supported`, whose §10.1 default,
  `pre-registered`, would refuse §5.10's own example; and a `jwks` for
  an encrypted Request Object is ignored, §5.10.1 answering with "a
  signed, optionally encrypted, request object". A refused POST is an
  HTTP 400 (413, 415) with RFC 6749's `invalid_request`: §5.10.2
  defines no error code, only that the Wallet terminates on any HTTP
  error, and §8.5's codes are the Wallet's.
- **Request encryption JWKs without `kid`.** OpenID4VCI 1.0 §12.2.4
  requires a `kid` on each key in an Issuer's
  `credential_request_encryption.jwks`. The wallet takes the first EC
  P-256 ECDH-ES key it can encrypt to whether it has one or not, and a
  JWE to a key without one carries no `kid` header (OpenID4VCI 1.0
  §10). This library's `issuer` publishes a `kid` on each of its own
  keys, which it requires, and refuses a JWE that names none
  (`invalid_encryption_parameters`).
- **Unrecognised Credential Request members** are ignored (OpenID4VCI
  1.0 §8.2), but one that differs from a known member only in case is
  refused, deliberately: parsers that fold case would read it as the
  known member.
- **JWE headers.** A `zip` that isn't a string, or is empty, is read as
  no compression rather than refused (RFC 7516 §4.1.3), and an `epk`
  carrying a private `d` member is accepted, its `d` ignored (RFC 7518
  §4.6.1.1).
- **mdoc encoding.** A one-element `x5chain` array is accepted as well as
  the single byte string RFC 9360 §2 asks for, and a `tdate` in an MSO's
  validityInfo is accepted with fractional seconds or a UTC offset,
  which ISO/IEC 18013-5 §12.3.4 excludes; `mdoc.Issue` produces neither.
- **mdoc rules for the issuer.** A reader doesn't check that each
  IssuerSignedItem's `random` is at least 16 bytes (ISO/IEC 18013-5
  §12.3.5), or that an MSO's `validFrom` is no earlier than its
  `signed` (§12.3.4): a credential that breaks either tells a reader
  nothing false, so `mdoc.Verify` accepts it. `mdoc.Issue` meets both.
- **A DeviceResponse's `documentErrors`** are decoded but not read.
  The OpenID4VP and ISO/IEC TS 18013-7 Annex C readers take the
  documents a response carries and ignore its `documentErrors`; the
  proximity reader reports them only when no document came back
  (`proximity.ErrNoDocument`). A request for several documents
  answered with some of them gives the caller those, without the
  reason the others are missing.
- **mdoc status lists with `bits` other than 1.** ISO/IEC 18013-5
  §12.3.6.5 requires one bit per status for a list an mdoc references.
  Neither `statuslist.Publisher` nor the Checker enforces it; a list
  with any valid `bits` is read correctly.
- **mdoc algorithms.** A reader is to support every algorithm and curve
  ISO/IEC 18013-5 §12.3.4 and §12.7.2 list. This library supports the
  ones Go's standard library implements: ES256 (P-256), ES384 (P-384),
  ES512 (P-521) and EdDSA (Ed25519) for issuer, device and reader
  authentication and for CWT status and identifier lists, and P-256,
  P-384 and P-521 for a proximity session's ephemeral keys and device
  MAC. The brainpool curves (brainpoolP256r1, P320r1, P384r1, P512r1)
  and Ed448 are refused with an error naming the curve
  (`credential/mdoc`'s package doc, "Algorithm and curve support"). A
  proximity holder generates its own ephemeral key on P-256, and the
  Digital Credentials API's HPKE suite (Annex C) is DHKEM(P-256) as
  specified. JOSE (SD-JWT VC, JWT status lists) verifies ES256, ES384,
  ES512 and EdDSA too, but signs ES256 and EdDSA only.

## Known strictness

Where this library refuses input a specification allows, or requires
more than it asks, deliberately. Each can stop an exchange with another
implementation that relies on the latitude. Most aren't needed for the
security of an exchange both sides run as this library does; those that
guard against a third party say so.

- **An `x509_san_dns` request's `response_uri` must be on its DNS
  name**, always (outside the DC API). OpenID4VP 1.0 §5.9.3 lets a
  Wallet that "can establish trust in the Client Identifier ... e.g.
  because the Client Identifier is contained in a list of trusted
  Client Identifiers" let the Verifier choose it freely; the wallet
  keeps no such list, so the response never goes to a host the
  certificate doesn't name. The name must also be a dNSName of the
  signing certificate exactly, without regard to case: a wildcard
  dNSName matches no `client_id`, and a `client_id` that isn't a host
  name (an IP address, a wildcard) is refused. And the prefix is
  refused without trust anchors (`NoVerifierTrust`), since the name
  alone binds the request to no one.
- **A key attestation attesting more keys than `batch_size`** is
  refused (`invalid_proof`), though OpenID4VCI 1.0 Appendix F.3 only
  asks the Issuer to issue for each attested key, which `batch_size`
  (§12.2.4) bounds as a `proofs` array. `batch_size` then bounds what
  one request has the Issuer sign, whichever way the keys arrive.
- **A key attestation's `nonce` must be the proof's own c_nonce.**
  OpenID4VCI 1.0 Appendix F.1 asks for "a" c_nonce the server provided.
  Tying it to the one the request spends makes the attestation as
  single-use as the proof.
- **A presentation may disclose only what its own Credential Query
  selected.** OpenID4VP 1.0 §6.4 lets a presentation carry claims
  another query of the same request selected for the same credential;
  the Verifier checks each presentation against its own query.
- **An empty `vp_token`** (every credential set optional, nothing
  matched; OpenID4VP 1.0 §6.4.2, §8.1) is neither built by the wallet
  nor accepted by the Verifier: a request that can be answered with
  nothing is answered with an error.
- **Answering more than one option of a credential set** is refused
  (`dcql`): §6.4.2 has the wallet return one option.
- **Two claim queries on the same path that differ otherwise** fail
  the request, where OpenID4VP 1.0 §6.1 has wallets ignore duplicates;
  the wallet drops only exact duplicates.
- **`trusted_authorities` by authority key identifier** matches an
  intermediate only by the key identifiers derived from its own key
  (RFC 5280 §4.2.1.2 method 1, RFC 7093 method 1), where OpenID4VP 1.0
  §6.1.1.1 compares the raw bytes: a declared `subjectKeyIdentifier`
  is something an attacker can copy into a certificate of their own.
  A CA whose key identifiers come from another method is matched only
  as an anchor.
- **An SD-JWT VC with the transitional `vc+sd-jwt` typ** is refused
  unless `sdjwtvc.VerifyOptions.AcceptLegacyTyp` is set, where SD-JWT
  VC draft-13 §3.2.1, the version HAIP 1.0 names, recommends that
  Holders and Verifiers accept it for a transition period. Draft-19
  dropped that; only `dc+sd-jwt` is accepted by default, by the
  verifier and wallet too.
- **A Status List Token without `exp`** issued more than a day ago
  (`statuslist.DefaultMaxAgeWithoutExp`) is refused unless
  `VerifyOptions.MaxAge` says otherwise. `exp` is optional (Token
  Status List draft-14 §5.1) and freshness is the Relying Party's
  policy (§8.3); a list signed before a revocation and replayed from a
  cache would otherwise be accepted for ever.
- **Two documents of the same docType in one DeviceResponse** are
  refused (proximity and ISO/IEC 18013-7 Annex C): documents are
  matched to the reader's requests by docType, so a request can't ask
  for one docType twice. The holder side refuses such a DeviceRequest
  too (`proximity.ParseDeviceRequest` and `DecodeDeviceRequest`,
  `mdocdcapi.ParseRequest`).
- **The `attestation` proof type** (OpenID4VCI 1.0 Appendix F.3, one
  of the two combinations HAIP 1.0 §4.5.1 names) is refused by
  `issuer.New` under `AssuranceProduction` unless
  `Config.AllowAttestationProofType` is set, and then only with a Nonce
  Endpoint. It guards against a third party: a key attestation names
  no audience, so another issuer that fetched a c_nonce here could
  relay a Wallet's attestation. A Wallet that sends only `attestation`
  proofs finds just `jwt` in `proof_types_supported`;
  `haip.RecommendedJWTKeyAttestationProofType` is HAIP's other
  combination, a `jwt` proof carrying the key attestation in its
  `key_attestation` header.
- **A claim whose value isn't among its claims query's `values`**
  fails the Credential Query at the Verifier. OpenID4VP 1.0 §6.3 has
  the Wallet return such a claim only when its value matches, which
  this library's wallet does; the Verifier checks the same of what it
  received (`ReasonNotAnswered`), so a Wallet that returns the claim
  anyway has its response refused, `verifier.Transactions` answering
  the Response URI's POST with 400 `invalid_request`.
- **An mdoc's ECDSA algorithm must match its key's curve**: ES256 with
  P-256, ES384 with P-384, ES512 with P-521, for issuer, device and
  reader authentication and CWT status and identifier lists. RFC 9053
  §2.1 only suggests that pairing: an ES256 signature by a P-384 key,
  say, is refused rather than verified, as is a protected `alg` other
  than the one the key's curve gives (`internal/cose`).
- **Authorization errors before the user is authenticated** are shown
  on the Authorization Server's own page under `AssuranceProduction`,
  not redirected to the client. FAPIgo's `server` can't trust a
  redirect destination for a request it couldn't validate (an unknown,
  expired or reused `request_uri`, another client's, or a client no
  longer registered: `server.LocalErrorResponse`), where RFC 6749
  §4.1.2.1 redirects every error but a bad client or redirect URI.
  `server.BuildAuthorizationErrorRedirect` sends one to a redirect URI
  the client registered, but only under `AssuranceDevelopment`. Under
  production it refuses, guarding against a third party: any
  registered client could otherwise have the server send users to a
  page of its own, which RFC 9700 §4.11.2 forbids before the user has
  authenticated. The conformance binaries run at development and
  redirect, for the OIDF suite's negative modules; under
  `cmd/conformance-issuer`'s production setup those modules end
  `REVIEW` instead, waiting for a screenshot of the error page
  (`conformance/issuer/README.md`'s "Production setup"). A Wallet sees the
  browser stop at the error page; errors once the user is
  authenticated, a denial among them, are redirected as usual.
- **An `org-iso-mdoc` Digital Credentials API answer that withholds a
  requested element** is refused (`ReasonNotAnswered`), and the request
  stays open, unless `verifier.MdocDCAPIRequest.AllowWithheld` is set.
  ISO/IEC 18013-5 lets a holder withhold any element; refusing makes
  every element of the request required, as each claim of an OpenID4VP
  request's Credential Query is. A Wallet whose holder left an element
  out gets no completed presentation.

## HAIP's deviations from plain FAPI 2.0

Confirmed directly against HAIP 1.0's text (not paraphrased from memory):

- **Client authentication**: "Wallet Attestation … can be used" (HAIP §4.4,
  §4.4.1) in place of FAPI 2.0's `private_key_jwt`/mTLS client
  authentication. Wallets MUST authenticate at the PAR endpoint using the
  same rule as the token endpoint.
- **DPoP**: mandatory — "MUST support DPoP as defined in [RFC9449]" —
  where plain FAPI 2.0 treats sender-constraining as MTLS-or-DPoP.
  mTLS itself is explicitly called out as not generally applicable:
  "some optional parts of [FAPI2_Security_Profile] are not applicable when
  using only OpenID for Verifiable Credential Issuance, e.g., MTLS or
  OpenID Connect."
- **PAR**: required "only when using the Authorization Endpoint" (HAIP
  §4.3) — i.e. conditional on flow, not unconditional the way FAPI 2.0
  Security Profile Final otherwise treats it.
- **Cryptography**: HAIP §7 overrides FAPI 2.0 Security Profile Final
  §5.4.1 clause 1's algorithm requirements with its own: ES256 "at a
  minimum", for every entity. OID4VCgo signs its JWSs with ES256 (or
  EdDSA, where a caller configures it), and verifies ES256, ES384
  (P-384), ES512 (P-521) and EdDSA (Ed25519) wherever it verifies one:
  Request Objects, SD-JWT VC Issuer-signed JWTs and Key Binding JWTs,
  Token Status List JWTs, signed Credential Issuer Metadata, jwt
  proofs and key attestations. Each ECDSA algorithm verifies with a
  key on its own curve only (RFC 7518 §3.4), and the algorithm is taken
  from the trusted key, not from the token's header. An issuer's
  `proof_signing_alg_values_supported` may list ES384 and ES512.

## Scope note

HAIP as a whole spans both OID4VCI (issuance) and OID4VP (presentation);
OID4VCgo's name covers both, not issuance alone — the repo's own scope
is the full HAIP profile: `issuer` + wallet's OID4VCI role, and
`verifier` + wallet's OID4VP presentation role. It also implements the
mdoc protocols in "Beyond HAIP" above, which HAIP doesn't profile. See
ARCHITECTURE.md for the package layout.

[oid4vci]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[oid4vp]: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
[haip]: https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html
[fapi2]: https://openid.net/specs/fapi-security-profile-2_0.html
[dpop]: https://www.rfc-editor.org/rfc/rfc9449.html
[par]: https://www.rfc-editor.org/rfc/rfc9126.html
[pkce]: https://www.rfc-editor.org/rfc/rfc7636.html
[iss]: https://www.rfc-editor.org/rfc/rfc9207.html
[asmeta]: https://www.rfc-editor.org/rfc/rfc8414.html
[revocation]: https://www.rfc-editor.org/rfc/rfc7009.html
[bearer]: https://www.rfc-editor.org/rfc/rfc6750.html
[sdjwtvc]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-13
[iso18013-5]: https://www.iso.org/standard/69084.html
[iso18013-7]: https://www.iso.org/standard/91154.html
[attclientauth]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07
[statuslist]: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-14
[jws]: https://www.rfc-editor.org/rfc/rfc7515.html
[jwe]: https://www.rfc-editor.org/rfc/rfc7516.html
[jwk]: https://www.rfc-editor.org/rfc/rfc7517.html
[jwa]: https://www.rfc-editor.org/rfc/rfc7518.html
[jwt]: https://www.rfc-editor.org/rfc/rfc7519.html
[cose]: https://www.rfc-editor.org/rfc/rfc9052.html
[x5chain]: https://www.rfc-editor.org/rfc/rfc9360.html
[dcapi]: https://www.w3.org/TR/digital-credentials/
[hpke]: https://www.rfc-editor.org/rfc/rfc9180.html

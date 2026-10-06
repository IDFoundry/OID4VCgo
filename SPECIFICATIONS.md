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

## Credential formats (HAIP requires at least one; OID4VCgo supports both)

| Spec | Pinned by | Draft |
|---|---|---|
| [SD-JWT-based Verifiable Credentials (SD-JWT VC)][sdjwtvc] | HAIP 1.0 §9.4 (overriding OID4VCI 1.0 §14.7's draft-11) | `draft-ietf-oauth-sd-jwt-vc-13` (2025-11-06) |
| [ISO/IEC 18013-5:2021 — mdoc][iso18013-5] | OID4VCI 1.0 Appendix A.2, HAIP §5.3.1 | — |
| ISO/IEC 23220 series | HAIP §5.3.1 (mdoc presentation specifics) | — |
| [ISO/IEC TS 18013-7:2025 — mdoc online presentation][iso18013-7], Annex C (`org-iso-mdoc` over the Digital Credentials API) | — (`mdocdcapi`; outside HAIP, which uses OpenID4VP over the DC API) | — |
| ISO/IEC 18013-5 second edition: `ReaderAuthAll`, DeviceRequest version "1.1" | — (`mdocdcapi` only, which Apple's implementation expects; `proximity` uses the first edition's per-`DocRequest` `ReaderAuth`) | CD ballot resolution draft |
| ISO/IEC TS 23220-2 and the 23220-4 draft — Photo ID (`org.iso.23220.photoid.1`) | — (`examples/passport-vdc` only; checked against open implementations, not 23220-4 itself) | — |

## Beyond HAIP

HAIP covers OpenID4VCI and OpenID4VP. These are the other protocols
the library implements, for a wallet's presentations outside the
redirect flow.

| Spec | Used by | Version |
|---|---|---|
| [ISO/IEC 18013-5:2021][iso18013-5] §8.2–§8.3 (device engagement, BLE GATT), §9.1 (session encryption, §9.1.4 reader authentication), Annex B (reader authentication EKU 1.0.18013.5.1.6), Annex D (test vectors) | `proximity`, `internal/readerauth` | First edition |
| OpenID4VP 1.0 Appendix A — the Digital Credentials API | `verifier`, `wallet`, `walletflow` (HAIP §5.2 profiles it: unsigned, signed and multi-signed requests) | Final |
| [W3C Digital Credentials][dcapi] | The browser API the DC API flows run over; this library builds and answers the requests, the platform invokes the API | Not pinned: what Safari and Chrome ship |
| [RFC 9180 — HPKE][hpke] | `mdocdcapi` (ISO/IEC TS 18013-7 Annex C's response encryption) | Informational |

Platform APIs the mobile wallets use, not specifications: Apple's
IdentityDocumentServices (an iOS document provider for `org-iso-mdoc`)
and Android's Credential Manager (`androidx.credentials` registry
providers for OpenID4VP). See [MOBILE.md](MOBILE.md).

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
AGENTS.md's "Relationship to FAPIgo".

## Status

| Spec | Pinned by | Draft |
|---|---|---|
| [Token Status List (TSL)][statuslist] | HAIP 1.0 §9.4 (overriding OID4VCI 1.0 §14.7's draft-12), Appendix D/E `status` claim | `draft-ietf-oauth-status-list-14` (2025-12-10) |

HAIP 1.0 §9.4 pins SD-JWT VC draft-13 and Token Status List draft-14,
and states that its versions "overwrite the versions previously
mentioned in" OID4VCI and OID4VP. This library targets HAIP, so it
follows HAIP's. Relative to the drafts OID4VCI names, the changes that
reach this code are SD-JWT VC Type Metadata's (no JSON Schema, `locale`
instead of `lang`, `mandatory` claims, `vct` required) and a Status List
Token CWT that may be untagged; the credential formats and verification
rules are otherwise unchanged.

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
  §5.4.1 clause 1's algorithm requirements with its own.

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
[dcapi]: https://www.w3.org/TR/digital-credentials/
[hpke]: https://www.rfc-editor.org/rfc/rfc9180.html

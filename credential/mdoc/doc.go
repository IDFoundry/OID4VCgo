// Package mdoc implements ISO/IEC 18013-5 mdoc credential's data
// structures for both roles: IssuerSigned (the namespace/data-element
// digest-and-salt selective-disclosure mechanism, §10.3.3), the Mobile
// Security Object (MSO, §12.3.4), and IssuerAuth on the issuer side;
// DeviceSigned and mdoc authentication (§10.3.3, §12.4) on the
// Holder/presentation side. Both are built on internal/cose the way
// credential/sdjwtvc is built on internal/jose.
//
// Citations throughout this package are to the CD ballot resolution
// draft of ISO/IEC 18013-5's second edition (dated 2025-09-14) — see
// SPECIFICATIONS.md and ARCHITECTURE.md for why that document, not yet
// the paywalled published text, is this package's primary source.
//
// # Scope
//
// Issue and Verify cover the issuer-side envelope: IssuerSigned, the
// MSO, and IssuerAuth, plus DeviceKeyInfo (the mdoc analog of SD-JWT
// VC's cnf.jwk — see CoseKey). SignDeviceSignature/VerifyDeviceSignature
// and ComputeDeviceMAC/VerifyDeviceMAC cover DeviceSigned: the Holder's
// own proof of possession of the mdoc authentication key at
// presentation time, via either of §12.4's two mechanisms. Building
// SessionTranscript itself (DeviceEngagement, EReaderKey, Handover,
// §12.7.1) is deliberately out of scope: for an OID4VP presentation
// this needs OID4VP's own "Handover" construction, a different spec's
// concern entirely, not ISO/IEC 18013-5's proximity-flow one — every
// function that needs it takes SessionTranscriptBytes as an opaque,
// caller-supplied value instead, the same "resolving trust is the
// caller's job" split this package already draws for the Issuer's
// public key. MSO revocation (the optional "status" member, §12.3.6)
// is wired in for the status_list mechanism only (Claims.Status,
// MobileSecurityObject.Status, VerifiedMSO.Status) — the same scope
// credential/sdjwtvc.Claims.Status already takes; §12.3.6.4's own
// ISO-specific identifier_list alternative isn't modeled, and this
// package never fetches or checks the referenced list itself (that
// needs statuslist.CWTStatusClaim/ParseCWTStatusClaim and an actual
// list fetch, entirely the caller's own job).
//
// # Algorithm and curve support
//
// Matches internal/cose's curated set exactly: ES256 (P-256) and EdDSA
// (Ed25519) for IssuerAuth's and DeviceSignature's signatures, and the
// corresponding COSE_Key types for DeviceKeyInfo.DeviceKey (CoseKey).
// DeviceMac is narrower still — P-256 only, since MAC authentication
// requires ECDH, which Ed25519 keys don't support (see deriveEMacKey).
// ISO/IEC 18013-5 also permits ES384/ES512 and additional
// brainpool/Ed448 curves (§12.3.4); extend here only once internal/cose
// itself grows that support, to keep the two packages' capabilities
// from silently diverging.
//
// # Building a namespace/data-element tree
//
// Issue takes Claims.NameSpaces as a map of namespace to a map of data
// element identifier to value; SignDeviceSignature/ComputeDeviceMAC
// take the same shape for DeviceSigned's own NameSpaces. Every
// IssuerSigned element becomes its own IssuerSignedItem with a random
// ≥16-byte salt (§12.3.5) and a randomly assigned DigestID unique
// within its namespace — deliberately not sequential, since §12.3.4
// requires "no correlation" between the DigestIDs used for the same
// element across different MSOs. An element's value can be any type
// github.com/fxamacker/cbor/v2 encodes — a plain Go value, or a
// cbor.Tag for one of mdoc's date tags (0 for tdate, 1004 for
// full-date) — this package has no opinion on namespace-specific data
// models (the mDL data elements of org.iso.18013.5.1, for instance) any
// more than credential/sdjwtvc has an opinion on the claims inside
// Claims.Additional.
//
// If an element's value is (or contains) a native Go map, encoding it
// twice can produce different bytes each time — Go deliberately
// randomizes map iteration order. IssuerSigned and DeviceSigned both
// cache the exact bytes they authenticated internally (see their own
// doc comments) precisely so this doesn't matter for the real
// Issue/Sign → Marshal → Unmarshal → Verify pipeline; it only matters
// if you build one of those types directly as a struct literal rather
// than through this package's own constructors.
//
// # Presenting a subset of what was issued
//
// IssuerSigned.SelectNameSpaces implements §10.3.3's own selective
// disclosure mechanism on the Holder's side: a Holder may present only
// some of the namespace/data elements an Issuer originally signed,
// since each IssuerSignedItem's digest is checked independently
// against the MSO's own valueDigests (Verify still succeeds against a
// trimmed IssuerSigned, since trimming never touches an item's own
// bytes or salt, only which items are included at all). It carries the
// rawItems cache forward for whichever items survive the trim, for the
// same reason Issue/UnmarshalIssuerSigned populate it in the first
// place — see wallet.PresentMdocSelective for where this feeds into an
// OID4VP Presentation.
//
// # Verifying
//
// Verify expects the Issuer's already-resolved public key, the same
// separation credential/sdjwtvc's Verify draws: resolving which key
// that is (via the IssuerAuth x5chain and an Issuer trust policy) is a
// caller concern, not this package's. VerifyDeviceSignature/
// VerifyDeviceMAC expect the mdoc authentication public key the same
// way — ordinarily VerifiedMSO.DeviceKey, from a prior successful
// Verify call. CheckKeyAuthorizations implements the one additional
// mdoc-authentication-specific check §12.8.2 requires: that every
// namespace/element DeviceSigned discloses is actually authorized for
// the key that authenticated it.
package mdoc

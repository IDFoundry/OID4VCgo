// Package mdoc implements the ISO/IEC 18013-5 mdoc credential format's
// issuer-side data structures: IssuerSigned (the namespace/data-element
// digest-and-salt selective-disclosure mechanism, §10.3.3), the Mobile
// Security Object (MSO, §12.3.4), and IssuerAuth, the COSE_Sign1
// envelope that signs it — built on internal/cose the way
// credential/sdjwtvc is built on internal/jose.
//
// Citations throughout this package are to the CD ballot resolution
// draft of ISO/IEC 18013-5's second edition (dated 2025-09-14) — see
// SPECIFICATIONS.md and ARCHITECTURE.md for why that document, not yet
// the paywalled published text, is this package's primary source.
//
// # Scope
//
// This is deliberately just the issuer-side envelope: Issue and Verify
// cover IssuerSigned, the MSO, and IssuerAuth, plus DeviceKeyInfo (the
// mdoc analog of SD-JWT VC's cnf.jwk — see CoseKey). DeviceSigned (the
// Holder's own proof of possession at presentation time, §10.3.3,
// §12.4) is out of scope here, the same way credential/sdjwtvc's Key
// Binding JWT is a distinct concern from Issue/Verify — it belongs with
// a future presentation-side package once OID4VP work starts. MSO
// revocation (the optional "status" member, §12.3.6) is also deferred:
// it needs statuslist's CWT/COSE encoding, which doesn't exist yet
// (statuslist currently only implements the JWT/JOSE encoding).
//
// # Algorithm and curve support
//
// Matches internal/cose's curated set exactly: ES256 (P-256) and EdDSA
// (Ed25519) for IssuerAuth's signature, and the corresponding COSE_Key
// types for DeviceKeyInfo.DeviceKey (CoseKey). ISO/IEC 18013-5 also
// permits ES384/ES512 and additional brainpool/Ed448 curves (§12.3.4);
// extend here only once internal/cose itself grows that support, to
// keep the two packages' capabilities from silently diverging.
//
// # Building a namespace/data-element tree
//
// Issue takes Claims.NameSpaces as a map of namespace to a map of data
// element identifier to value. Every element becomes its own
// IssuerSignedItem with a random ≥16-byte salt (§12.3.5) and a randomly
// assigned DigestID unique within its namespace — deliberately not
// sequential, since §12.3.4 requires "no correlation" between the
// DigestIDs used for the same element across different MSOs. An
// element's value can be any type github.com/fxamacker/cbor/v2 encodes
// — a plain Go value, or a cbor.Tag for one of mdoc's date tags (0 for
// tdate, 1004 for full-date) — this package has no opinion on
// namespace-specific data models (the mDL data elements of
// org.iso.18013.5.1, for instance) any more than credential/sdjwtvc has
// an opinion on the claims inside Claims.Additional.
//
// # Verifying
//
// Verify expects the Issuer's already-resolved public key, the same
// separation credential/sdjwtvc's Verify draws: resolving which key
// that is (via the IssuerAuth x5chain and an Issuer trust policy) is a
// caller concern, not this package's.
package mdoc

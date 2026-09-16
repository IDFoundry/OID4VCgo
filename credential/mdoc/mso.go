package mdoc

import "time"

// DigestAlg identifies an MSO digest algorithm (Table 16).
type DigestAlg string

const (
	SHA256 DigestAlg = "SHA-256"
	SHA384 DigestAlg = "SHA-384"
	SHA512 DigestAlg = "SHA-512"
)

// mobileSecurityObjectVersion is the only value §12.3.4 defines for the
// MSO's own "version" member (distinct from DeviceResponse's "version").
const mobileSecurityObjectVersion = "1.0"

// MobileSecurityObject is the MSO (§12.3.4) — the payload IssuerAuth
// signs.
type MobileSecurityObject struct {
	Version         string               `cbor:"version"`
	DigestAlgorithm DigestAlg            `cbor:"digestAlgorithm"`
	ValueDigests    map[string]DigestIDs `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo        `cbor:"deviceKeyInfo"`
	DocType         string               `cbor:"docType"`
	ValidityInfo    ValidityInfo         `cbor:"validityInfo"`

	// Status is OPTIONAL: MSO revocation information (§12.3.6) — see
	// its own doc comment for what's modeled.
	Status *Status `cbor:"status,omitempty"`
}

// Status is the MSO's own optional "status" element (§12.3.6.2): a
// pointer to an externally-hosted MSO revocation list, via either of
// §12.3.6's two mechanisms — status_list (draft-ietf-oauth-status-list,
// via StatusListRef, the same scope credential/sdjwtvc.Claims.Status
// already takes) or identifier_list (§12.3.6.4's ISO-specific
// alternative, via IdentifierListRef). §12.3.6 itself presents these as
// two alternative ways an issuer implements MSO revocation, not as a
// pair whose simultaneous use it explicitly forbids — the CDDL marks
// both members independently optional, with no stated exclusivity.
// Issue nonetheless rejects a Claims value that sets both, as this
// package's own conservative default (every worked example and every
// deployment this package has reason to expect picks one mechanism per
// MSO); relax this if a real, spec-compliant deployment ever needs
// both set at once.
type Status struct {
	IdentifierList *IdentifierListRef `cbor:"identifier_list,omitempty"`
	StatusList     *StatusListRef     `cbor:"status_list,omitempty"`
}

// IdentifierListRef is the MSO's own "identifier_list" element
// (§12.3.6.2, §12.3.6.4): a pointer to an externally-hosted identifier
// list, the ISO-specific alternative to StatusListRef — an mdoc reader
// treats this MSO as revoked if ID appears in the referenced list's own
// "identifiers" map, rather than by indexing into a bit-packed list.
// §12.3.6.4 recommends ID be unique (and ideally random) per MSO, to
// prevent it being used as a correlation handle across presentations.
// Certificate mirrors StatusListRef's own field: present, it's the mdoc
// reader's trust anchor for the identifier list's own x5chain; absent,
// that x5chain must instead chain to whatever certificate signed the
// MSO's own IssuerAuth x5chain certificate (the IACA certificate, for
// an mDL).
//
// This package models only the MSO-level pointer — resolving it
// (fetching the identifier list and checking ID's membership) is
// entirely the caller's own job, the same split StatusListRef already
// draws for the status_list mechanism.
type IdentifierListRef struct {
	ID          []byte `cbor:"id"`
	URI         string `cbor:"uri"`
	Certificate []byte `cbor:"certificate,omitempty"`
}

// StatusListRef is the MSO's own "status_list" element (§12.3.6.2,
// §12.3.6.5): draft-ietf-oauth-status-list's own StatusListInfo
// {idx, uri} — the same logical pointer statuslist.StatusListRef
// represents, kept as this package's own independent type rather than
// importing that package (this package never imports statuslist —
// resolving what to do with a status pointer, including actually
// fetching and checking the referenced list, is entirely the caller's
// job, the same split credential/sdjwtvc.Claims.Status already draws)
// — plus this section's own optional Certificate: a DER certificate
// containing the public key that signed the top-level certificate in
// the MSO revocation list's own x5chain, the mdoc reader's trust
// anchor for that chain when present. Absent means the MSO revocation
// list's top-level certificate must instead be signed by whatever
// certificate signed the MSO's own IssuerAuth x5chain certificate (the
// IACA certificate, for an mDL).
type StatusListRef struct {
	Idx         uint64 `cbor:"idx"`
	URI         string `cbor:"uri"`
	Certificate []byte `cbor:"certificate,omitempty"`
}

// DigestIDs maps a DigestID (§12.3.4: an unsigned integer smaller than
// 2^31, unique within its namespace) to the digest of the matching
// IssuerSignedItemBytes.
type DigestIDs map[uint64][]byte

// DeviceKeyInfo carries the mdoc authentication public key (§12.3.4).
// KeyInfo (extra, mostly-RFU key metadata) isn't modeled — add it only
// once a concrete consumer needs it.
type DeviceKeyInfo struct {
	DeviceKey         CoseKey            `cbor:"deviceKey"`
	KeyAuthorizations *KeyAuthorizations `cbor:"keyAuthorizations,omitempty"`
}

// KeyAuthorizations scopes which namespaces/data elements the device
// key in the enclosing DeviceKeyInfo may authenticate (§12.3.4). A
// namespace listed in NameSpaces must not also appear as a key in
// DataElements.
type KeyAuthorizations struct {
	NameSpaces   []string            `cbor:"nameSpaces,omitempty"`
	DataElements map[string][]string `cbor:"dataElements,omitempty"`
}

// ValidityInfo describes the MSO's validity period (§12.3.4). All
// timestamps are tdate (CBOR tag 0, RFC 3339, no fractional seconds,
// UTC) — see cbor.go's encMode/decMode.
type ValidityInfo struct {
	Signed         time.Time  `cbor:"signed"`
	ValidFrom      time.Time  `cbor:"validFrom"`
	ValidUntil     time.Time  `cbor:"validUntil"`
	ExpectedUpdate *time.Time `cbor:"expectedUpdate,omitempty"`
}

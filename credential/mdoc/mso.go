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
// signs. Its optional "status" member (MSO revocation, §12.3.6) isn't
// modeled yet; add it once statuslist grows the CWT/COSE encoding that
// mechanism needs (see the package doc comment).
type MobileSecurityObject struct {
	Version         string               `cbor:"version"`
	DigestAlgorithm DigestAlg            `cbor:"digestAlgorithm"`
	ValueDigests    map[string]DigestIDs `cbor:"valueDigests"`
	DeviceKeyInfo   DeviceKeyInfo        `cbor:"deviceKeyInfo"`
	DocType         string               `cbor:"docType"`
	ValidityInfo    ValidityInfo         `cbor:"validityInfo"`
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

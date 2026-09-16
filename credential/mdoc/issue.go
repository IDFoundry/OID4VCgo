package mdoc

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

// CredentialFormat is the OID4VCI 1.0 Credential Format Identifier for
// this format (Appendix A.2.1) — the value a Credential Issuer's
// credential_configurations_supported metadata (§12.2.4) uses in its
// "format" member, and a Wallet's authorization_details/Credential
// Request use to select it.
const CredentialFormat = "mso_mdoc" //nolint:gosec // an OID4VCI format identifier, not a credential

// maxDigestID is §12.3.4's bound: "The value shall be smaller than 2^31."
const maxDigestID = 1 << 31

// Claims is the input to Issue.
type Claims struct {
	// DocType identifies the mdoc document type (§8.1), e.g.
	// "org.iso.18013.5.1.mDL". REQUIRED.
	DocType string

	// NameSpaces maps each namespace to its data elements (identifier
	// => value). REQUIRED — at least one namespace with at least one
	// element. A value can be anything github.com/fxamacker/cbor/v2
	// encodes; see the package doc comment for mdoc's date tags.
	NameSpaces map[string]map[string]interface{}

	// DeviceKey is the mdoc holder authentication public key
	// (DeviceKeyInfo.DeviceKey, the analog of SD-JWT VC's cnf.jwk).
	// REQUIRED — must be a type CoseKey's NewCoseKey supports (a P-256
	// *ecdsa.PublicKey or an ed25519.PublicKey).
	DeviceKey crypto.PublicKey

	// KeyAuthorizations optionally scopes DeviceKey (§12.3.4).
	KeyAuthorizations *KeyAuthorizations

	// Signed, ValidFrom and ValidUntil populate ValidityInfo (§12.3.4).
	// All REQUIRED — Issue applies no implicit defaults ("now",
	// "signed + N days", ...); the caller decides.
	Signed     time.Time
	ValidFrom  time.Time
	ValidUntil time.Time

	// ExpectedUpdate optionally populates ValidityInfo.ExpectedUpdate.
	ExpectedUpdate *time.Time

	// Status optionally populates the MSO's own "status.status_list"
	// element (§12.3.6.2) — see StatusListRef's own doc comment. Flat
	// here (unlike MobileSecurityObject.Status's own nesting) matching
	// this struct's existing ValidityInfo-flattening convention; Issue
	// wraps it into the real wire shape.
	Status *StatusListRef

	// IdentifierList optionally populates the MSO's own
	// "status.identifier_list" element (§12.3.6.2) — see
	// IdentifierListRef's own doc comment. Flat, the same as Status; at
	// most one of Status and IdentifierList may be set — see Status's
	// own doc comment (in mso.go) for why this package enforces that as
	// its own conservative default rather than a literal §12.3.6 MUST.
	IdentifierList *IdentifierListRef
}

// IssueOptions configures Issue.
type IssueOptions struct {
	// DigestAlg selects the MSO's digest algorithm (Table 16). Defaults
	// to SHA256.
	DigestAlg DigestAlg

	// X5Chain is the issuer's certificate (DER), followed by any
	// intermediates, leaf first. REQUIRED — §12.3.4 requires IssuerAuth
	// to carry at least one certificate in its unprotected x5chain
	// header.
	X5Chain [][]byte

	// KeyID optionally sets the COSE "kid" protected header.
	KeyID []byte
}

// Issue builds and signs IssuerSigned: it assigns each data element a
// random ≥16-byte salt and a randomly chosen, namespace-unique DigestID
// (§12.3.4's "no correlation" requirement rules out sequential IDs),
// builds the MSO from the resulting digests, and signs it as IssuerAuth
// via internal/cose. Resolving the caller's actual signer/certificate
// is out of scope — see the package doc comment.
func Issue(signer crypto.Signer, alg cose.Alg, claims Claims, opts IssueOptions) (IssuerSigned, error) {
	if claims.DocType == "" {
		return IssuerSigned{}, fmt.Errorf("mdoc: Claims.DocType is required")
	}
	if len(claims.NameSpaces) == 0 {
		return IssuerSigned{}, fmt.Errorf("mdoc: Claims.NameSpaces must have at least one namespace")
	}
	if claims.DeviceKey == nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: Claims.DeviceKey is required")
	}
	if claims.Signed.IsZero() || claims.ValidFrom.IsZero() || claims.ValidUntil.IsZero() {
		return IssuerSigned{}, fmt.Errorf("mdoc: Claims.Signed, ValidFrom and ValidUntil are required")
	}
	if len(opts.X5Chain) == 0 {
		return IssuerSigned{}, fmt.Errorf("mdoc: IssueOptions.X5Chain must include at least one certificate")
	}
	if claims.Status != nil && claims.IdentifierList != nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: Claims.Status and Claims.IdentifierList must not both be set")
	}
	digestAlg := opts.DigestAlg
	if digestAlg == "" {
		digestAlg = SHA256
	}

	nameSpaces, rawItems, valueDigests, err := issueNameSpaces(claims.NameSpaces, digestAlg)
	if err != nil {
		return IssuerSigned{}, err
	}

	deviceKey, err := NewCoseKey(claims.DeviceKey)
	if err != nil {
		return IssuerSigned{}, err
	}

	mso := MobileSecurityObject{
		Version:         mobileSecurityObjectVersion,
		DigestAlgorithm: digestAlg,
		ValueDigests:    valueDigests,
		DeviceKeyInfo: DeviceKeyInfo{
			DeviceKey:         deviceKey,
			KeyAuthorizations: claims.KeyAuthorizations,
		},
		DocType: claims.DocType,
		ValidityInfo: ValidityInfo{
			Signed:         claims.Signed,
			ValidFrom:      claims.ValidFrom,
			ValidUntil:     claims.ValidUntil,
			ExpectedUpdate: claims.ExpectedUpdate,
		},
	}
	if claims.Status != nil {
		mso.Status = &Status{StatusList: claims.Status}
	}
	if claims.IdentifierList != nil {
		mso.Status = &Status{IdentifierList: claims.IdentifierList}
	}
	payload, err := wrapTag24(mso)
	if err != nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: encode MobileSecurityObjectBytes: %w", err)
	}

	// §12.3.4: "The external_aad field used in the Sig_structure shall
	// be a bytestring of size zero."
	issuerAuth, err := cose.Sign(
		alg, signer,
		cose.Headers{KID: opts.KeyID},
		cose.Headers{X5Chain: opts.X5Chain},
		payload, []byte{},
	)
	if err != nil {
		return IssuerSigned{}, fmt.Errorf("mdoc: sign IssuerAuth: %w", err)
	}

	return IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: issuerAuth, rawItems: rawItems}, nil
}

func issueNameSpaces(
	claimed map[string]map[string]interface{}, digestAlg DigestAlg,
) (nameSpaces map[string][]IssuerSignedItem, rawItems map[string][]cbor.RawMessage, valueDigests map[string]DigestIDs, err error) {
	nameSpaces = make(map[string][]IssuerSignedItem, len(claimed))
	rawItems = make(map[string][]cbor.RawMessage, len(claimed))
	valueDigests = make(map[string]DigestIDs, len(claimed))
	for namespace, elements := range claimed {
		if len(elements) == 0 {
			return nil, nil, nil, fmt.Errorf("mdoc: namespace %q has no data elements", namespace)
		}
		usedIDs := make(map[uint64]bool, len(elements))
		items := make([]IssuerSignedItem, 0, len(elements))
		itemBytesList := make([]cbor.RawMessage, 0, len(elements))
		digests := make(DigestIDs, len(elements))
		for identifier, value := range elements {
			item, itemBytes, d, err := issueItem(identifier, value, digestAlg, usedIDs)
			if err != nil {
				return nil, nil, nil, err
			}
			items = append(items, item)
			itemBytesList = append(itemBytesList, itemBytes)
			digests[item.DigestID] = d
		}
		nameSpaces[namespace] = items
		rawItems[namespace] = itemBytesList
		valueDigests[namespace] = digests
	}
	return nameSpaces, rawItems, valueDigests, nil
}

// issueItem builds one IssuerSignedItem, returning both it and its
// exact IssuerSignedItemBytes (for IssuerSigned's rawItems cache — see
// that type's doc comment) alongside the digest computed over those
// same bytes.
func issueItem(
	identifier string, value interface{}, digestAlg DigestAlg, usedIDs map[uint64]bool,
) (item IssuerSignedItem, itemBytes []byte, digestOut []byte, err error) {
	digestID, err := randomDigestID(usedIDs)
	if err != nil {
		return IssuerSignedItem{}, nil, nil, err
	}
	random := make([]byte, randomMinLength)
	if _, err := rand.Read(random); err != nil {
		return IssuerSignedItem{}, nil, nil, fmt.Errorf("mdoc: generate random salt: %w", err)
	}
	item = IssuerSignedItem{
		DigestID:          digestID,
		Random:            random,
		ElementIdentifier: identifier,
		ElementValue:      value,
	}
	itemBytes, err = issuerSignedItemBytes(item)
	if err != nil {
		return IssuerSignedItem{}, nil, nil, err
	}
	digestOut, err = digest(digestAlg, itemBytes)
	if err != nil {
		return IssuerSignedItem{}, nil, nil, err
	}
	return item, itemBytes, digestOut, nil
}

// randomDigestID draws a DigestID smaller than 2^31 (§12.3.4) not
// already present in used, and records it.
func randomDigestID(used map[uint64]bool) (uint64, error) {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(maxDigestID))
		if err != nil {
			return 0, fmt.Errorf("mdoc: generate DigestID: %w", err)
		}
		id := n.Uint64()
		if !used[id] {
			used[id] = true
			return id, nil
		}
	}
}

package mdoc

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// CredentialFormat is the OID4VCI 1.0 Credential Format Identifier for
// this format (Appendix A.2.1) — the value a Credential Issuer's
// credential_configurations_supported metadata (§12.2.4) uses in its
// "format" member, and a Wallet's authorization_details/Credential
// Request use to select it.
const CredentialFormat = "mso_mdoc" //nolint:gosec // an OID4VCI format identifier, not a credential

// maxDigestID is §12.3.4's bound: "The value shall be smaller than 2^31."
const maxDigestID = 1 << 31

// MaxDecoys bounds Claims.Decoys for one namespace. Decoys only need to
// obscure how many data elements a namespace really holds — a handful
// does that — and an unbounded count turns a misconfiguration into
// memory exhaustion instead of an error.
const MaxDecoys = 1000

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

	// Decoys optionally adds, for each namespace it names, that many
	// decoy digests to the namespace's valueDigests in the MSO: random
	// values of the digest algorithm's length under random DigestIDs
	// unused by the namespace's data elements, with no IssuerSignedItem
	// behind them. The MSO goes to every reader in full, so without
	// them its number of digests says how many data elements each
	// namespace holds, even those the holder doesn't present — which of
	// a fixed set of elements an issuer left out, say. A reader checks
	// only the digests of the items presented, as Verify does, and a
	// decoy looks like the digest of an element left undisclosed. Each
	// namespace named must be in NameSpaces; Issue rejects a count
	// below 0 or above MaxDecoys, or one that takes a namespace's
	// digests past MaxCBORContainerItems. Each decoy adds about 40 bytes
	// (SHA-256) to 72 bytes (SHA-512) to IssuerAuth, and Issue refuses
	// an IssuerAuth larger than the 64 KiB Verify accepts: with SHA-256,
	// all namespaces' decoys and data elements together come to at most
	// about 1,500.
	Decoys map[string]int
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

// validateIssueInputs checks every Issue precondition on claims/opts
// that doesn't itself require building any output.
func validateIssueInputs(signer crypto.Signer, claims Claims, opts IssueOptions) error {
	if err := validateClaims(claims); err != nil {
		return err
	}
	return validateX5Chain(signer, claims, opts)
}

// normalizeValidity puts claims' validity times in UTC with whole
// seconds, as ISO/IEC 18013-5 §9.1.2.4 has the MSO's tdate values
// encoded, before their order is checked: two times within one second
// would otherwise pass validFrom < validUntil and encode as equal.
func normalizeValidity(claims Claims) Claims {
	norm := func(t time.Time) time.Time { return t.UTC().Truncate(time.Second) }
	claims.Signed, claims.ValidFrom, claims.ValidUntil = norm(claims.Signed), norm(claims.ValidFrom), norm(claims.ValidUntil)
	if claims.ExpectedUpdate != nil {
		update := norm(*claims.ExpectedUpdate)
		claims.ExpectedUpdate = &update
	}
	return claims
}

// validateClaims checks claims on their own: what's required, and the
// order of the validity timestamps.
func validateClaims(claims Claims) error {
	if claims.DocType == "" {
		return fmt.Errorf("mdoc: Claims.DocType is required")
	}
	if len(claims.NameSpaces) == 0 {
		return fmt.Errorf("mdoc: Claims.NameSpaces must have at least one namespace")
	}
	if claims.DeviceKey == nil {
		return fmt.Errorf("mdoc: Claims.DeviceKey is required")
	}
	if claims.Signed.IsZero() || claims.ValidFrom.IsZero() || claims.ValidUntil.IsZero() {
		return fmt.Errorf("mdoc: Claims.Signed, ValidFrom and ValidUntil are required")
	}
	// §12.3.4: "The timestamp of validFrom shall be equal or later than
	// the signed element" / "The value of the validUntil element shall
	// be later than the validFrom element" — found in a repo-wide
	// spec-comprehensiveness review; previously only each timestamp's
	// own IsZero() was checked, not their relative ordering.
	if claims.ValidFrom.Before(claims.Signed) {
		return fmt.Errorf("mdoc: Claims.ValidFrom must not be before Claims.Signed")
	}
	if !claims.ValidUntil.After(claims.ValidFrom) {
		return fmt.Errorf("mdoc: Claims.ValidUntil must be after Claims.ValidFrom")
	}
	if claims.Status != nil && claims.Status.URI == "" {
		return fmt.Errorf("mdoc: Claims.Status.URI is required")
	}
	if claims.Status != nil && claims.IdentifierList != nil {
		return fmt.Errorf("mdoc: Claims.Status and Claims.IdentifierList must not both be set")
	}
	if claims.IdentifierList != nil {
		if err := claims.IdentifierList.validate(); err != nil {
			return err
		}
	}
	if err := validateDecoys(claims); err != nil {
		return err
	}
	if claims.KeyAuthorizations != nil {
		return claims.KeyAuthorizations.validate()
	}
	return nil
}

// validateDecoys checks claims.Decoys: each for a namespace claims
// has, within MaxDecoys, and leaving the namespace's valueDigests
// decodable.
func validateDecoys(claims Claims) error {
	for namespace, n := range claims.Decoys {
		elements, ok := claims.NameSpaces[namespace]
		if !ok {
			return fmt.Errorf("mdoc: Claims.Decoys names namespace %q, which Claims.NameSpaces hasn't", namespace)
		}
		if n < 0 || n > MaxDecoys {
			return fmt.Errorf("mdoc: Claims.Decoys[%q] is %d, outside 0..%d", namespace, n, MaxDecoys)
		}
		if len(elements)+n > MaxCBORContainerItems {
			return fmt.Errorf("mdoc: namespace %q would have %d digests, over the %d a reader of this package decodes", namespace, len(elements)+n, MaxCBORContainerItems)
		}
	}
	return nil
}

// validateX5Chain checks opts.X5Chain's leaf against signer and claims'
// validity.
func validateX5Chain(signer crypto.Signer, claims Claims, opts IssueOptions) error {
	if len(opts.X5Chain) == 0 {
		return fmt.Errorf("mdoc: IssueOptions.X5Chain must include at least one certificate")
	}
	leaf, err := x509.ParseCertificate(opts.X5Chain[0])
	if err != nil {
		return fmt.Errorf("mdoc: parse IssueOptions.X5Chain[0]: %w", err)
	}
	// §12.3.4: "The value of the validUntil element shall be equal or
	// earlier than the value of the notAfter element in the leaf
	// certificate in the x5chain element of the IssuerAuth structure."
	if claims.ValidUntil.After(leaf.NotAfter) {
		return fmt.Errorf("mdoc: Claims.ValidUntil (%s) must not be after IssueOptions.X5Chain[0]'s own NotAfter (%s)", claims.ValidUntil, leaf.NotAfter)
	}
	// A two-value assertion, not a direct one: signer.Public() is every
	// stdlib key type's own crypto.PublicKey, all of which implement
	// Equal, but a custom Signer (an HSM/KMS-backed one) may not — a
	// direct assertion would panic instead of returning this func's
	// own documented config-mismatch error, the same "Signer may not
	// be comparable" risk verifier.New's own equivalent check already
	// guards against. Found in the same review as the ValidUntil
	// checks above.
	if comparableKey, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool }); ok && !comparableKey.Equal(leaf.PublicKey) {
		return fmt.Errorf("mdoc: IssueOptions.X5Chain[0]'s public key does not match signer's public key")
	}
	return nil
}

// Issue builds and signs IssuerSigned: it assigns each data element a
// random ≥16-byte salt and a randomly chosen, namespace-unique DigestID
// (§12.3.4's "no correlation" requirement rules out sequential IDs),
// builds the MSO from the resulting digests, and signs it as IssuerAuth
// via internal/cose. Resolving the caller's actual signer/certificate
// is out of scope — see the package doc comment.
func Issue(signer crypto.Signer, alg oid4vci.COSEAlg, claims Claims, opts IssueOptions) (IssuerSigned, error) {
	claims = normalizeValidity(claims)
	if err := validateIssueInputs(signer, claims, opts); err != nil {
		return IssuerSigned{}, err
	}
	digestAlg := opts.DigestAlg
	if digestAlg == "" {
		digestAlg = SHA256
	}

	nameSpaces, rawItems, valueDigests, err := issueNameSpaces(claims.NameSpaces, claims.Decoys, digestAlg)
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
	// Verify, and so every reader built on this package, refuses an
	// IssuerAuth over cose.MaxBytes: an mdoc carrying one would be
	// issued only to be refused wherever it's presented.
	if len(issuerAuth) > cose.MaxBytes {
		return IssuerSigned{}, fmt.Errorf("mdoc: IssuerAuth is %d bytes, more than the %d Verify accepts: issue fewer Claims.Decoys or data elements", len(issuerAuth), cose.MaxBytes)
	}

	return IssuerSigned{NameSpaces: nameSpaces, IssuerAuth: issuerAuth, rawItems: rawItems}, nil
}

func issueNameSpaces(
	claimed map[string]map[string]interface{}, decoys map[string]int, digestAlg DigestAlg,
) (nameSpaces map[string][]IssuerSignedItem, rawItems map[string][]cbor.RawMessage, valueDigests map[string]DigestIDs, err error) {
	nameSpaces = make(map[string][]IssuerSignedItem, len(claimed))
	rawItems = make(map[string][]cbor.RawMessage, len(claimed))
	valueDigests = make(map[string]DigestIDs, len(claimed))
	for namespace, elements := range claimed {
		// §8.1: "Doctype, NameSpace and DataElementIdentifier shall
		// not be empty strings" — found in a repo-wide
		// spec-comprehensiveness review.
		if namespace == "" {
			return nil, nil, nil, fmt.Errorf("mdoc: namespace must not be an empty string")
		}
		if len(elements) == 0 {
			return nil, nil, nil, fmt.Errorf("mdoc: namespace %q has no data elements", namespace)
		}
		usedIDs := make(map[uint64]bool, len(elements)+decoys[namespace])
		items := make([]IssuerSignedItem, 0, len(elements))
		itemBytesList := make([]cbor.RawMessage, 0, len(elements))
		digests := make(DigestIDs, len(elements)+decoys[namespace])
		for identifier, value := range elements {
			if identifier == "" {
				return nil, nil, nil, fmt.Errorf("mdoc: namespace %q: element identifier must not be an empty string", namespace)
			}
			item, itemBytes, d, err := issueItem(identifier, value, digestAlg, usedIDs)
			if err != nil {
				return nil, nil, nil, err
			}
			items = append(items, item)
			itemBytesList = append(itemBytesList, itemBytes)
			digests[item.DigestID] = d
		}
		if err := addDecoyDigests(digests, decoys[namespace], digestAlg, usedIDs); err != nil {
			return nil, nil, nil, err
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

// addDecoyDigests adds n decoy digests to digests (Claims.Decoys):
// each under a DigestID drawn as a data element's is, so it collides
// with none in used, and the digest of fresh crypto/rand bytes under
// digestAlg, so it has a real digest's length and looks like one.
func addDecoyDigests(digests DigestIDs, n int, digestAlg DigestAlg, used map[uint64]bool) error {
	for range n {
		digestID, err := randomDigestID(used)
		if err != nil {
			return err
		}
		random := make([]byte, randomMinLength)
		if _, err := rand.Read(random); err != nil {
			return fmt.Errorf("mdoc: generate decoy digest: %w", err)
		}
		d, err := digest(digestAlg, random)
		if err != nil {
			return err
		}
		digests[digestID] = d
	}
	return nil
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

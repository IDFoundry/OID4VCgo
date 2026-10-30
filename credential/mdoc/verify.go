package mdoc

import (
	"bytes"
	"crypto"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Now is compared against ValidityInfo's ValidFrom/ValidUntil.
	// Defaults to time.Now.
	Now func() time.Time
	// MaxClockSkew is how far Now may be from the issuer's clock: an MSO
	// is accepted up to MaxClockSkew before ValidFrom and after
	// ValidUntil. Zero applies §12.8.1's window exactly — which refuses
	// an MSO valid from the moment it was signed, when the verifier's
	// clock is a second behind the issuer's.
	MaxClockSkew time.Duration
}

// VerifiedMSO is Verify's result: the MSO's own fields, plus the
// disclosed data elements once every one of their digests has been
// checked against valueDigests.
type VerifiedMSO struct {
	DocType      string
	NameSpaces   map[string]map[string]interface{}
	DeviceKey    crypto.PublicKey
	ValidityInfo ValidityInfo
	X5Chain      [][]byte

	// KeyAuthorizations is the verified DeviceKeyInfo's own
	// KeyAuthorizations (§12.3.4), for CheckKeyAuthorizations — nil
	// when the MSO carried none, which CheckKeyAuthorizations treats
	// as "authorizes nothing".
	KeyAuthorizations *KeyAuthorizations

	// Status is the MSO's own Status element (§12.3.6), nil when the
	// MSO carried none. Verify never fetches or checks the referenced
	// MSO revocation list itself — that's optional for an mdoc reader
	// (§12.3.6.1) and entirely the caller's own job, the same
	// "resolving trust is the caller's job" split this package already
	// draws for the Issuer's public key.
	Status *Status
}

// Verify checks IssuerAuth's signature under issuerPub, decodes the
// MSO, checks that its own docType matches docType (§12.8.1 step 4 —
// docType sits outside the signed IssuerAuth envelope, in the wire
// Document structure a caller decodes separately, so without this
// check an attacker who controls that outer structure could present
// signed.NameSpaces/IssuerAuth under a different, unsigned docType;
// found in a repo-wide spec-comprehensiveness review), checks every
// disclosed IssuerSignedItem's digest against the MSO's valueDigests
// (§12.3.5) — an item whose digest doesn't match, or isn't present in
// valueDigests at all, is rejected — and checks ValidityInfo's
// ValidFrom/ValidUntil against opts.Now (or time.Now if unset), refusing
// a ValidityInfo without Signed, ValidFrom or ValidUntil, or whose
// ValidUntil isn't later than its ValidFrom.
// Resolving which key issuerPub is (the IssuerAuth x5chain and an
// Issuer trust policy) is the caller's job — see the package doc
// comment. VerifiedMSO.X5Chain is IssuerAuth's x5chain from either
// header (§12.3.4 puts it in the unprotected one, and a reader should
// accept it in the protected one).
//
// Two of §12.3.4/§12.3.5's rules for the issuer aren't checked here:
// each IssuerSignedItem's random is at least 16 bytes, and validFrom is
// no earlier than signed. They protect the holder's privacy and keep
// the MSO tidy, but a reader learns nothing false from a credential
// that breaks them, so refusing one would only refuse a credential
// whose data is sound. Issue meets both.
func Verify(signed IssuerSigned, docType string, issuerPub crypto.PublicKey, alg oid4vci.COSEAlg, opts VerifyOptions) (VerifiedMSO, error) {
	protected, unprotected, payload, err := cose.Verify(alg, issuerPub, signed.IssuerAuth, []byte{})
	if err != nil {
		return VerifiedMSO{}, fmt.Errorf("mdoc: verify IssuerAuth: %w", err)
	}

	var mso MobileSecurityObject
	if err := unwrapTag24(payload, &mso); err != nil {
		return VerifiedMSO{}, fmt.Errorf("mdoc: decode MobileSecurityObject: %w", err)
	}
	if mso.Version != mobileSecurityObjectVersion {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MSO version %q, want %q", mso.Version, mobileSecurityObjectVersion)
	}
	if mso.DocType != docType {
		return VerifiedMSO{}, fmt.Errorf("mdoc: docType %q does not match the MSO's own docType %q", docType, mso.DocType)
	}
	if err := mso.ValidityInfo.check(); err != nil {
		return VerifiedMSO{}, err
	}

	nameSpaces, err := checkDigests(signed, mso)
	if err != nil {
		return VerifiedMSO{}, err
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	// §12.8.1 step 5: valid from validFrom (inclusive) up to and
	// including validUntil — the current timestamp "shall be equal or
	// later than" validFrom and validUntil "shall be equal or later
	// than" the current timestamp, so both ends are closed, not just
	// the lower one (found in the same review as the docType check
	// above: this previously rejected the exact ValidUntil instant as
	// already expired).
	if opts.MaxClockSkew < 0 {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MaxClockSkew must not be negative")
	}
	if t := now(); t.Add(opts.MaxClockSkew).Before(mso.ValidityInfo.ValidFrom) {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MSO is not yet valid (validFrom %s)", mso.ValidityInfo.ValidFrom)
	} else if t.Add(-opts.MaxClockSkew).After(mso.ValidityInfo.ValidUntil) {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MSO has expired (validUntil %s)", mso.ValidityInfo.ValidUntil)
	}

	deviceKey, err := mso.DeviceKeyInfo.DeviceKey.PublicKey()
	if err != nil {
		return VerifiedMSO{}, fmt.Errorf("mdoc: decode DeviceKeyInfo.DeviceKey: %w", err)
	}

	return VerifiedMSO{
		DocType:           mso.DocType,
		NameSpaces:        nameSpaces,
		DeviceKey:         deviceKey,
		ValidityInfo:      mso.ValidityInfo,
		X5Chain:           cose.X5ChainOf(protected, unprotected),
		KeyAuthorizations: mso.DeviceKeyInfo.KeyAuthorizations,
		Status:            mso.Status,
	}, nil
}

// checkDigests recomputes each disclosed item's digest and checks it
// against mso.ValueDigests, returning the disclosed elements. It digests
// the exact bytes signed carries (signed.rawItems when available — see
// IssuerSigned's doc comment on why re-deriving bytes from the decoded
// IssuerSignedItem isn't safe in general), and takes each element's
// identifier, digestID and value from those same bytes: never from the
// exported NameSpaces, which a caller can change after unmarshalling.
func checkDigests(signed IssuerSigned, mso MobileSecurityObject) (map[string]map[string]interface{}, error) {
	nameSpaces := make(map[string]map[string]interface{}, len(signed.NameSpaces))
	for namespace, items := range signed.NameSpaces {
		digests, ok := mso.ValueDigests[namespace]
		if !ok {
			return nil, fmt.Errorf("mdoc: namespace %q has no entry in valueDigests", namespace)
		}
		cached, hasCache := signed.rawItems[namespace]
		if hasCache && len(cached) != len(items) {
			return nil, fmt.Errorf("mdoc: namespace %q was changed after unmarshalling", namespace)
		}
		elements, err := checkNamespaceDigests(namespace, items, cached, digests, mso.DigestAlgorithm)
		if err != nil {
			return nil, err
		}
		nameSpaces[namespace] = elements
	}
	return nameSpaces, nil
}

// checkNamespaceDigests is checkDigests for the items of one namespace,
// whose received bytes, if any, are cached and whose digests the MSO
// lists, by alg, in digests.
func checkNamespaceDigests(namespace string, items []IssuerSignedItem, cached []cbor.RawMessage, digests DigestIDs, alg DigestAlg) (map[string]interface{}, error) {
	elements := make(map[string]interface{}, len(items))
	for i, item := range items {
		itemBytes, err := hashedItemBytes(cached, i, item)
		if err != nil {
			return nil, err
		}
		var hashed IssuerSignedItem
		if err := unwrapTag24(itemBytes, &hashed); err != nil {
			return nil, fmt.Errorf("mdoc: namespace %q item %d: %w", namespace, i, err)
		}
		want, ok := digests[hashed.DigestID]
		if !ok {
			return nil, fmt.Errorf("mdoc: namespace %q digestID %d has no entry in valueDigests", namespace, hashed.DigestID)
		}
		got, err := digest(alg, itemBytes)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(got, want) {
			return nil, fmt.Errorf("mdoc: namespace %q element %q: digest mismatch", namespace, hashed.ElementIdentifier)
		}
		if _, dup := elements[hashed.ElementIdentifier]; dup {
			return nil, fmt.Errorf("mdoc: namespace %q element %q appears twice", namespace, hashed.ElementIdentifier)
		}
		elements[hashed.ElementIdentifier] = hashed.ElementValue
	}
	return elements, nil
}

// hashedItemBytes is the IssuerSignedItemBytes item i was received as,
// or, without them, item's own encoding.
func hashedItemBytes(cached []cbor.RawMessage, i int, item IssuerSignedItem) ([]byte, error) {
	if i < len(cached) {
		return cached[i], nil
	}
	return issuerSignedItemBytes(item)
}

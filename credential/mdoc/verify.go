package mdoc

import (
	"bytes"
	"crypto"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/cose"
)

// VerifyOptions configures Verify.
type VerifyOptions struct {
	// Now is compared against ValidityInfo's ValidFrom/ValidUntil.
	// Defaults to time.Now.
	Now func() time.Time
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
}

// Verify checks IssuerAuth's signature under issuerPub, decodes the
// MSO, checks every disclosed IssuerSignedItem's digest against the
// MSO's valueDigests (§12.3.5) — an item whose digest doesn't match, or
// isn't present in valueDigests at all, is rejected — and checks
// ValidityInfo's ValidFrom/ValidUntil against opts.Now (or time.Now if
// unset). Resolving which key issuerPub is (the IssuerAuth x5chain and
// an Issuer trust policy) is the caller's job — see the package doc
// comment.
func Verify(signed IssuerSigned, issuerPub crypto.PublicKey, alg cose.Alg, opts VerifyOptions) (VerifiedMSO, error) {
	_, unprotected, payload, err := cose.Verify(alg, issuerPub, signed.IssuerAuth, []byte{})
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

	if err := checkDigests(signed, mso); err != nil {
		return VerifiedMSO{}, err
	}

	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	if t := now(); t.Before(mso.ValidityInfo.ValidFrom) {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MSO is not yet valid (validFrom %s)", mso.ValidityInfo.ValidFrom)
	} else if !t.Before(mso.ValidityInfo.ValidUntil) {
		return VerifiedMSO{}, fmt.Errorf("mdoc: MSO has expired (validUntil %s)", mso.ValidityInfo.ValidUntil)
	}

	deviceKey, err := mso.DeviceKeyInfo.DeviceKey.PublicKey()
	if err != nil {
		return VerifiedMSO{}, fmt.Errorf("mdoc: decode DeviceKeyInfo.DeviceKey: %w", err)
	}

	nameSpaces := make(map[string]map[string]interface{}, len(signed.NameSpaces))
	for namespace, items := range signed.NameSpaces {
		elements := make(map[string]interface{}, len(items))
		for _, item := range items {
			elements[item.ElementIdentifier] = item.ElementValue
		}
		nameSpaces[namespace] = elements
	}

	return VerifiedMSO{
		DocType:      mso.DocType,
		NameSpaces:   nameSpaces,
		DeviceKey:    deviceKey,
		ValidityInfo: mso.ValidityInfo,
		X5Chain:      unprotected.X5Chain,
	}, nil
}

// checkDigests recomputes each disclosed item's digest and checks it
// against mso.ValueDigests. It always digests the exact bytes signed.NameSpaces'
// backing implementation actually produced (signed.rawItems when
// available — see IssuerSigned's own doc comment on why re-deriving
// bytes from the decoded IssuerSignedItem isn't safe in general).
func checkDigests(signed IssuerSigned, mso MobileSecurityObject) error {
	for namespace, items := range signed.NameSpaces {
		digests, ok := mso.ValueDigests[namespace]
		if !ok {
			return fmt.Errorf("mdoc: namespace %q has no entry in valueDigests", namespace)
		}
		cached := signed.rawItems[namespace]
		for i, item := range items {
			want, ok := digests[item.DigestID]
			if !ok {
				return fmt.Errorf("mdoc: namespace %q digestID %d has no entry in valueDigests", namespace, item.DigestID)
			}
			var itemBytes []byte
			var err error
			if i < len(cached) {
				itemBytes = cached[i]
			} else {
				itemBytes, err = issuerSignedItemBytes(item)
				if err != nil {
					return err
				}
			}
			got, err := digest(mso.DigestAlgorithm, itemBytes)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				return fmt.Errorf("mdoc: namespace %q element %q: digest mismatch", namespace, item.ElementIdentifier)
			}
		}
	}
	return nil
}

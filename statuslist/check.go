package statuslist

import (
	"crypto"
	"fmt"
	"math"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// Check validates a Status List Token against issuerPub/alg, checks
// that its sub matches ref.URI, decompresses its Status List, and
// returns the status at ref.Idx — draft-14 §8.3 steps 3-7. Steps 1-2
// (extracting ref from an already-validated Referenced Token via
// ParseStatusClaim, and fetching token from ref.URI) are the caller's
// job: this package has no HTTP client and doesn't validate the
// Referenced Token itself.
func Check(token string, issuerPub crypto.PublicKey, alg oid4vci.JOSEAlg, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	parsed, err := verifyToken(token, issuerPub, alg, opts)
	if err != nil {
		return failClosed(0, TokenClaims{}, err)
	}
	status, parsed, err := checkClaims(parsed, ref, nil)
	return failClosed(status, parsed.claims, err)
}

// CheckCWT is Check for a Status List Token in CWT format.
func CheckCWT(token []byte, issuerPub crypto.PublicKey, alg oid4vci.COSEAlg, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	parsed, err := verifyTokenCWT(token, issuerPub, alg, opts)
	if err != nil {
		return failClosed(0, TokenClaims{}, err)
	}
	status, parsed, err := checkClaims(parsed, ref, nil)
	return failClosed(status, parsed.claims, err)
}

// checkClaims is Check/CheckCWT's shared tail once their respective
// verifyToken/verifyTokenCWT call has produced already-signature-
// checked claims: draft-14 §8.3 steps 4 (sub match) and 5-7 (decompress
// and look up the status), from decoded, the list already decompressed,
// unless it's nil.
func checkClaims(parsed parsedClaims, ref StatusListRef, decoded *Decoded) (StatusType, parsedClaims, error) {
	claims := parsed.claims
	if err := checkSub(claims, ref.URI); err != nil {
		return 0, parsedClaims{}, err
	}
	if ref.Idx > math.MaxInt {
		return 0, parsedClaims{}, fmt.Errorf("statuslist: index %d is out of bounds", ref.Idx)
	}
	var status uint8
	var err error
	if decoded != nil {
		status, err = decoded.Status(int(ref.Idx))
	} else {
		status, err = claims.StatusList.Status(int(ref.Idx))
	}
	if err != nil {
		return 0, parsedClaims{}, err
	}
	return StatusType(status), parsed, nil
}

// checkSub checks claims are uri's (draft-14 §8.3 step 4).
func checkSub(claims TokenClaims, uri string) error {
	if claims.Sub != uri {
		return fmt.Errorf("statuslist: token sub %q does not match the Referenced Token's status_list.uri %q", claims.Sub, uri)
	}
	return nil
}

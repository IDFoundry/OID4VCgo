package statuslist

import (
	"crypto"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jose"
)

// Check validates a Status List Token against issuerPub/alg, checks
// that its sub matches ref.URI, decompresses its Status List, and
// returns the status at ref.Idx — draft-12 §8.3 steps 3-7. Steps 1-2
// (extracting ref from an already-validated Referenced Token via
// ParseStatusClaim, and fetching token from ref.URI) are the caller's
// job: this package has no HTTP client and doesn't validate the
// Referenced Token itself.
func Check(token string, issuerPub crypto.PublicKey, alg jose.Alg, ref StatusListRef, opts VerifyOptions) (StatusType, TokenClaims, error) {
	claims, err := VerifyToken(token, issuerPub, alg, opts)
	if err != nil {
		return 0, TokenClaims{}, err
	}
	if claims.Sub != ref.URI {
		return 0, TokenClaims{}, fmt.Errorf("statuslist: token sub %q does not match the Referenced Token's status_list.uri %q", claims.Sub, ref.URI)
	}

	status, err := claims.StatusList.Status(ref.Idx)
	if err != nil {
		return 0, TokenClaims{}, err
	}
	return StatusType(status), claims, nil
}

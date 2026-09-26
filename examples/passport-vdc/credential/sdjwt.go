package credential

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// SDJWTClaims encodes e as dc+sd-jwt content under vct (the URL this
// demo serves its SD-JWT VC type metadata at). Every claim except the
// registered ones (vct, iss, iat, exp — always disclosed) is
// selectively disclosable; each age
// threshold and each raw data group is its own disclosure. CNF is left
// unset: issuer.RequestCredential binds each issued instance to the
// Wallet's own key.
func SDJWTClaims(e passport.Evidence, vct string, o Options) (*sdjwtvc.Claims, error) {
	if vct == "" {
		return nil, fmt.Errorf("credential: vct is required")
	}
	validUntil, err := ValidUntil(e, o)
	if err != nil {
		return nil, err
	}
	if len(e.Raw.SOD) == 0 || len(e.Raw.DG1) == 0 {
		return nil, fmt.Errorf("credential: evidence is missing SOD or DG1")
	}

	id := e.Identity
	claims := map[string]any{
		FamilyName:         sdjwtvc.SD(id.FamilyName),
		GivenName:          sdjwtvc.SD(id.GivenNames),
		NamesFromMRZ:       sdjwtvc.SD(id.NamesFromMRZ),
		Sex:                sdjwtvc.SD(id.Sex),
		SDJWTNationalities: sdjwtvc.SD([]any{id.Nationality}),
		IssuingCountry:     sdjwtvc.SD(id.IssuingCountry),
		DocumentNumber:     sdjwtvc.SD(id.DocumentNumber),
		ExpiryDate:         sdjwtvc.SD(id.ExpiryDate.Format(time.DateOnly)),

		ICAOSOD: sdjwtvc.SD(b64(e.Raw.SOD)),
		ICAODG1: sdjwtvc.SD(b64(e.Raw.DG1)),
	}
	if id.BirthDate.Known() {
		claims[SDJWTBirthDate] = sdjwtvc.SD(id.BirthDate.Date.Format(time.DateOnly))
	}
	if ages := ageClaims(e, o); len(ages) > 0 {
		over := make(map[string]any, len(ages))
		for threshold, v := range ages {
			over[strconv.Itoa(threshold)] = sdjwtvc.SD(v)
		}
		claims[SDJWTAgeEqualOrOver] = over
	}
	if len(e.Raw.DG2) > 0 {
		claims[ICAODG2] = sdjwtvc.SD(b64(e.Raw.DG2))
	}
	if len(e.Raw.DG11) > 0 {
		claims[ICAODG11] = sdjwtvc.SD(b64(e.Raw.DG11))
	}

	claims["iat"] = o.Now.Unix()
	exp := validUntil.Unix()
	return &sdjwtvc.Claims{
		VCT:        vct,
		Iss:        o.Issuer,
		Exp:        &exp,
		Additional: claims,
	}, nil
}

// b64 is base64url without padding — the encoding SD-JWT itself uses —
// for carrying raw data-group bytes in a JSON claim.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

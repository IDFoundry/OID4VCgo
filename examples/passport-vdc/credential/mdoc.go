package credential

import (
	"fmt"
	"strconv"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// fullDateTag is CBOR tag 1004, an RFC 8943 full-date string — the
// form ISO/IEC 18013-5 uses for dates like birth_date.
const fullDateTag = 1004

func fullDate(t time.Time) cbor.Tag {
	return cbor.Tag{Number: fullDateTag, Content: t.Format(time.DateOnly)}
}

// MdocClaims encodes e as mso_mdoc content. DeviceKey is left unset:
// issuer.RequestCredential binds each issued instance to the Wallet's
// own key.
func MdocClaims(e passport.Evidence, o Options) (*mdoc.Claims, error) {
	validUntil, err := ValidUntil(e, o)
	if err != nil {
		return nil, err
	}

	id := e.Identity
	identity := map[string]interface{}{
		FamilyName:     id.FamilyName,
		GivenName:      id.GivenNames,
		NamesFromMRZ:   id.NamesFromMRZ,
		Sex:            id.Sex,
		Nationality:    id.Nationality,
		IssuingCountry: id.IssuingCountry,
		DocumentNumber: id.DocumentNumber,
		ExpiryDate:     fullDate(id.ExpiryDate),
	}
	if id.BirthDate.Known() {
		identity[BirthDate] = fullDate(id.BirthDate.Date)
	}
	for threshold, over := range ageClaims(e, o) {
		identity[mdocAgeOverPrefix+strconv.Itoa(threshold)] = over
	}

	if len(e.Raw.SOD) == 0 || len(e.Raw.DG1) == 0 {
		return nil, fmt.Errorf("credential: evidence is missing SOD or DG1")
	}
	icao := map[string]interface{}{
		ICAOSOD: e.Raw.SOD,
		ICAODG1: e.Raw.DG1,
	}
	if len(e.Raw.DG2) > 0 {
		icao[ICAODG2] = e.Raw.DG2
	}
	if len(e.Raw.DG11) > 0 {
		icao[ICAODG11] = e.Raw.DG11
	}

	return &mdoc.Claims{
		DocType: DocType,
		NameSpaces: map[string]map[string]interface{}{
			IdentityNamespace: identity,
			ICAONamespace:     icao,
		},
		Signed:     o.Now,
		ValidFrom:  o.Now,
		ValidUntil: validUntil,
	}, nil
}

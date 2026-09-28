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
	if len(e.Portrait) > 0 {
		identity[Portrait] = e.Portrait
	}
	for threshold, over := range ageClaims(e, o) {
		identity[mdocAgeOverPrefix+strconv.Itoa(threshold)] = over
	}

	if len(e.File) == 0 {
		return nil, fmt.Errorf("credential: evidence is missing the passport file")
	}

	return &mdoc.Claims{
		DocType: DocType,
		NameSpaces: map[string]map[string]interface{}{
			IdentityNamespace: identity,
			FileNamespace:     {PassportFile: e.File},
		},
		Signed:     o.Now,
		ValidFrom:  o.Now,
		ValidUntil: validUntil,
	}, nil
}

// Package credential encodes passport.Evidence as the credential
// content the issuer package signs: mdoc.Claims for mso_mdoc and
// sdjwtvc.Claims for dc+sd-jwt. Both carry the same identity
// attributes and the same raw ICAO data groups, one selectively
// disclosable element/claim per data group, so a verifier can check a
// passport-derived credential either by trusting this demo's issuer or
// by re-running Passive Authentication over the raw bytes.
package credential

// PROVISIONAL identifiers. ISO/IEC 23220-4 (PhotoID) is understood to
// define a DTC namespace for exactly this kind of raw eMRTD data; these
// names should be aligned with its text before this demo is presented
// as interoperable. Kept in one place so that change is a single edit.
const (
	// DocType is the mso_mdoc doctype.
	DocType = "org.idfoundry.passport.1"

	// IdentityNamespace holds the holder's identity attributes.
	IdentityNamespace = "org.idfoundry.passport.1"

	// ICAONamespace holds the raw, ICAO-signed data groups.
	ICAONamespace = "org.idfoundry.passport.icao.1"
)

// Element and claim names shared by both formats, except where a
// format has its own established convention (see SD-JWT's birthdate
// and nationalities).
const (
	FamilyName     = "family_name"
	GivenName      = "given_name"
	BirthDate      = "birth_date" // mso_mdoc; SD-JWT uses "birthdate"
	Sex            = "sex"
	Nationality    = "nationality" // mso_mdoc; SD-JWT uses "nationalities"
	IssuingCountry = "issuing_country"
	DocumentNumber = "document_number"
	ExpiryDate     = "expiry_date"
	NamesFromMRZ   = "names_from_mrz"

	ICAOSOD  = "icao_sod"
	ICAODG1  = "icao_dg1"
	ICAODG2  = "icao_dg2"
	ICAODG11 = "icao_dg11"
)

// SD-JWT VC claim names that follow the EUDI PID / OpenID Connect
// conventions rather than the mdoc element names.
const (
	SDJWTBirthDate       = "birthdate"
	SDJWTNationalities   = "nationalities"
	SDJWTAgeEqualOrOver  = "age_equal_or_over"
	mdocAgeOverPrefix    = "age_over_"
	defaultValidityYears = 1
)

// DefaultAgeThresholds are the ages for which age claims are issued.
var DefaultAgeThresholds = []int{13, 16, 18, 21, 65}

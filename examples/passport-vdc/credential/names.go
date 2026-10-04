// Package credential encodes passport.Evidence as the credential
// content the issuer package signs: mdoc.Claims for mso_mdoc and
// sdjwtvc.Claims for dc+sd-jwt. Both carry the same identity
// attributes and the same gmrtd portable passport file, so a verifier
// can check a passport-derived credential either by trusting this
// demo's issuer or by re-verifying the file itself with
// passport.Verify.
package credential

// PROVISIONAL identifiers, specific to this demo. Kept in one place so
// a change is a single edit.
const (
	// DocType is the mso_mdoc doctype.
	DocType = "dev.idfoundry.passport.1"

	// IdentityNamespace holds the holder's identity attributes.
	IdentityNamespace = "dev.idfoundry.passport.1"

	// FileNamespace holds the gmrtd portable passport file.
	FileNamespace = "dev.idfoundry.passport.gmrtd.1"
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

	// Portrait is the holder's photo as JPEG bytes (mso_mdoc), named
	// after ISO/IEC 18013-5's mDL portrait element. SD-JWT uses
	// "picture".
	Portrait = "portrait"

	// PassportFile is the gmrtd portable passport file (gmrtd's
	// "gmrtd-verifiable-doc" format) the issuer verified, byte-for-byte:
	// every data group read from the chip — the photo and DG11
	// included — plus any chip authentication evidence. It's one
	// element/claim, so disclosing it discloses all of that.
	PassportFile = "gmrtd_verifiable_doc" // #nosec G101 -- a claim name, not a credential
)

// SD-JWT VC claim names that follow the EUDI PID / OpenID Connect
// conventions rather than the mdoc element names.
const (
	SDJWTBirthDate       = "birthdate"
	SDJWTNationalities   = "nationalities"
	SDJWTAgeEqualOrOver  = "age_equal_or_over"
	SDJWTPicture         = "picture" // OpenID Connect's picture, here a data: URL
	mdocAgeOverPrefix    = "age_over_"
	defaultValidityYears = 1
)

// DefaultAgeThresholds are the ages for which age claims are issued.
var DefaultAgeThresholds = []int{13, 16, 18, 21, 65}

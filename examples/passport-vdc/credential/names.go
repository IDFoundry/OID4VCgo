// Package credential encodes passport.Evidence as the credential
// content the issuer package signs: mdoc.Claims for mso_mdoc and
// sdjwtvc.Claims for dc+sd-jwt. Both carry the same identity
// attributes and the same gmrtd portable passport file, so a verifier
// can check a passport-derived credential either by trusting this
// demo's issuer or by re-verifying the file itself with
// passport.Verify.
package credential

// The mdoc is a Photo ID (ISO/IEC TS 23220-4): one of the document
// types an iOS document provider app can present to a website over the
// Digital Credentials API. Its data model here follows the open
// implementations of the 23220-4 draft (Multipaz's PhotoID document
// type), checked against ISO/IEC TS 23220-2's org.iso.23220.1
// definitions. What neither defines is in this demo's own namespaces,
// as 23220-2 §6.2.4 allows.
const (
	// DocType is the mso_mdoc doctype: the Photo ID.
	DocType = "org.iso.23220.photoid.1"

	// ISONamespace holds ISO/IEC TS 23220-2's person and document
	// elements: names, birth date, sex, nationality, portrait, age
	// statements, and the mobile document's own issue and expiry.
	ISONamespace = "org.iso.23220.1"

	// PhotoIDNamespace holds the Photo ID profile's own elements: here
	// the passport's number, as the travel document it was derived
	// from.
	PhotoIDNamespace = "org.iso.23220.photoid.1"

	// DemoNamespace holds what neither defines: whether the names came
	// from the MRZ, and the passport's own expiry.
	DemoNamespace = "dev.idfoundry.passport.1"

	// FileNamespace holds the gmrtd portable passport file.
	FileNamespace = "dev.idfoundry.passport.gmrtd.1"
)

// mdoc element names that differ from, or aren't in, the SD-JWT VC.
const (
	// IssuingAuthority names who issued the mobile document
	// (23220-2's issuing_authority): this demo's issuer.
	IssuingAuthority = "issuing_authority"
	// IssueDate and ExpiryDate are the mobile document's own (23220-2),
	// not the passport's: the credential's validity.
	IssueDate = "issue_date"
	// TravelDocumentNumber is the passport's number (Photo ID).
	TravelDocumentNumber = "travel_document_number"
	// PassportExpiryDate is the passport's expiry (this demo's own).
	PassportExpiryDate = "passport_expiry_date" // #nosec G101 -- a claim name, not a credential
	// IssuingAuthorityName is IssuingAuthority's value.
	IssuingAuthorityName = "IDFoundry passport demo"
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

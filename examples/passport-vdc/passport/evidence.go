package passport

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/verifier"
)

// Evidence is a verified passport's content, independent of any
// credential format.
type Evidence struct {
	Identity Identity

	// File is the gmrtd portable passport file Verify accepted,
	// byte-for-byte: every data group read from the chip plus any chip
	// authentication evidence. A verifier that doesn't trust this
	// demo's issuer passes it to Verify itself, re-running Passive
	// Authentication against its own CSCA trust anchors.
	File []byte

	// Portrait is the holder's photo from DG2 as JPEG (converted when
	// the passport stores JPEG 2000), or nil when the passport has no
	// usable face image.
	Portrait []byte

	Checks Checks
}

// Identity is the holder's identity as the passport states it.
type Identity struct {
	FamilyName string
	GivenNames string

	// NamesFromMRZ is true when the names came from the MRZ (DG1)
	// rather than DG11 — MRZ names may be truncated or transliterated.
	NamesFromMRZ bool

	BirthDate BirthDate

	Sex            string // MRZ code: "M", "F" or "X"
	Nationality    string // ISO 3166-1 alpha-3 (or ICAO code)
	IssuingCountry string // ISO 3166-1 alpha-3 (or ICAO code)
	DocumentNumber string
	ExpiryDate     time.Time
}

// Checks summarizes what gmrtd verified.
type Checks struct {
	// PassiveAuthentication is always true for Evidence Verify returns:
	// it refuses a file whose data isn't trusted.
	PassiveAuthentication bool

	// ChipAuthenticity is gmrtd's chip authentication status (e.g.
	// "n/a" when the file carries no chip authentication evidence).
	ChipAuthenticity string
}

// ErrNotTrusted is returned by Verify when gmrtd could decode the file
// but did not establish the data as trusted (Passive Authentication or
// a document consistency check failed).
var ErrNotTrusted = errors.New("passport: data is not trusted")

// ErrUnreadable is returned by Verify when the file isn't a readable
// gmrtd portable passport file.
var ErrUnreadable = errors.New("passport: not a readable gmrtd portable passport file")

// Verify decodes a gmrtd portable passport file, verifies it against
// cscaPool (cms.DefaultMasterList for real passports, or a test CSCA),
// and returns its Evidence. now is the reference time for the expiry
// check and for resolving a two-digit MRZ birth year. The issuer calls
// it on an uploaded file; a verifier calls it on the file a credential
// discloses.
func Verify(data []byte, cscaPool cms.CertPool, now time.Time) (Evidence, error) {
	// gmrtd's errors can embed the raw MRZ, so none are wrapped here:
	// nothing from the passport reaches a log line or page through an
	// error Verify returns.
	docEx, err := verifier.NewVerifier(cscaPool).Verify(data)
	if err != nil {
		return Evidence{}, ErrUnreadable
	}
	summary := docEx.Summary()
	if !summary.DataTrusted {
		return Evidence{}, ErrNotTrusted
	}
	e, err := evidenceFrom(&docEx.Document, summary, now)
	if err != nil {
		return Evidence{}, err
	}
	e.File = slices.Clone(data)
	return e, nil
}

func evidenceFrom(doc *document.Document, summary *document.DocumentSummary, now time.Time) (Evidence, error) {
	attrs := summary.IdentityAttributes
	if attrs == nil {
		return Evidence{}, fmt.Errorf("passport: no identity attributes")
	}
	lds := doc.Mf.Lds1
	if lds.Sod == nil || lds.Dg1 == nil {
		return Evidence{}, fmt.Errorf("passport: SOD and DG1 are required")
	}

	identity, err := identityFrom(attrs, lds.Dg11 != nil, now)
	if err != nil {
		return Evidence{}, err
	}
	return Evidence{
		Identity: identity,
		Portrait: portraitJPEG(attrs.FaceImages),
		Checks: Checks{
			PassiveAuthentication: true,
			ChipAuthenticity:      fmt.Sprint(summary.ChipAuthenticity),
		},
	}, nil
}

func identityFrom(attrs *document.IdentityAttributes, hasDG11 bool, now time.Time) (Identity, error) {
	id := Identity{
		Sex:            attrs.Sex,
		DocumentNumber: attrs.DocumentNumber,
		NamesFromMRZ:   !hasDG11,
	}
	if attrs.Name != nil {
		id.FamilyName, id.GivenNames = attrs.Name.Primary, attrs.Name.Secondary
	}
	if attrs.Nationality != nil {
		id.Nationality = attrs.Nationality.Alpha3
	}
	if attrs.IssuingState != nil {
		id.IssuingCountry = attrs.IssuingState.Alpha3
	}

	expiry, err := time.Parse("20060102", attrs.DateOfExpiry)
	if err != nil {
		return Identity{}, fmt.Errorf("passport: date of expiry %q: %w", attrs.DateOfExpiry, err)
	}
	id.ExpiryDate = expiry

	id.BirthDate, err = resolveBirthDate(attrs.DateOfBirth, now)
	if err != nil {
		return Identity{}, err
	}
	return id, nil
}

// ExpiredAt reports whether the passport had expired by t. A passport
// expiring today is still valid today. Expiry doesn't affect whether its
// data can be trusted — Passive Authentication verifies an expired
// passport's data just the same — so Verify accepts one, and this is for
// showing it.
func (id Identity) ExpiredAt(t time.Time) bool {
	return id.ExpiryDate.Before(dayOf(t))
}

// dayOf truncates t to midnight UTC, so a passport expiring today is
// still valid today.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

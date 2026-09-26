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

	// Raw holds the passport's original, ICAO-signed bytes. A verifier
	// that doesn't trust this demo's issuer can re-run Passive
	// Authentication over them against its own CSCA trust anchors.
	Raw RawDataGroups

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

// RawDataGroups are the original LDS elementary files, exactly as read
// from the chip. SOD and DG1 are always present; DG2 (facial image)
// and DG11 (additional personal details) only when the passport has
// them. DG14/DG15 are deliberately not carried: they only matter to a
// live chip session, which a verifier holding a copy can't run.
type RawDataGroups struct {
	SOD  []byte
	DG1  []byte
	DG2  []byte
	DG11 []byte
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

// ErrExpired is returned by Verify for a passport past its expiry date.
var ErrExpired = errors.New("passport: document has expired")

// Verify decodes a gmrtd portable passport file, verifies it against
// cscaPool (cms.DefaultMasterList for real passports, or a test CSCA),
// and returns its Evidence. now is the reference time for the expiry
// check and for resolving a two-digit MRZ birth year.
func Verify(data []byte, cscaPool cms.CertPool, now time.Time) (Evidence, error) {
	docEx, err := verifier.NewVerifier(cscaPool).Verify(data)
	if err != nil {
		return Evidence{}, fmt.Errorf("passport: decode/verify: %w", err)
	}
	summary := docEx.Summary()
	if !summary.DataTrusted {
		return Evidence{}, fmt.Errorf("%w (passive authentication: %v, document: %v)",
			ErrNotTrusted, docEx.Session.PassiveAuthErr, docEx.Session.DocumentVerifyErr)
	}
	return evidenceFrom(&docEx.Document, summary, now)
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
	if identity.ExpiryDate.Before(dayOf(now)) {
		return Evidence{}, ErrExpired
	}

	raw := RawDataGroups{SOD: slices.Clone(lds.Sod.RawData), DG1: slices.Clone(lds.Dg1.RawData)}
	if lds.Dg2 != nil {
		raw.DG2 = slices.Clone(lds.Dg2.RawData)
	}
	if lds.Dg11 != nil {
		raw.DG11 = slices.Clone(lds.Dg11.RawData)
	}

	return Evidence{
		Identity: identity,
		Raw:      raw,
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

// dayOf truncates t to midnight UTC, so a passport expiring today is
// still valid today.
func dayOf(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

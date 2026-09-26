package passport

import (
	"fmt"
	"time"
)

// BirthDateResolution records how certain a BirthDate is.
type BirthDateResolution int

const (
	// BirthDateUnknown means the passport carried no usable date of
	// birth.
	BirthDateUnknown BirthDateResolution = iota

	// BirthDateExact means the date came with an explicit century
	// (DG11's full date of birth).
	BirthDateExact

	// BirthDateInferred means the date came from the MRZ's two-digit
	// year and exactly one century gave a plausible age: the other
	// reading was in the future or implied an age over MaxPlausibleAge.
	BirthDateInferred

	// BirthDateAmbiguous means both centuries gave a plausible age (e.g.
	// 12 or 112) — typical for a child's passport without DG11. Only
	// the youngest reading is available, for age claims that must never
	// overstate age.
	BirthDateAmbiguous
)

// MaxPlausibleAge bounds which century readings of a two-digit MRZ
// birth year count as plausible — the same bound gmrtd applies.
const MaxPlausibleAge = 120

// BirthDate is a holder's date of birth as far as the passport
// establishes it.
type BirthDate struct {
	Resolution BirthDateResolution

	// Date is the date of birth, set only when Resolution is
	// BirthDateExact or BirthDateInferred.
	Date time.Time

	// Youngest is the latest (youngest) plausible date of birth — equal
	// to Date when that is set. Age claims derive from it, so under
	// BirthDateAmbiguous they can only understate the holder's age:
	// reading a 12-year-old as 112 would wrongly assert age_over_18.
	Youngest time.Time
}

// Known reports whether Date is set.
func (b BirthDate) Known() bool {
	return b.Resolution == BirthDateExact || b.Resolution == BirthDateInferred
}

// resolveBirthDate interprets gmrtd's date of birth: an 8-digit
// YYYYMMDD (DG11) is exact; a 6-digit YYMMDD (DG1 MRZ) is resolved by
// trying both centuries against now.
func resolveBirthDate(dob string, now time.Time) (BirthDate, error) {
	switch len(dob) {
	case 0:
		return BirthDate{}, nil
	case 8:
		d, err := time.Parse("20060102", dob)
		if err != nil {
			return BirthDate{}, fmt.Errorf("passport: date of birth %q: %w", dob, err)
		}
		return BirthDate{Resolution: BirthDateExact, Date: d, Youngest: d}, nil
	case 6:
		var plausible []time.Time // youngest first
		for _, century := range []string{"20", "19"} {
			d, err := time.Parse("20060102", century+dob)
			if err != nil {
				return BirthDate{}, fmt.Errorf("passport: date of birth %q: %w", dob, err)
			}
			if d.After(now) || AgeOn(d, now) > MaxPlausibleAge {
				continue
			}
			plausible = append(plausible, d)
		}
		switch len(plausible) {
		case 0:
			return BirthDate{}, fmt.Errorf("passport: date of birth %q has no plausible century", dob)
		case 1:
			return BirthDate{Resolution: BirthDateInferred, Date: plausible[0], Youngest: plausible[0]}, nil
		default:
			return BirthDate{Resolution: BirthDateAmbiguous, Youngest: plausible[0]}, nil
		}
	default:
		return BirthDate{}, fmt.Errorf("passport: date of birth %q is neither YYYYMMDD nor YYMMDD", dob)
	}
}

// AgeOn returns the age in whole years of someone born on birth, on
// date on.
func AgeOn(birth, on time.Time) int {
	age := on.Year() - birth.Year()
	if !sameMonthDayOrLater(on, birth) {
		age--
	}
	return age
}

// sameMonthDayOrLater reports whether on's month/day is on or after
// birth's, comparing calendar month and day rather than day-of-year so
// leap years don't shift the birthday.
func sameMonthDayOrLater(on, birth time.Time) bool {
	if on.Month() != birth.Month() {
		return on.Month() > birth.Month()
	}
	return on.Day() >= birth.Day()
}

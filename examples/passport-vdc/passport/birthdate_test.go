package passport

import (
	"testing"
	"time"
)

func date(s string) time.Time {
	d, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic(err)
	}
	return d
}

func TestResolveBirthDate(t *testing.T) {
	now := date("2026-09-26")
	cases := []struct {
		name         string
		dob          string
		want         BirthDateResolution
		wantDate     string // "" when Date must be unset
		wantYoungest string // "" when Youngest must be unset
	}{
		{name: "DG11 full date", dob: "19800101", want: BirthDateExact, wantDate: "1980-01-01", wantYoungest: "1980-01-01"},
		{name: "MRZ, 20YY in the future", dob: "800101", want: BirthDateInferred, wantDate: "1980-01-01", wantYoungest: "1980-01-01"},
		{name: "MRZ, 19YY over 120", dob: "050101", want: BirthDateInferred, wantDate: "2005-01-01", wantYoungest: "2005-01-01"},
		// A child's passport without DG11: 2014 (age 12) and 1914 (age
		// 112) are both plausible. No date is asserted; age claims use
		// the youngest reading.
		{name: "MRZ, child — both centuries plausible", dob: "140615", want: BirthDateAmbiguous, wantYoungest: "2014-06-15"},
		{name: "absent", dob: "", want: BirthDateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveBirthDate(tc.dob, now)
			if err != nil {
				t.Fatalf("resolveBirthDate: %v", err)
			}
			if got.Resolution != tc.want {
				t.Errorf("Resolution = %v, want %v", got.Resolution, tc.want)
			}
			if tc.wantDate == "" {
				if !got.Date.IsZero() || got.Known() {
					t.Errorf("Date = %v (Known=%v), want unset", got.Date, got.Known())
				}
			} else if !got.Date.Equal(date(tc.wantDate)) {
				t.Errorf("Date = %v, want %s", got.Date, tc.wantDate)
			}
			if tc.wantYoungest == "" {
				if !got.Youngest.IsZero() {
					t.Errorf("Youngest = %v, want unset", got.Youngest)
				}
			} else if !got.Youngest.Equal(date(tc.wantYoungest)) {
				t.Errorf("Youngest = %v, want %s", got.Youngest, tc.wantYoungest)
			}
		})
	}
}

func TestResolveBirthDateRejectsMalformed(t *testing.T) {
	for _, dob := range []string{"1980", "801301", "19801301"} {
		if _, err := resolveBirthDate(dob, date("2026-09-26")); err == nil {
			t.Errorf("resolveBirthDate(%q) = nil error, want error", dob)
		}
	}
}

func TestAgeOn(t *testing.T) {
	cases := []struct {
		birth, on string
		want      int
	}{
		{"2008-09-26", "2026-09-26", 18}, // birthday itself
		{"2008-09-27", "2026-09-26", 17}, // day before
		{"2008-02-29", "2026-02-28", 17}, // leap-day birth, non-leap year
		{"2008-02-29", "2026-03-01", 18},
		{"1980-01-01", "2026-09-26", 46},
	}
	for _, tc := range cases {
		if got := AgeOn(date(tc.birth), date(tc.on)); got != tc.want {
			t.Errorf("AgeOn(%s, %s) = %d, want %d", tc.birth, tc.on, got, tc.want)
		}
	}
}

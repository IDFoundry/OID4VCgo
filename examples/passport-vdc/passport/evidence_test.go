package passport

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
	"github.com/gmrtd/gmrtd/document"
	"github.com/gmrtd/gmrtd/mrz"
)

func TestIdentityFrom(t *testing.T) {
	attrs := &document.IdentityAttributes{
		IssuingState:   &document.CountryInfo{Alpha3: "SGP"},
		Nationality:    &document.CountryInfo{Alpha3: "SGP"},
		DocumentNumber: "K0000000A",
		Sex:            "F",
		Name:           &mrz.MrzName{Primary: "DOE", Secondary: "JANE"},
		DateOfBirth:    "140615", // MRZ only: ambiguous for a child
		DateOfExpiry:   "20310101",
	}
	id, err := identityFrom(attrs, false, date("2026-09-26"))
	if err != nil {
		t.Fatalf("identityFrom: %v", err)
	}
	if id.FamilyName != "DOE" || id.GivenNames != "JANE" || !id.NamesFromMRZ {
		t.Errorf("names = %q/%q (fromMRZ=%v)", id.FamilyName, id.GivenNames, id.NamesFromMRZ)
	}
	if id.Nationality != "SGP" || id.IssuingCountry != "SGP" || id.DocumentNumber != "K0000000A" || id.Sex != "F" {
		t.Errorf("identity = %+v", id)
	}
	if !id.ExpiryDate.Equal(date("2031-01-01")) {
		t.Errorf("ExpiryDate = %v", id.ExpiryDate)
	}
	if id.BirthDate.Resolution != BirthDateAmbiguous {
		t.Errorf("BirthDate.Resolution = %v, want BirthDateAmbiguous", id.BirthDate.Resolution)
	}

	id, err = identityFrom(attrs, true, date("2026-09-26"))
	if err != nil {
		t.Fatalf("identityFrom: %v", err)
	}
	if id.NamesFromMRZ {
		t.Error("NamesFromMRZ = true with DG11 present")
	}
}

func TestIdentityFromRejectsBadExpiry(t *testing.T) {
	attrs := &document.IdentityAttributes{DateOfExpiry: "999999"} // gmrtd's raw fallback for an unparseable date
	if _, err := identityFrom(attrs, false, date("2026-09-26")); err == nil {
		t.Error("identityFrom = nil error, want error")
	}
}

// TestVerifySample runs Verify against a real gmrtd portable passport
// file, when one is provided. Real passport files are personal data:
// point PASSPORT_VDC_SAMPLE at a file outside this repository — never
// commit one. This test asserts structure only and logs nothing from
// the passport. It is skipped when the variable is unset, so CI covers
// everything except real-passport verification until gmrtd provides a
// synthetic test passport.
func TestVerifySample(t *testing.T) {
	path := os.Getenv("PASSPORT_VDC_SAMPLE")
	if path == "" {
		t.Skip("PASSPORT_VDC_SAMPLE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}

	e, err := Verify(data, pool, time.Now())
	if errors.Is(err, ErrExpired) {
		t.Skip("sample passport has expired")
	}
	if err != nil {
		t.Fatal("Verify failed on the sample (error not printed: gmrtd errors can embed the MRZ)")
	}
	if !e.Checks.PassiveAuthentication {
		t.Error("PassiveAuthentication = false")
	}
	if len(e.Raw.SOD) == 0 || len(e.Raw.DG1) == 0 {
		t.Error("SOD or DG1 missing from Evidence.Raw")
	}
	if e.Identity.FamilyName == "" || e.Identity.DocumentNumber == "" || e.Identity.ExpiryDate.IsZero() {
		t.Error("identity attributes incomplete")
	}
	if e.Identity.BirthDate.Youngest.IsZero() {
		t.Error("no usable birth date")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	if _, err := Verify([]byte("not a gmrtd file"), pool, time.Now()); err == nil {
		t.Error("Verify(garbage) = nil error, want error")
	}
}

// TestVerifyDataGroupsSample checks the verifier-side fallback: Passive
// Authentication over just the sample's SOD and DG1 (no DG2), when
// PASSPORT_VDC_SAMPLE is set. Logs nothing from the passport.
func TestVerifyDataGroupsSample(t *testing.T) {
	path := os.Getenv("PASSPORT_VDC_SAMPLE")
	if path == "" {
		t.Skip("PASSPORT_VDC_SAMPLE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	// Errors are never printed in this test: gmrtd errors can embed
	// the passport's MRZ.
	e, err := Verify(data, pool, time.Now())
	if err != nil {
		t.Skip("sample doesn't verify")
	}
	id, err := VerifyDataGroups(e.Raw.SOD, e.Raw.DG1, pool, time.Now())
	if err != nil {
		t.Fatal("VerifyDataGroups failed on the sample's own SOD and DG1")
	}
	if id.FamilyName != e.Identity.FamilyName || id.DocumentNumber != e.Identity.DocumentNumber {
		t.Error("identity from SOD+DG1 differs from the full passport's")
	}

	// A tampered DG1 fails — whether at parsing (a broken MRZ check
	// digit) or at the SOD hash comparison.
	tampered := append([]byte(nil), e.Raw.DG1...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := VerifyDataGroups(e.Raw.SOD, tampered, pool, time.Now()); !errors.Is(err, ErrPassiveAuthentication) {
		t.Error("tampered DG1 was not rejected with ErrPassiveAuthentication")
	}
}

func TestVerifyDataGroupsRejectsGarbage(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	if _, err := VerifyDataGroups([]byte("not a sod"), []byte("not dg1"), pool, time.Now()); err == nil {
		t.Error("VerifyDataGroups(garbage) = nil error")
	}
	if _, err := VerifyDataGroups(nil, nil, pool, time.Now()); err == nil {
		t.Error("VerifyDataGroups(nil) = nil error")
	}
}

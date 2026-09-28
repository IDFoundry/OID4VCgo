package passport

import (
	"bytes"
	"errors"
	"image/jpeg"
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
	if !bytes.Equal(e.File, data) {
		t.Error("Evidence.File isn't the verified file byte-for-byte")
	}
	if e.Identity.FamilyName == "" || e.Identity.DocumentNumber == "" || e.Identity.ExpiryDate.IsZero() {
		t.Error("identity attributes incomplete")
	}
	if e.Identity.BirthDate.Youngest.IsZero() {
		t.Error("no usable birth date")
	}
	if _, err := jpeg.DecodeConfig(bytes.NewReader(e.Portrait)); err != nil {
		t.Error("no displayable JPEG portrait")
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

// TestVerifySample_TamperedDataGroupFails re-serializes the sample
// with one byte of its facial image (DG2) changed: the file is still
// well-formed, but the DG2 hash no longer matches the SOD, so it must
// not be trusted. Logs nothing from the passport.
func TestVerifySample_TamperedDataGroupFails(t *testing.T) {
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
	doc, _, err := document.UnmarshalVerifiableDoc(data)
	if err != nil || doc.Mf.Lds1.Dg2 == nil {
		t.Skip("sample has no readable DG2")
	}
	reserialize := func() []byte {
		t.Helper()
		out, err := (&document.DocumentEx{Document: *doc}).ToCbor()
		if err != nil {
			t.Fatal("re-serializing the sample failed")
		}
		return out
	}
	// Control: re-serializing alone keeps the file trusted.
	if _, err := Verify(reserialize(), pool, time.Now()); err != nil {
		t.Fatal("the re-serialized, untampered sample didn't verify")
	}

	dg2 := doc.Mf.Lds1.Dg2.RawData
	dg2[len(dg2)-1] ^= 0x01
	tampered := reserialize()
	if _, err := Verify(tampered, pool, time.Now()); !errors.Is(err, ErrNotTrusted) {
		t.Error("a file with a tampered DG2 was not rejected as untrusted")
	}
}

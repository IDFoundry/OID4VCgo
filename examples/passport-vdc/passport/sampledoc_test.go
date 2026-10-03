package passport

import (
	"errors"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"
)

func TestSampleDocument(t *testing.T) {
	now := time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC)
	e, err := SampleDocument(now)
	if err != nil {
		t.Fatalf("SampleDocument: %v", err)
	}
	if e.Checks.PassiveAuthentication {
		t.Error("the sample claims Passive Authentication passed")
	}
	id := e.Identity
	if id.FamilyName != "SMITH" || id.Nationality != "UTO" || !id.ExpiredAt(now) {
		t.Errorf("identity = %+v, want gmrtd's sample (SMITH, UTO, expired)", id)
	}
	if len(e.File) == 0 || len(e.Portrait) == 0 {
		t.Errorf("file %d bytes, portrait %d bytes; want both", len(e.File), len(e.Portrait))
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(e.File, pool, now); !errors.Is(err, ErrNotTrusted) {
		t.Errorf("Verify(sample file) = %v, want ErrNotTrusted", err)
	}
}

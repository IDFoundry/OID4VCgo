package conformancecert_test

import (
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

func TestCredentialExp_SameDayIssuanceYieldsSameExp(t *testing.T) {
	// Two "issuances" separated by a real, non-trivial gap, both
	// within the same UTC day — the exact scenario
	// happy-flow-multiple-clients caught live: two credentials issued
	// moments apart must not carry two different exp values, or a
	// party holding both can correlate them by the gap alone.
	first := time.Date(2026, time.September, 16, 10, 0, 0, 0, time.UTC)
	second := first.Add(3 * time.Second)

	lifetime := 365 * 24 * time.Hour
	got1 := conformancecert.CredentialExp(first, lifetime)
	got2 := conformancecert.CredentialExp(second, lifetime)
	if got1 != got2 {
		t.Errorf("CredentialExp(first) = %d, CredentialExp(second) = %d, want equal for same-day issuance", got1, got2)
	}
}

func TestCredentialExp_CrossesDayBoundary(t *testing.T) {
	before := time.Date(2026, time.September, 16, 23, 59, 59, 0, time.UTC)
	after := time.Date(2026, time.September, 17, 0, 0, 1, 0, time.UTC)

	lifetime := 24 * time.Hour
	got1 := conformancecert.CredentialExp(before, lifetime)
	got2 := conformancecert.CredentialExp(after, lifetime)
	if got1 == got2 {
		t.Errorf("CredentialExp on either side of a day boundary produced the same value %d, want different", got1)
	}
	wantBefore := time.Date(2026, time.September, 17, 0, 0, 0, 0, time.UTC).Unix()
	if got1 != wantBefore {
		t.Errorf("CredentialExp(before) = %d, want %d (start of before's own day + lifetime)", got1, wantBefore)
	}
}

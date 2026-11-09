package walletflow

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// A copy's status reaches the holder as its own value, and the
// credential's is its copies' most severe: revoked over suspended, over
// an application-specific value, over valid. A suspended copy isn't
// reported as valid, nor a revoked one as suspended.
func TestStatusSeverityAndValue(t *testing.T) {
	appSpecific := statuslist.StatusType(0x0b)
	for _, tc := range []struct {
		status statuslist.StatusType
		value  string
	}{
		{statuslist.StatusValid, StatusValid},
		{statuslist.StatusInvalid, StatusInvalid},
		{statuslist.StatusSuspended, StatusSuspended},
		{appSpecific, "0x0b"},
	} {
		if got := statusValue(tc.status); got != tc.value {
			t.Errorf("statusValue(%d) = %q, want %q", tc.status, got, tc.value)
		}
	}
	order := []statuslist.StatusType{statuslist.StatusValid, appSpecific, statuslist.StatusSuspended, statuslist.StatusInvalid}
	for i := 1; i < len(order); i++ {
		if severity(order[i]) <= severity(order[i-1]) {
			t.Errorf("severity(%d) = %d, not above severity(%d) = %d", order[i], severity(order[i]), order[i-1], severity(order[i-1]))
		}
	}
}

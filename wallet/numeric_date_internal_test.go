package wallet

import (
	"math"
	"testing"
	"time"
)

// A Request Object's exp and nbf are NumericDates within jwtdate's range
// (RFC 7519 §2): one before 1970 or past year 9999, which time.Unix
// would wrap or saturate, is refused rather than compared.
func TestCheckRequestObjectClaims_NumericDateRange(t *testing.T) {
	now := func() time.Time { return time.Unix(1_800_000_000, 0) }
	for name, tc := range map[string]struct {
		exp, nbf *float64
		ok       bool
	}{
		"in range":          {exp: ptr(1_800_000_600.5), nbf: ptr(1_799_999_000), ok: true},
		"negative exp":      {exp: ptr(-1)},
		"exp past 9999":     {exp: ptr(1e19)},
		"nbf past 9999":     {nbf: ptr(math.MaxFloat64)},
		"negative nbf":      {nbf: ptr(-1e19)},
		"exp NaN":           {exp: ptr(math.NaN())},
		"expired, in range": {exp: ptr(1_700_000_000)},
	} {
		err := checkRequestObjectClaims(wireRequestObjectPayload{Exp: tc.exp, Nbf: tc.nbf}, now)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}

func ptr(v float64) *float64 { return &v }

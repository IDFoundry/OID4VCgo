package credential

import (
	"errors"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// Options controls validity and age claims for both encoders.
type Options struct {
	// Now is the issuance time — also the SD-JWT's iat.
	Now time.Time

	// Issuer is the Credential Issuer's identifier, set as the
	// SD-JWT's iss claim when non-empty. (An mdoc carries its issuer
	// only in its x5chain.)
	Issuer string

	// MaxValidity caps how long the credential is valid; zero means one
	// year. The credential never outlives the passport or the next age
	// threshold the holder crosses (see ValidUntil).
	MaxValidity time.Duration

	// AgeThresholds are the ages to issue age claims for; nil means
	// DefaultAgeThresholds.
	AgeThresholds []int
}

func (o Options) thresholds() []int {
	if o.AgeThresholds == nil {
		return DefaultAgeThresholds
	}
	return o.AgeThresholds
}

// ErrNoValidity is returned when the credential would already be
// invalid at issuance.
var ErrNoValidity = errors.New("credential: passport evidence yields no validity period")

// ValidUntil is when a credential issued from e under o stops being
// valid: the earliest of the passport's expiry (end of that day),
// Now+MaxValidity, and — when age claims are issued — the day the holder
// crosses the next age threshold, since an age_over_NN = false claim
// becomes wrong on that birthday.
func ValidUntil(e passport.Evidence, o Options) (time.Time, error) {
	maxValidity := o.MaxValidity
	if maxValidity == 0 {
		maxValidity = defaultValidityYears * 365 * 24 * time.Hour
	}
	until := o.Now.Add(maxValidity)

	endOfExpiryDay := e.Identity.ExpiryDate.Add(24*time.Hour - time.Second)
	if endOfExpiryDay.Before(until) {
		until = endOfExpiryDay
	}

	if youngest := e.Identity.BirthDate.Youngest; !youngest.IsZero() {
		age := passport.AgeOn(youngest, o.Now)
		for _, t := range o.thresholds() {
			if age >= t {
				continue
			}
			if crossing := youngest.AddDate(t, 0, 0); crossing.Before(until) {
				until = crossing
			}
		}
	}

	if !until.After(o.Now) {
		return time.Time{}, ErrNoValidity
	}
	return until, nil
}

// ageClaims returns threshold → age_over value, derived from the
// youngest plausible birth date so an ambiguous MRZ year can only
// understate age. Empty when the passport has no usable birth date.
func ageClaims(e passport.Evidence, o Options) map[int]bool {
	youngest := e.Identity.BirthDate.Youngest
	if youngest.IsZero() {
		return nil
	}
	age := passport.AgeOn(youngest, o.Now)
	out := make(map[int]bool, len(o.thresholds()))
	for _, t := range o.thresholds() {
		out[t] = age >= t
	}
	return out
}

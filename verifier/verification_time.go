package verifier

import (
	"context"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// WithVerificationTime returns ctx carrying now, the instant a
// verification is made at: X5CIssuerKeyResolver and
// X5ChainIssuerKeyResolver, and dcql.AKITrustedAuthoritiesChecker,
// then check certificates' validity at it, as
// the rest of the verification checks expiry and ages at
// VerifyResponseRequest.Now. VerifyResponse sets it from its request's
// Now; a caller of a resolver directly, or of mdocdcapi.VerifyResponse,
// sets it the same way.
//
// Status checks don't read it: a statuslist.Checker checks a Status
// List Token's times at its own Options.Now, since the token it fetches
// says what's true when it was fetched, not at an earlier instant. A
// caller verifying at another instant than now sets that clock too.
func WithVerificationTime(ctx context.Context, now time.Time) context.Context {
	return certchain.WithTime(ctx, now)
}

// verificationTime is the instant WithVerificationTime set on ctx, zero
// (the current time) when none was.
func verificationTime(ctx context.Context) time.Time {
	return certchain.TimeFrom(ctx)
}

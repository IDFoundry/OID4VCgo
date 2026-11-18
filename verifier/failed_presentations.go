package verifier

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// MaxFailedPresentationsPerResponse bounds how many presentations of
// one response VerifyResponse verifies and discards for a failed check,
// across all its Credential Queries. Once that many have failed, the
// response is refused as a whole, as malformed, when the next
// presentation is reached, unverified.
//
// A presentation counts when a check of the credential it presents
// fails, whatever the check:
//   - its issuer signature, its validity or its digests
//     (ReasonInvalidCredential);
//   - its issuer certificate chain, where the built-in
//     X5CIssuerKeyResolver or X5ChainIssuerKeyResolver doesn't verify
//     it (a chain that verifies but that the leaf policy or revocation
//     refuses doesn't count);
//   - its holder binding: the Key Binding JWT, the mdoc device
//     signature or its key authorizations (ReasonHolderBinding).
//
// A presentation that verifies, then is discarded for what it says,
// doesn't count: one that doesn't satisfy its Credential Query
// (ReasonNotAnswered), discloses claims it didn't ask for
// (ReasonUnrequestedClaims), or comes from an issuer the Verifier
// trusts but refuses for it, as revoked, by the leaf policy,
// IssuerAuthorized, trusted_authorities or the document signer checks
// (ReasonUntrustedIssuer). Nor does one refused as malformed before any
// signature is checked, or an issuer key a resolver of the caller's own
// refuses. So an honest response, its credentials the Wallet's own, is
// refused by it only when more than this many of them fail their own
// signatures, validity or holder binding.
//
// Every failed check counts here, so a response is refused by this
// before MaxFailedIssuerChainsPerResponse refuses it; that limit still
// applies alone through ResponseIssuerChains. Each presentation's
// issuer signature is checked once, with its x5c or x5chain leaf's key
// through a built-in resolver, and identical presentations are
// recognised before either is verified (see
// VerifyResponseResult.Credentials): a response costs at most this many
// failed presentations' checks, besides those of the presentations
// that verify.
const MaxFailedPresentationsPerResponse = 4

// errTooManyFailedPresentations refuses a response once
// MaxFailedPresentationsPerResponse of its presentations have failed:
// VerifyResponse refuses the whole response, not just the presentation
// that went over.
var errTooManyFailedPresentations = fmt.Errorf("%d presentations in one response failed to verify", MaxFailedPresentationsPerResponse)

// answerLog is what VerifyResponse has seen of one response's
// presentations so far: each one's identity, by the credential query it
// answered, and how many failed verification.
type answerLog struct {
	// distinct is VerifyResponseRequest.DistinctCredentials.
	distinct bool
	seen     map[[sha256.Size]byte]string
	failed   int
}

func newAnswerLog(distinct bool) *answerLog {
	return &answerLog{distinct: distinct, seen: make(map[[sha256.Size]byte]string)}
}

// identify records signed, the part of a presentation its issuer
// signed, as presented for queryID, before any of it is verified. A
// presentation repeating one already presented for queryID, or, under
// distinct, for another query, refuses the response: one credential
// presented twice isn't two credentials, and a Verifier counting them
// (one per person, say) would be misled. A Wallet never does it. Doing
// it before verification costs each copy nothing.
func (l *answerLog) identify(queryID string, signed []byte) error {
	identity := sha256.Sum256(signed)
	if other, ok := l.seen[identity]; ok {
		if other == queryID {
			return &refusedResponseError{newError(ReasonMalformed, "the same credential was presented more than once", nil)}
		}
		if l.distinct {
			return &refusedResponseError{newError(ReasonMalformed, fmt.Sprintf("the same credential was presented for credential queries %q and %q", other, queryID), nil)}
		}
	}
	l.seen[identity] = queryID
	return nil
}

// full reports whether MaxFailedPresentationsPerResponse presentations
// have failed.
func (l *answerLog) full() bool {
	return l.failed >= MaxFailedPresentationsPerResponse
}

// discarded counts failed, err, a presentation's discard, toward
// MaxFailedPresentationsPerResponse when a check of its credential
// failed (see there).
func (l *answerLog) discarded(failed *Error, err error) {
	switch failed.Reason() {
	case ReasonInvalidCredential, ReasonHolderBinding:
		l.failed++
	case ReasonUntrustedIssuer:
		if errors.As(err, new(*unverifiedChainError)) {
			l.failed++
		}
	}
}

// refusedResponseError is a presentation's failure that refuses the
// whole response, not only the presentation: verifyCredentialQuery
// returns the *Error it carries.
type refusedResponseError struct{ err *Error }

func (e *refusedResponseError) Error() string { return e.err.Error() }

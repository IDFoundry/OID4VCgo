package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusPolicy is a Verifier's revocation decision: how the status of
// every credential in an answer is checked, by the library itself and
// before any Accept, so a business check in Accept can't stand in for
// it. TransactionsConfig.Status, VerifyResponseRequest.Status and
// mdocdcapi.VerifyParams.Status take one; under AssuranceProduction each
// requires it or an explicit NoStatusCheck.
//
//	statusCache := statuslist.NewCache(statuslist.CacheOptions{}) // one for the process
//	...
//	Status: &verifier.StatusPolicy{Checker: statuslist.Checker{
//		Roots: issuerRoots,
//		Options: statuslist.VerifyOptions{
//			Revocation: certrevocation.CRLs{...},
//			MaxAge:     24 * time.Hour, // how long ago a list may have been signed
//		},
//		Cache: statusCache,
//	}},
//
// Share one statuslist.Cache across every StatusPolicy and request, so
// a list many credentials reference is fetched once per its ttl rather
// than once per answer; each check still verifies the kept list with
// its own Checker's Roots and Options.
//
// Each credential's status is checked as RequireValidStatus checks it
// (RequireValidStatusFrom, with StatusIssuers): an answer is refused
// when a credential isn't VALID on its status list, is on its mdoc
// identifier list, or has a status that can't be read or names no
// mechanism this package knows. One with no status reference passes,
// unless RequireReference is set.
type StatusPolicy struct {
	// Checker fetches and verifies each status list, and an mdoc's
	// identifier list with its Fetcher, Roots, Options and Cache (see
	// RequireValidStatus). Its Roots are REQUIRED. Under
	// AssuranceProduction, its Fetcher must be HardenedForProduction,
	// its Cache set — one statuslist.Cache shared by the process — its
	// Options.Revocation set — certrevocation.CRLs, a
	// certrevocation.Checker of your own, or certrevocation.NoCheck{}
	// to decline checking the list signers' certificates explicitly —
	// and its Options.MaxAge set, unless AnyListAge is.
	//
	// Its Options.MaxAge bounds how long ago either kind of list may have
	// been signed (its iat). A list signed before a revocation stays
	// valid until its exp, which an issuer may put months ahead, so
	// anyone who can serve bytes at the list's uri — a CDN, a mirror, a
	// former owner of the domain — could replay it until then; with
	// MaxAge, only for MaxAge after the revocation. A list older is
	// refused, so MaxAge must be longer than the interval your issuers
	// sign their lists at. 24 hours suits issuers that sign them at
	// least daily (statuslist.Publisher signs a new token every 30
	// seconds by default), and is the bound
	// statuslist.DefaultMaxAgeWithoutExp puts on a list without exp. It
	// isn't the Cache's CacheOptions.MaxAge, which bounds how long a
	// fetched list is used before it's fetched again.
	//
	// Its Fetcher's MaxBytes bounds both kinds of list: zero leaves
	// each at its package's default, statuslist.DefaultMaxTokenBytes (1
	// MiB) and identifierlist.DefaultMaxTokenBytes (4 MiB). Its
	// Options.MaxTokenBytes bounds status lists alone.
	//
	// Its Options.Issuer, IssuerKey and UnboundSigner must be unset:
	// each check binds the list's signer to the credential's issuer
	// itself (RequireValidStatus), and a signer named here would
	// replace that binding for every credential. A policy setting any
	// of them is refused.
	Checker statuslist.Checker

	// StatusIssuers, if set, accepts a separate Status Issuer's
	// signature on an issuer's status lists, as RequireValidStatusFrom
	// does; nil requires each list signed by the credential's own
	// issuer. For an mdoc it decides only when the mdoc has no issuer
	// chain and its MSO names no status Certificate: ISO/IEC 18013-5
	// §12.3.6.2 binds every other mdoc's lists to its own IACA.
	StatusIssuers StatusIssuerPolicy

	// RequireReference refuses a credential with no status reference
	// this package can check, as RequireStatusReference does: one an
	// issuer couldn't revoke afterwards.
	RequireReference bool

	// AnyListAge accepts, under AssuranceProduction, a Checker whose
	// Options.MaxAge is unset: a status or identifier list is then
	// accepted until its exp, however long before it was signed, and a
	// list from before a revocation can be replayed until then (a
	// status list without exp stays bounded by
	// statuslist.DefaultMaxAgeWithoutExp). It exists so that declining
	// the bound is a visible line of code, never a MaxAge left unset by
	// mistake: set it only where your issuers' lists expire soon after
	// they're signed, or where whoever serves the lists' uris is trusted
	// not to serve an old one. It can't be set with Options.MaxAge.
	AnyListAge bool
}

// Check checks the status of each of vcs, as the policy says: nil when
// every one passes. A proximity reader, or any caller holding verified
// credentials outside VerifyResponse, checks them with it too.
func (p *StatusPolicy) Check(ctx context.Context, vcs ...VerifiedCredential) error {
	if err := checkSignerUnbound(p.Checker.Options); err != nil {
		return fmt.Errorf("verifier: credential status: %w", err)
	}
	if p.RequireReference {
		if err := requireReferences(vcs); err != nil {
			return err
		}
	}
	for _, vc := range vcs {
		if err := requireValid(ctx, p.Checker, p.StatusIssuers, vc); err != nil {
			return fmt.Errorf("verifier: credential status: %w", err)
		}
	}
	return nil
}

// validate refuses a policy that can't check anything, whose Checker
// binds every list's signer to one issuer, or that both bounds a list's
// age and accepts any, and under AssuranceProduction one whose Fetcher
// may reach the Verifier's own network, that has no Cache, that hasn't
// decided its list signers' revocation, or that leaves a list's age
// unbounded without AnyListAge.
func (p *StatusPolicy) validate(assurance AssuranceLevel) error {
	if p.Checker.Roots == nil {
		return errors.New("Status.Checker.Roots is required: the trust anchors for status list signers")
	}
	if err := checkSignerUnbound(p.Checker.Options); err != nil {
		return err
	}
	if p.AnyListAge && p.Checker.Options.MaxAge != 0 {
		return errors.New("set Status.Checker.Options.MaxAge or Status.AnyListAge, not both")
	}
	if assurance != AssuranceProduction {
		return nil
	}
	if !p.Checker.Fetcher.HardenedForProduction() {
		return errors.New("under AssuranceProduction, Status.Checker.Fetcher must be HardenedForProduction: none of AllowLoopback, AllowPrivate, AllowProxy and UncheckedTransport")
	}
	if p.Checker.Cache == nil {
		return errors.New("under AssuranceProduction, Status.Checker.Cache is required (statuslist.NewCache, one shared by the process): without one every answer fetches each issuer's status list again, ignoring its ttl")
	}
	if err := checkListAge(p); err != nil {
		return err
	}
	return validateRevocation("Status.Checker.Options", p.Checker.Options.Revocation)
}

// checkListAge refuses, under AssuranceProduction, a policy that
// doesn't bound how long ago a list may have been signed, unless it
// declines that with AnyListAge.
func checkListAge(p *StatusPolicy) error {
	switch age := p.Checker.Options.MaxAge; {
	case age < 0:
		return fmt.Errorf("Status.Checker.Options.MaxAge is %s: it must be positive", age)
	case age == 0 && !p.AnyListAge:
		return errors.New("under AssuranceProduction, Status.Checker.Options.MaxAge is required: how long ago a status or identifier list may have been signed, so a list from before a revocation isn't accepted until its exp (24 hours where issuers sign their lists daily); or set Status.AnyListAge to accept a list of any age")
	}
	return nil
}

// checkSignerUnbound refuses Options that bind a Status List Token's
// signer for every credential: statuslist.VerifyOptions.Issuer or
// IssuerKey, set, would replace the binding each check installs as
// UnboundSigner, so another issuer's list could decide a credential's
// status (ISO/IEC 18013-5 §12.3.6.2, and StatusIssuers' rule).
func checkSignerUnbound(o statuslist.VerifyOptions) error {
	if o.Issuer != "" || o.IssuerKey != nil || o.UnboundSigner != nil {
		return errors.New("Status.Checker.Options's Issuer, IssuerKey and UnboundSigner must be unset: each check binds the list's signer to the credential's")
	}
	return nil
}

// CheckStatusDecision refuses a configuration's status decision —
// status, the StatusPolicy it sets, and noStatusCheck, its explicit
// opt-out — when it sets both, or a StatusPolicy that can't be used at
// assurance (StatusPolicy's documentation), and under
// AssuranceProduction when it sets neither: left undecided, a revoked
// credential is accepted. An Accept doesn't decide it. Configurations
// of this package and mdocdcapi check theirs with it; a relying party
// of another kind, such as a proximity reader, can too.
func CheckStatusDecision(assurance AssuranceLevel, status *StatusPolicy, noStatusCheck bool) error {
	switch {
	case status != nil && noStatusCheck:
		return errors.New("set Status or NoStatusCheck, not both")
	case status != nil:
		return status.validate(assurance)
	case !noStatusCheck && assurance == AssuranceProduction:
		return errors.New("under AssuranceProduction, set Status (a verifier.StatusPolicy) or NoStatusCheck: without either, a revoked credential is accepted, and an Accept doesn't decide it")
	}
	return nil
}

// Chain is an Accept running each of accepts in turn on an answer,
// skipping nil ones: the first error refuses it. Use it to compose a
// Verifier's own checks into one Accept. Revocation is
// TransactionsConfig.Status's, which runs first.
func Chain(accepts ...func(ctx context.Context, id string, result VerifyResponseResult) error) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return func(ctx context.Context, id string, result VerifyResponseResult) error {
		for _, accept := range accepts {
			if accept == nil {
				continue
			}
			if err := accept(ctx, id, result); err != nil {
				return err
			}
		}
		return nil
	}
}

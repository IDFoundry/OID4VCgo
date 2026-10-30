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
//	Status: &verifier.StatusPolicy{Checker: statuslist.Checker{
//		Roots:   issuerRoots,
//		Options: statuslist.VerifyOptions{Revocation: certrevocation.CRLs{...}},
//	}},
//
// Each credential's status is checked as RequireValidStatus checks it
// (RequireValidStatusFrom, with StatusIssuers): an answer is refused
// when a credential isn't VALID on its status list, is on its mdoc
// identifier list, or has a status that can't be read or names no
// mechanism this package knows. One with no status reference passes,
// unless RequireReference is set.
type StatusPolicy struct {
	// Checker fetches and verifies each status list, and an mdoc's
	// identifier list with its Fetcher, Roots and Options (see
	// RequireValidStatus). Its Roots are REQUIRED. Under
	// AssuranceProduction, its Fetcher must be HardenedForProduction
	// and its Options.Revocation set — certrevocation.CRLs, a
	// certrevocation.Checker of your own, or certrevocation.NoCheck{}
	// to decline checking the list signers' certificates explicitly.
	Checker statuslist.Checker

	// StatusIssuers, if set, accepts a separate Status Issuer's
	// signature on an issuer's status lists, as RequireValidStatusFrom
	// does; nil requires each list signed by the credential's own
	// issuer.
	StatusIssuers StatusIssuerPolicy

	// RequireReference refuses a credential with no status reference
	// this package can check, as RequireStatusReference does: one an
	// issuer couldn't revoke afterwards.
	RequireReference bool
}

// Check checks the status of each of vcs, as the policy says: nil when
// every one passes. A proximity reader, or any caller holding verified
// credentials outside VerifyResponse, checks them with it too.
func (p *StatusPolicy) Check(ctx context.Context, vcs ...VerifiedCredential) error {
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

// validate refuses a policy that can't check anything, and under
// AssuranceProduction one whose Fetcher may reach the Verifier's own
// network or that hasn't decided its list signers' revocation.
func (p *StatusPolicy) validate(assurance AssuranceLevel) error {
	if p.Checker.Roots == nil {
		return errors.New("Status.Checker.Roots is required: the trust anchors for status list signers")
	}
	if assurance != AssuranceProduction {
		return nil
	}
	if !p.Checker.Fetcher.HardenedForProduction() {
		return errors.New("under AssuranceProduction, Status.Checker.Fetcher must be HardenedForProduction: none of AllowLoopback, AllowPrivate, AllowProxy and UncheckedTransport")
	}
	return validateRevocation("Status.Checker.Options", p.Checker.Options.Revocation)
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

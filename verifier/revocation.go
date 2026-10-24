package verifier

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// validateRevocation refuses a resolver's missing Revocation, or one
// that reports itself incomplete (certrevocation.CRLs.Validate).
// Leaving revocation unchecked is a decision, made with
// certrevocation.NoCheck{}, never a field forgotten.
func validateRevocation(resolver string, revocation certrevocation.Checker) error {
	if revocation == nil {
		return fmt.Errorf("verifier: %s: Revocation is required: pass certrevocation.CRLs{...}, your own certrevocation.Checker, or certrevocation.NoCheck{} to decline", resolver)
	}
	if v, ok := revocation.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("verifier: %s: Revocation: %w", resolver, err)
		}
	}
	return nil
}

// checkIssuerKeysValid runs Validate on whichever of req's issuer-key
// resolvers has it (X5CIssuerKeyResolver, X5ChainIssuerKeyResolver),
// for an mdoc resolver also on the ones it wraps, through Unwrap — so a
// resolver configured without Revocation is refused before any
// credential reaches it, at every assurance level.
func checkIssuerKeysValid(req VerifyResponseRequest) error {
	if v, ok := req.IssuerKeys.(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return fmt.Errorf("issuer_keys: %w", err)
		}
	}
	resolver := req.MdocIssuerKeys
	for range 16 {
		if resolver == nil {
			return nil
		}
		if v, ok := resolver.(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return fmt.Errorf("mdoc_issuer_keys: %w", err)
			}
		}
		wrapper, ok := resolver.(MdocIssuerKeyResolverWrapper)
		if !ok {
			return nil
		}
		resolver = wrapper.Unwrap()
	}
	return nil
}

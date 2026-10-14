package verifier

import (
	"context"
	"fmt"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// StatusListRef returns the Token Status List reference vc carries, in
// one form whichever format it is: an SD-JWT VC's "status" claim or an
// mdoc's MSO status. cwt reports which Status List Token form to fetch
// for it — CWT for an mdoc, JWT for an SD-JWT VC — as
// statuslist.Checker.Check takes it. ok is false when vc has no status
// list reference; err is set when it has a malformed one, or a status
// mechanism this package can't check (an mdoc identifier list) — so a
// caller that checks status when ok doesn't skip it.
//
//	ref, cwt, ok, err := vc.StatusListRef()
//	if err == nil && ok {
//		err = checker.RequireValid(ctx, ref, cwt)
//	}
//	if err != nil {
//		// refuse vc: revoked, suspended, or its status unreadable
//	}
//
// RequireValidStatus does this for every credential in an answer, as a
// TransactionsConfig.Accept.
func (vc VerifiedCredential) StatusListRef() (ref statuslist.StatusListRef, cwt, ok bool, err error) {
	if vc.MdocStatus != nil {
		sl := vc.MdocStatus.StatusList
		if sl == nil {
			if vc.MdocStatus.IdentifierList != nil {
				// A status this package can't check isn't "no status":
				// read as one, a revoked mdoc would pass.
				return statuslist.StatusListRef{}, false, false, fmt.Errorf("verifier: the mdoc's status is an identifier list, which isn't supported")
			}
			return statuslist.StatusListRef{}, false, false, nil
		}
		return statuslist.StatusListRef{Idx: sl.Idx, URI: sl.URI}, true, true, nil
	}
	status, present := vc.Claims["status"].(map[string]any)
	if !present {
		return statuslist.StatusListRef{}, false, false, nil
	}
	if ref, err = statuslist.ParseStatusClaim(status); err != nil {
		return statuslist.StatusListRef{}, false, false, err
	}
	return ref, false, true, nil
}

// RequireValidStatus is a TransactionsConfig.Accept that checks the
// status of every credential in an answer that carries a status list
// reference, with checker: an answer is refused when any of them isn't
// VALID (statuslist.NotValidError), when a status can't be read, or
// when a reference is malformed or uses a mechanism this package can't
// check. A credential with no status reference passes: it has no
// status to check.
func RequireValidStatus(checker statuslist.Checker) func(ctx context.Context, id string, result VerifyResponseResult) error {
	return func(ctx context.Context, _ string, result VerifyResponseResult) error {
		for _, vc := range result.Credentials {
			ref, cwt, ok, err := vc.StatusListRef()
			if err == nil && ok {
				err = checker.RequireValid(ctx, ref, cwt)
			}
			if err != nil {
				return fmt.Errorf("verifier: credential status: %w", err)
			}
		}
		return nil
	}
}

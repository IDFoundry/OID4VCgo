package verifierapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// checkStatus checks a verified credential's revocation status against
// the Token Status List it references, fetched from the issuer on every
// check so a revocation applies at once. A revoked or suspended
// credential, or one whose status can't be established, is an error —
// the presentation isn't accepted. A credential without a status
// reference is accepted and reported as such.
func (a *App) checkStatus(ctx context.Context, vc verifier.VerifiedCredential) (string, error) {
	ref, cwt, ok, err := vc.StatusListRef()
	if err != nil {
		return "", fmt.Errorf("the credential's status reference is malformed: %w", err)
	}
	if !ok {
		return "no status reference", nil
	}
	checker := statuslist.Checker{
		// The demo serves its status list on 127.0.0.1; a real Verifier
		// leaves AllowLoopback off, so a credential can't point it at
		// its own machine.
		Fetcher: statuslist.Fetcher{HTTP: a.cfg.HTTP, AllowLoopback: true},
		Roots:   a.issuerRoots,
		Options: statuslist.VerifyOptions{Now: a.now},
	}
	status, _, err := checker.Check(ctx, ref, cwt)
	if err != nil {
		return "", fmt.Errorf("couldn't check the credential's status: %w", err)
	}
	switch status {
	case statuslist.StatusValid:
		return "valid", nil
	case statuslist.StatusInvalid:
		return "", errors.New("the credential has been revoked by its issuer")
	case statuslist.StatusSuspended:
		return "", errors.New("the credential is suspended by its issuer")
	default:
		return "", fmt.Errorf("the credential has status %s, which this verifier doesn't accept", status)
	}
}

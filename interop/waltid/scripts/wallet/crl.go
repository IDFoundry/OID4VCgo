package main

import (
	"context"
	"fmt"
	"log"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// startCRL publishes the run's CA's CRL, the set crlSet names (setup's
// crl-publisher-SET.json, in the working directory), over https from
// this process, at the distribution point Issuer2's and Verifier2's
// certificates name, and starts the Refresher that fetches it back
// (crl-trust.json): https only, the distribution point bound to the
// CA. Its checker refuses a revoked certificate, and one whose CA has
// no current CRL.
//
// crlSet "none" checks no revocation (a nil checker): for credentials
// from cmd/conformance-issuer, whose CAs publish no CRL.
func startCRL(ctx context.Context, crlSet string) (certrevocation.Checker, error) {
	if crlSet == "none" {
		return nil, nil
	}
	checker, err := conformancecrl.StartFiles(ctx, "crl-publisher-"+crlSet+".json", "crl-trust.json", log.Printf)
	if err != nil {
		return nil, fmt.Errorf("-crl-set %q: %w", crlSet, err)
	}
	return checker, nil
}

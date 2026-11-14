package main

import (
	"context"
	"fmt"
	"log"
	"path/filepath"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// startCRL publishes the CRLs of the CAs the wallet trusts the issuer
// by — the IACA's and the metadata CA's, the set o.crlSet names
// (pidsetup's crl-publisher-SET.json) — over https from this process,
// at the distribution points their certificates name, and starts the
// Refresher that fetches them back (crl-trust.json): https only, each
// distribution point bound to its CA. Its checker refuses a revoked
// certificate, and one whose CA has no current CRL.
func startCRL(ctx context.Context, o options) (certrevocation.Checker, error) {
	checker, err := conformancecrl.StartFiles(ctx,
		filepath.Join(o.work, "crl-publisher-"+o.crlSet+".json"), filepath.Join(o.work, "crl-trust.json"), log.Printf)
	if err != nil {
		return nil, fmt.Errorf("-crl-set %q: %w", o.crlSet, err)
	}
	return checker, nil
}

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
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
	var pub conformancecrl.Publisher
	if err := readJSON(filepath.Join(o.work, "crl-publisher-"+o.crlSet+".json"), &pub); err != nil {
		return nil, fmt.Errorf("-crl-set %q: %w", o.crlSet, err)
	}
	var trust conformancecrl.Trust
	if err := readJSON(filepath.Join(o.work, "crl-trust.json"), &trust); err != nil {
		return nil, err
	}
	if err := pub.Start(func(err error) { log.Printf("crl publisher: %v", err) }); err != nil {
		return nil, err
	}
	logf := func(format string, args ...any) { log.Printf(format, args...) }
	crls, err := trust.Start(ctx, logf)
	if err != nil {
		return nil, err
	}
	return crls, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- a file pidsetup wrote into -work
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

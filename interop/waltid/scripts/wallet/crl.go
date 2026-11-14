package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

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
func startCRL(ctx context.Context, crlSet string) (certrevocation.Checker, error) {
	if crlSet == "none" {
		return nil, nil
	}
	var pub conformancecrl.Publisher
	if err := readJSON("crl-publisher-"+crlSet+".json", &pub); err != nil {
		return nil, fmt.Errorf("-crl-set %q: %w", crlSet, err)
	}
	var trust conformancecrl.Trust
	if err := readJSON("crl-trust.json", &trust); err != nil {
		return nil, err
	}
	if err := pub.Start(func(err error) { log.Printf("crl publisher: %v", err) }); err != nil {
		return nil, err
	}
	crls, err := trust.Start(ctx, log.Printf)
	if err != nil {
		return nil, err
	}
	return crls, nil
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path) // #nosec G304 -- a file setup wrote into the working directory
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

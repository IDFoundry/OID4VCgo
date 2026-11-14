// Command run-sdjwt-modules drives cmd/conformance-verifier through
// `oid4vp-1final-verifier-haip-test-plan` under `direct_post.jwt` +
// `x509_hash` + `request_uri_signed` + `credential_format=sd_jwt_vc`:
// every module the plan lists, graded against the expectation
// internal/conformanceverifier names for it (expectations.go, the table
// in conformance/verifier/README.md). It exits non-zero when any
// module's verdict differs from its expectation, or the plan lists a
// module with none.
//
// Everything but this run's own credential format is shared with
// run-mdoc-module via internal/conformanceverifier.
//
// Usage: go run ./conformance/verifier/scripts/run-sdjwt-modules \
//
//	-suite=https://localhost:8443/ \
//	-verifier-base=https://localhost:19446
package main

import (
	"flag"
	"log"

	"github.com/idfoundry/oid4vcgo/internal/conformanceverifier"
)

func main() {
	flags := conformanceverifier.DefineFlags("oid4vcgo-verifier-sdjwt")
	flag.Parse()

	setup, err := conformanceverifier.Setup(conformanceverifier.SetupParams{ //nolint:gosec // false positive: PlanCredentialFormat is a suite variant selector value, not a credential
		Flags:                flags,
		ClientCN:             "conformance-verifier-sdjwt-client",
		ClientCACN:           "conformance-verifier-sdjwt-client-ca",
		PlanDescription:      "OID4VCgo cmd/conformance-verifier sd_jwt_vc live run",
		PlanCredentialFormat: "sd_jwt_vc",
		// Config.CredentialFormat left at its zero value: "" defaults
		// to "dc+sd-jwt" in cmd/conformance-verifier's own loadConfig,
		// this binary's own original format — no mdoc-specific fields
		// needed, just VCT/Claims.
		Configure: func(cfg *conformanceverifier.Config) {
			cfg.VCT = "urn:eudi:pid:1"
			cfg.Claims = []string{"given_name", "family_name"}
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	moduleVariant := map[string]string{"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}

	results := conformanceverifier.DriveModules(setup, moduleVariant)
	// The negative controls of the Verifier's revocation check of the
	// issuer certificate, each under a plan of its own.
	results = append(results, conformanceverifier.DriveCRLControls(setup, moduleVariant)...)
	conformanceverifier.PrintSummaryAndExit(results, *flags.APIBase, setup.PlanID)
}

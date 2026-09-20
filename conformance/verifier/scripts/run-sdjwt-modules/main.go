// Command run-sdjwt-modules closes conformance-verifier's own last
// "driven by hand" gap: `oid4vp-1final-verifier-haip-test-plan`'s 11
// `direct_post.jwt` + `x509_hash` + `request_uri_signed` +
// `credential_format=sd_jwt_vc` modules (confirmed against a real
// historical plan document, GET /api/plan/{id}, fetched from this
// repo's own already-passing run — not guessed) were originally run
// live one at a time by hand (see conformance/verifier/README.md's own
// "Interaction model, confirmed live" section), never as a committed,
// repeatable tool.
//
// Everything but this run's own module list is shared with
// run-mdoc-module via internal/conformanceverifier (DriveModules/
// PrintSummaryAndExit) — see that package's own doc comment for why.
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

// testNames is every oid4vp-1final-verifier-* module this repo's own
// sd_jwt_vc-format run reaches — confirmed against a real historical
// plan document, not the base module list guessed from
// /api/runner/available alone (that list also includes
// invalid-session-transcript, the iso_mdl-only 12th module
// run-mdoc-module already covers, and the unrelated oid4vp-id2/id3
// draft-version modules this repo doesn't target).
var testNames = []string{
	"oid4vp-1final-verifier-happy-flow",
	"oid4vp-1final-verifier-minimal-cnf-jwk",
	"oid4vp-1final-verifier-request-uri-method-post",
	"oid4vp-1final-verifier-request-uri-fetched-twice",
	"oid4vp-1final-verifier-invalid-kb-jwt-signature",
	"oid4vp-1final-verifier-invalid-credential-signature",
	"oid4vp-1final-verifier-invalid-sd-hash",
	"oid4vp-1final-verifier-invalid-kb-jwt-nonce",
	"oid4vp-1final-verifier-invalid-kb-jwt-aud",
	"oid4vp-1final-verifier-kb-jwt-iat-in-past",
	"oid4vp-1final-verifier-kb-jwt-iat-in-future",
}

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

	results := conformanceverifier.DriveModules(setup.HTTPClient, *flags.APIBase, *flags.VerifierBase, setup.PlanID, testNames, moduleVariant)
	conformanceverifier.PrintSummaryAndExit(results, *flags.APIBase, setup.PlanID)
}

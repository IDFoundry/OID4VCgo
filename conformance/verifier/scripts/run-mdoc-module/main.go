// Command run-mdoc-module closes this repo's own remaining OIDF
// Verifier-role certification gap: the "iso_mdl direct_post.jwt"
// certification profile's own 4 applicable modules of
// `oid4vp-1final-verifier-haip-test-plan` — happy-flow,
// request-uri-method-post, request-uri-fetched-twice, and
// invalid-session-transcript (confirmed against the suite's own Java
// source, VP1FinalVerifierTestPlan's own 12-module testModules list
// minus the 8 SD-JWT-VC-only modules — 7 KB-JWT-specific negative tests
// plus minimal-cnf-jwk, each carrying its own
// @VariantNotApplicable(credential_format=iso_mdl); minimal-cnf-jwk's
// own doc comment says so directly: "This test is only applicable for
// the SD-JWT VC credential format" — invalid-session-transcript carries
// the mirror-image @VariantNotApplicable(sd_jwt_vc) instead, the only
// one of the 12 that's iso_mdl-only rather than sd_jwt_vc-only or
// format-agnostic). This binary used to drive only
// invalid-session-transcript — a real, previously-unnoticed 3-module
// gap: the other 3 are also fully iso_mdl-applicable and share
// cmd/conformance-verifier's own generic buildMdocQuery path
// (handlers.go), so nothing about them is invalid-session-transcript-
// specific. (minimal-cnf-jwk was initially included here too, but a
// live 404 creating its module instance under this plan's own
// iso_mdl-variant module list caught the missing exclusion before this
// file's own doc comment or testNames list were finalized — see
// GET /api/plan/{id}'s own "modules" array, the authoritative source,
// not /api/runner/available's format-agnostic module catalog.)
//
// Everything but this run's own module list and looping is shared with
// run-sdjwt-modules via internal/conformanceverifier — see that
// package's own doc comment for why.
//
// Usage: go run ./conformance/verifier/scripts/run-mdoc-module \
//
//	-suite=https://localhost:8443/ \
//	-verifier-base=https://localhost:19446
package main

import (
	"flag"
	"log"
	"os"

	"github.com/idfoundry/oid4vcgo/internal/conformanceverifier"
)

const (
	mdlDoctype   = "org.iso.18013.5.1.mDL"
	mdlNamespace = "org.iso.18013.5.1"
)

// testNames is every oid4vp-1final-verifier-* module the "iso_mdl
// direct_post.jwt" certification profile reaches — confirmed against
// the suite's own Java source (see this file's own doc comment), not
// guessed from /api/runner/available alone.
var testNames = []string{
	"oid4vp-1final-verifier-happy-flow",
	"oid4vp-1final-verifier-request-uri-method-post",
	"oid4vp-1final-verifier-request-uri-fetched-twice",
	"oid4vp-1final-verifier-invalid-session-transcript",
}

type moduleResult struct {
	testName string
	status   string
	result   string
	err      error
}

func main() {
	flags := conformanceverifier.DefineFlags("oid4vcgo-verifier-mdoc")
	flag.Parse()

	setup, err := conformanceverifier.Setup(conformanceverifier.SetupParams{
		Flags:                flags,
		ClientCN:             "conformance-verifier-mdoc-client",
		ClientCACN:           "conformance-verifier-mdoc-client-ca",
		PlanDescription:      "OID4VCgo cmd/conformance-verifier mso_mdoc live run",
		PlanCredentialFormat: "iso_mdl",
		Configure: func(cfg *conformanceverifier.Config) {
			cfg.CredentialFormat = "mso_mdoc"
			cfg.Doctype = mdlDoctype
			cfg.Namespace = mdlNamespace
			cfg.MdocClaims = []string{"given_name", "family_name"}
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	moduleVariant := map[string]string{"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}

	results := make([]moduleResult, 0, len(testNames))
	for _, testName := range testNames {
		status, result, err := conformanceverifier.DriveModule(setup.HTTPClient, *flags.APIBase, *flags.VerifierBase, setup.PlanID, testName, moduleVariant)
		res := moduleResult{testName: testName, status: status, result: result, err: err}
		results = append(results, res)
		if err != nil {
			log.Printf("%s: ERROR: %v", testName, err)
		} else {
			log.Printf("%s: %s=%s", testName, status, result)
		}
	}

	log.Print("=== summary ===")
	allExpected := true
	for _, res := range results {
		// REVIEW is this plan's own legitimate terminal grade for every
		// module here, not a failure — see run-sdjwt-modules' own
		// identical doc comment for why.
		if res.err != nil || (res.result != "PASSED" && res.result != "REVIEW") {
			allExpected = false
		}
		log.Printf("%-55s %s=%s %v", res.testName, res.status, res.result, res.err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", *flags.APIBase, setup.PlanID)
		os.Exit(1)
	}
}

// Command run-mdoc-module closes this repo's own remaining OIDF
// Verifier-role certification gap: `oid4vp-1final-verifier-haip-test-plan`'s
// thirteenth module, `oid4vp-1final-verifier-invalid-session-transcript`,
// is `iso_mdl`-only (confirmed live against the suite's own
// /api/runner/available — its own "credential_format" variant offers
// no "sd_jwt_vc" value at all), so it's unreachable under the plan
// conformance/verifier/scripts/run-sdjwt-modules's own run uses.
// cmd/conformance-verifier's own buildQuery only ever asked for
// "dc+sd-jwt" until this repo also gained an "mso_mdoc" query path
// (see cmd/conformance-verifier/handlers.go's own buildMdocQuery) —
// this binary drives that new path against the one module that needs
// it.
//
// Everything but this module's own identity and its
// Config.CredentialFormat/Doctype/Namespace/MdocClaims values is
// shared with run-sdjwt-modules via internal/conformanceverifier — see
// that package's own doc comment for why.
//
// Usage: go run ./conformance/verifier/scripts/run-mdoc-module \
//
//	-suite=https://localhost:8443/ \
//	-verifier-base=https://localhost:19446
package main

import (
	"flag"
	"log"

	"github.com/idfoundry/oid4vcgo/internal/conformanceverifier"
)

const (
	testName     = "oid4vp-1final-verifier-invalid-session-transcript"
	mdlDoctype   = "org.iso.18013.5.1.mDL"
	mdlNamespace = "org.iso.18013.5.1"
)

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
	status, result, err := conformanceverifier.DriveModule(setup.HTTPClient, *flags.APIBase, *flags.VerifierBase, setup.PlanID, testName, moduleVariant)
	if err != nil {
		log.Fatalf("drive module: %v", err)
	}
	log.Printf("%s: %s=%s", testName, status, result)
	if result != "PASSED" && result != "REVIEW" {
		log.Fatalf("%s: unexpected result %s — see %splan-detail.html?plan=%s", testName, result, *flags.APIBase, setup.PlanID)
	}
}

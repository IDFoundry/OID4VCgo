// Command run-mdoc-module drives cmd/conformance-verifier through
// `oid4vp-1final-verifier-haip-test-plan`'s "iso_mdl direct_post.jwt"
// certification profile: every module the plan lists under
// credential_format=iso_mdl (the SD-JWT-VC-only modules carry
// @VariantNotApplicable(credential_format=iso_mdl) and aren't listed;
// invalid-session-transcript and present-credential-on-identifier-list
// are iso_mdl-only), graded against the expectation
// internal/conformanceverifier names for it (expectations.go, the table
// in conformance/verifier/README.md). It exits non-zero when any
// module's verdict differs from its expectation, or the plan lists a
// module with none.
//
// Everything but this run's own credential format is shared with
// run-sdjwt-modules via internal/conformanceverifier.
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

	results := conformanceverifier.DriveModules(setup, moduleVariant)
	conformanceverifier.PrintSummaryAndExit(results, *flags.APIBase, setup.PlanID)
}

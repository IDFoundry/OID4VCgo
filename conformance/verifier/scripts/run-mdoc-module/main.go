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
// This binary generates fresh throwaway key material via
// internal/conformanceverifier (shared with run-sdjwt-modules — see
// that package's own doc comment for why), with
// Config.CredentialFormat="mso_mdoc" and the standard ISO/IEC 18013-5
// mDL doctype/namespace, writes it to cmd/conformance-verifier's own
// config.json, restarts the container, creates a fresh suite
// plan+module instance, then drives it via
// conformanceverifier.DriveModule — the suite's own documented
// "scripted automation" interaction model
// (conformance/verifier/README.md's own "Interaction model, confirmed
// live" section).
//
// Usage: go run ./conformance/verifier/scripts/run-mdoc-module \
//
//	-suite=https://localhost:8443/ \
//	-verifier-base=https://localhost:19446
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/conformanceverifier"
)

const (
	testName     = "oid4vp-1final-verifier-invalid-session-transcript"
	planName     = "oid4vp-1final-verifier-haip-test-plan"
	mdlDoctype   = "org.iso.18013.5.1.mDL"
	mdlNamespace = "org.iso.18013.5.1"
)

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	verifierBase := flag.String("verifier-base", "https://localhost:19446", "cmd/conformance-verifier's own host-published base URL")
	verifierInternalBase := flag.String("verifier-internal-base", "https://conformance-verifier:8443", "cmd/conformance-verifier's own suite-network-internal base URL")
	alias := flag.String("alias", "oid4vcgo-verifier-mdoc", "suite plan alias")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-verifier container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)")
	flag.Parse()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local conformance suite, self-signed certs throughout

	km, err := conformanceverifier.GenerateKeyMaterial("conformance-verifier-mdoc-client", "conformance-verifier-mdoc-client-ca", *verifierInternalBase)
	if err != nil {
		log.Fatalf("generate key material: %v", err)
	}
	km.Config.CredentialFormat = "mso_mdoc"
	km.Config.Doctype = mdlDoctype
	km.Config.Namespace = mdlNamespace
	km.Config.MdocClaims = []string{"given_name", "family_name"}

	if err := conformanceverifier.WriteConfig(km.Config); err != nil {
		log.Fatalf("write config: %v", err)
	}
	log.Printf("wrote %s (credential_format=mso_mdoc)", conformanceverifier.ConfigOutPath)

	if !*skipDockerRestart {
		if err := conformanceverifier.RestartContainer(); err != nil {
			log.Fatalf("restart conformance-verifier container: %v", err)
		}
		log.Print("restarted conformance-verifier container, waiting for it to come up")
		if err := conformanceverifier.WaitReady(httpClient, *verifierBase); err != nil {
			log.Fatalf("wait for conformance-verifier: %v", err)
		}
	}

	pc := conformanceverifier.PlanConfig{
		Alias:       *alias,
		Description: "OID4VCgo cmd/conformance-verifier mso_mdoc live run",
		Client:      conformanceverifier.PlanConfigClient{RequestObjectTrustAnchorPEM: km.ClientCACertPEM},
		Credential:  conformanceverifier.PlanConfigCred{SigningJWK: km.CredentialIssuerPrivateJWK},
	}
	pcRaw, err := json.Marshal(pc)
	if err != nil {
		log.Fatalf("marshal plan config: %v", err)
	}

	planVariant := map[string]string{"credential_format": "iso_mdl", "response_mode": "direct_post.jwt"} //nolint:gosec // false positive: a suite variant selector value, not a credential
	planID, _, err := conformancesuite.CreatePlan(httpClient, *apiBase, planName, planVariant, pcRaw)
	if err != nil {
		log.Fatalf("create plan: %v", err)
	}
	log.Printf("created plan %s (alias %s)", planID, *alias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)

	moduleVariant := map[string]string{"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}
	status, result, err := conformanceverifier.DriveModule(httpClient, *apiBase, *verifierBase, planID, testName, moduleVariant)
	if err != nil {
		log.Fatalf("drive module: %v", err)
	}
	log.Printf("%s: %s=%s", testName, status, result)
	if result != "PASSED" && result != "REVIEW" {
		log.Fatalf("%s: unexpected result %s — see %splan-detail.html?plan=%s", testName, result, *apiBase, planID)
	}
}

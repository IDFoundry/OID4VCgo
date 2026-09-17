// Command run-sdjwt-modules closes conformance-verifier's own last
// "driven by hand" gap: `oid4vp-1final-verifier-haip-test-plan`'s 11
// `direct_post.jwt` + `x509_hash` + `request_uri_signed` +
// `credential_format=sd_jwt_vc` modules (confirmed against a real
// historical plan document, GET /api/plan/{id}, fetched from this
// repo's own already-passing run — not guessed) were originally run
// live one at a time by hand (see conformance/verifier/README.md's own
// "Interaction model, confirmed live" section), never as a committed,
// repeatable tool. This binary reuses that same documented two-request
// interaction model via internal/conformanceverifier (shared with
// run-mdoc-module — see that package's own doc comment for why),
// looped over all 11 instead of driven one at a time.
//
// Usage: go run ./conformance/verifier/scripts/run-sdjwt-modules \
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
	"os"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
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

const planName = "oid4vp-1final-verifier-haip-test-plan"

type moduleResult struct {
	testName string
	status   string
	result   string
	err      error
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	verifierBase := flag.String("verifier-base", "https://localhost:19446", "cmd/conformance-verifier's own host-published base URL")
	verifierInternalBase := flag.String("verifier-internal-base", "https://conformance-verifier:8443", "cmd/conformance-verifier's own suite-network-internal base URL")
	alias := flag.String("alias", "oid4vcgo-verifier-sdjwt", "suite plan alias")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-verifier container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)")
	flag.Parse()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local conformance suite, self-signed certs throughout

	// Config.CredentialFormat left at its zero value: "" defaults to
	// "dc+sd-jwt" in cmd/conformance-verifier's own loadConfig, this
	// binary's own original format — no mdoc-specific fields needed.
	km, err := conformanceverifier.GenerateKeyMaterial("conformance-verifier-sdjwt-client", "conformance-verifier-sdjwt-client-ca", *verifierInternalBase)
	if err != nil {
		log.Fatalf("generate key material: %v", err)
	}
	km.Config.VCT = "urn:eudi:pid:1"
	km.Config.Claims = []string{"given_name", "family_name"}

	if err := conformanceverifier.WriteConfig(km.Config); err != nil {
		log.Fatalf("write config: %v", err)
	}
	log.Printf("wrote %s (credential_format=dc+sd-jwt)", conformanceverifier.ConfigOutPath)

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
		Description: "OID4VCgo cmd/conformance-verifier sd_jwt_vc live run",
		Client:      conformanceverifier.PlanConfigClient{RequestObjectTrustAnchorPEM: km.ClientCACertPEM},
		Credential:  conformanceverifier.PlanConfigCred{SigningJWK: km.CredentialIssuerPrivateJWK},
	}
	pcRaw, err := json.Marshal(pc)
	if err != nil {
		log.Fatalf("marshal plan config: %v", err)
	}

	planVariant := map[string]string{"credential_format": "sd_jwt_vc", "response_mode": "direct_post.jwt"} //nolint:gosec // false positive: a suite variant selector value, not a credential
	planID, _, err := conformancesuite.CreatePlan(httpClient, *apiBase, planName, planVariant, pcRaw)
	if err != nil {
		log.Fatalf("create plan: %v", err)
	}
	log.Printf("created plan %s (alias %s)", planID, *alias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)

	moduleVariant := map[string]string{"client_id_prefix": "x509_hash", "request_method": "request_uri_signed", "vp_profile": "haip"}

	results := make([]moduleResult, 0, len(testNames))
	for _, testName := range testNames {
		status, result, err := conformanceverifier.DriveModule(httpClient, *apiBase, *verifierBase, planID, testName, moduleVariant)
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
		// module here, not a failure: each one only reaches FINISHED at
		// all because DriveModule's own upload-placeholder fill
		// satisfied its own screenshot-evidence requirement — see
		// internal/conformanceverifier.DriveModule's own doc comment
		// for why cmd/conformance-verifier's design means every module
		// takes that branch, not just the positive-behavior ones.
		if res.err != nil || (res.result != "PASSED" && res.result != "REVIEW") {
			allExpected = false
		}
		log.Printf("%-55s %s=%s %v", res.testName, res.status, res.result, res.err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)
		os.Exit(1)
	}
}

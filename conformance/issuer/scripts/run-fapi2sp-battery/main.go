// Command run-fapi2sp-battery drives the HAIP issuer test plan's own
// full module list — every VCI-specific happy-flow/negative-test/
// metadata module, its own Discovery module (a separate ModuleListEntry),
// and its generic FAPI2SP client conformance battery
// (VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules(), 39 modules) —
// against a real, locally-run OIDF conformance suite instance and a
// real cmd/conformance-issuer — the suite plays the FAPI2 client/wallet,
// this binary's job is entirely config generation and result polling,
// not driving any flow itself (see the package doc comment below for
// why). See haipBattery's own doc comment for the exact module count.
//
// Unlike cmd/conformance-wallet, this binary never calls the suite as a
// client: for the Issuer role the suite plays that side, driving PAR →
// authorize → consent → token → resource calls against
// cmd/conformance-issuer entirely on its own, via its own internal
// headless browser (see BrowserControl.java) — automated here by
// supplying a "browser" test-configuration block that auto-approves
// consent, plus the small set of per-module "override" blocks
// FAPIgo's own cmd/conformance-as reference configuration already
// established (deny consent for user-rejects-authentication; limit
// the PAR-reused-request-uri module to one authorize visit before its
// retry). No custom Go driving logic is needed at all — confirmed by
// FAPIgo's own OpenID-Certified cmd/conformance-as, which reuses this
// exact "browser"/"override" config mechanism against the same
// underlying FAPI2SPFinalTestPlan module family with zero external
// driver.
//
// This binary generates a fresh Client Attestation attester key plus
// two client instance keys (client1/client2) every run, writes a
// matching cmd/conformance-issuer server config
// (conformance/issuer/oidf-config/haip.config.json) and a suite-side
// plan config from the *same* key material in one step — eliminating
// the previous manual "create a plan via the suite's own UI, copy its
// generated client identity into haip.config.json" workflow
// conformance/issuer/README.md used to document, the same
// generate-both-sides-together pattern FAPIgo's own
// conformance/server/scripts/setup-config already established for
// cmd/conformance-as.
//
// Usage:
//
//	docker compose -f conformance/issuer/docker-compose.yml up -d --build
//	go run ./conformance/issuer/scripts/run-fapi2sp-battery
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// metadataTestName/happyFlowTestName are the two already-known-passing
// sanity-check modules every battery variant (haipBattery, baseBattery,
// mdocBattery) drives first or exclusively — named once here rather
// than repeating the literal in all three.
const (
	metadataTestName  = "oid4vci-1_0-issuer-metadata-test"
	happyFlowTestName = "oid4vci-1_0-issuer-happy-flow"
)

// battery is every testName this binary drives under fapi_profile=
// vci_haip — all 61 distinct test module classes VCIIssuerTestPlanHaip
// declares across its own 5 ModuleListEntry groups, confirmed against
// the suite's own Java source: the 21 VCI-specific happy-flow/negative-
// test/metadata modules (2 metadata + 18 happy-flow/negative-test +
// the 1 encrypted-only fail-unsupported-encryption-algorithm, its own
// separate entry) below, plus its own Discovery module (its own
// ModuleListEntry, no VCI variant parameters) plus the 39-module
// generic FAPI2SP client battery
// (VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules()) — set-subtracting
// FAPI2MessageSigningFinalTestPlan.testModules minus the signing-only
// removals in FAPI2SPFinalTestPlan.fapi2SPtestModules() minus the
// nonce/OIDC-only, private_key_jwt-only, and profile-specific removals
// VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules() itself applies —
// not guessed, and cross-checked against every module's own
// @PublishTestModule testName. The one HAIP-plan class not listed
// here, fail-invalid-key-attestation-signature, self-skips under this
// battery's own default jwt proof type — see keyAttestationBattery,
// which drives it (and the whole plan) under the attestation proof
// type instead, where it's genuinely applicable. 60 (this battery) + 1
// (keyAttestationBattery) = the plan's own full 61.
var haipBattery = []string{
	// Sanity check: already-passing modules, confirming the freshly
	// generated config/keys are behavior-preserving.
	metadataTestName,
	happyFlowTestName,

	// The remaining 17 VCI-specific modules (of the plan's own 21 total:
	// 2 metadata + 18 happy-flow/negative-test + the 1
	// encrypted-context-only fail-unsupported-encryption-algorithm,
	// minus the 2 sanity checks above and fail-invalid-key-attestation-
	// signature — see this var's own doc comment for why that one lives
	// in keyAttestationBattery instead). fail-unsupported-encryption-
	// algorithm's own ModuleListEntry pins
	// vci_credential_encryption=encrypted itself (VCIIssuerTestPlanHaip.java's
	// own 3rd entry) — no extra flag or plan variant needed to reach it,
	// unlike the base plan's own single, caller-chosen encryption
	// variant (see baseBattery's own doc comment); cmd/conformance-issuer
	// already advertises request/response encryption unconditionally
	// (wiring.go), regardless of which battery drives it.
	"oid4vci-1_0-issuer-metadata-test-signed",
	"oid4vci-1_0-issuer-happy-flow-additional-requests",
	"oid4vci-1_0-issuer-happy-flow-multiple-clients",
	"oid4vci-1_0-issuer-batch-issuance",
	"oid4vci-1_0-issuer-fail-invalid-nonce",
	"oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature",
	"oid4vci-1_0-issuer-fail-invalid-client-attestation-signature",
	"oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature",
	"oid4vci-1_0-issuer-fail-client-attestation-exp-in-past",
	"oid4vci-1_0-issuer-fail-client-attestation-no-sub",
	"oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud",
	"oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key",
	"oid4vci-1_0-issuer-fail-missing-proof",
	"oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm",
	"oid4vci-1_0-issuer-fail-unknown-credential-configuration",
	"oid4vci-1_0-issuer-fail-unknown-credential-identifier",
	"oid4vci-1_0-issuer-fail-on-access-token-in-query",

	// Notification Endpoint (§11) coverage under fapi_profile=vci_haip
	// specifically — this module's own testName is shared with
	// baseBattery (it supports both the "vci" and "vci_haip"
	// fapi_profile variant values).
	"oid4vci-1_0-issuer-happy-flow-skip-notification",

	// Discovery — its own ModuleListEntry, no VCI variant parameters.
	"fapi2-security-profile-final-discovery-end-point-verification",

	// The 39-module generic FAPI2SP client battery.
	"fapi2-security-profile-final-access-token-type-header-case-sensitivity",
	"fapi2-security-profile-final-attempt-reuse-authorization-code-after-one-second",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-expired-auth-code",
	"fapi2-security-profile-final-check-dpop-proof-nbf-exp",
	"fapi2-security-profile-final-dpop-negative-tests",
	"fapi2-security-profile-final-ensure-authorization-code-is-bound-to-client",
	"fapi2-security-profile-final-ensure-authorization-request-with-long-state",
	"fapi2-security-profile-final-ensure-authorization-request-without-state-success",
	"fapi2-security-profile-final-ensure-client-id-in-token-endpoint",
	"fapi2-security-profile-final-ensure-different-state-inside-and-outside-request-object",
	"fapi2-security-profile-final-ensure-dpop-auth-code-binding-success",
	"fapi2-security-profile-final-ensure-dpopproof-at-par-endpoint-binding-success",
	"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-after-succeeds",
	"fapi2-security-profile-final-ensure-dpopproof-with-iat-10seconds-before-succeeds",
	"fapi2-security-profile-final-ensure-holder-of-key-required",
	"fapi2-security-profile-final-ensure-mismatched-dpop-jkt-fails",
	"fapi2-security-profile-final-ensure-redirect-uri-in-authorization-request",
	"fapi2-security-profile-final-ensure-request-object-without-redirect-uri-fails",
	"fapi2-security-profile-final-ensure-response-type-code-idtoken-fails",
	"fapi2-security-profile-final-ensure-response-type-token-fails",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-jkt",
	"fapi2-security-profile-final-ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt",
	"fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails",
	"fapi2-security-profile-final-happy-flow",
	"fapi2-security-profile-final-par-attempt-reuse-request_uri",
	"fapi2-security-profile-final-par-attempt-to-use-expired-request_uri",
	"fapi2-security-profile-final-ensure-pkce-code-verifier-required",
	"fapi2-security-profile-final-par-ensure-pkce-required",
	"fapi2-security-profile-final-par-plain-pkce-rejected",
	"fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client",
	"fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds",
	"fapi2-security-profile-final-incorrect-pkce-code-verifier-rejected",
	"fapi2-security-profile-final-par-attempt-invalid-http-method",
	"fapi2-security-profile-final-par-authorization-request-containing-request_uri-form-param",
	"fapi2-security-profile-final-par-without-duplicate-parameters",
	"fapi2-security-profile-final-refresh-token",
	"fapi2-security-profile-final-state-only-outside-request-object-not-used",
	"fapi2-security-profile-final-plain-fapi-tolerate-unregistered-redirect-uri",
	"fapi2-security-profile-final-user-rejects-authentication",
}

// baseBattery is every testName this binary drives when -base-plan
// selects the suite's own base (non-HAIP) "oid4vci-1_0-issuer-test-plan"
// (VCIIssuerTestPlan.java — "alpha version - may be incomplete or
// incorrect") instead of the default HAIP plan. Unlike VCIIssuerTestPlanHaip,
// this plan's own module list doesn't reuse the FAPI2SP battery at all —
// just its own 2 metadata modules plus 20 happy-flow/negative-test
// modules, the exact same already-passing classes VCIIssuerTestPlanHaip
// also lists (confirmed identical testName strings against both plans'
// own Java source), just now under fapi_profile=vci instead of
// fapi_profile=vci_haip. Every module here is now also directly
// exercised above under HAIP via haipBattery itself (this list used to
// be the only repeatable-script coverage these 21 VCI-specific modules
// had — haipBattery only drove 3 of them until its own 17-module gap
// was closed) — this run is about confirming this binary's own server
// behaves the same way when the suite treats it as a base-profile VCI
// issuer rather than a HAIP one, not primary functional coverage.
var baseBattery = []string{
	metadataTestName,
	"oid4vci-1_0-issuer-metadata-test-signed",
	happyFlowTestName,
	"oid4vci-1_0-issuer-happy-flow-additional-requests",
	"oid4vci-1_0-issuer-happy-flow-multiple-clients",
	"oid4vci-1_0-issuer-happy-flow-skip-notification",
	"oid4vci-1_0-issuer-batch-issuance",
	"oid4vci-1_0-issuer-fail-invalid-nonce",
	"oid4vci-1_0-issuer-fail-invalid-jwt-proof-signature",
	"oid4vci-1_0-issuer-fail-invalid-key-attestation-signature",
	"oid4vci-1_0-issuer-fail-invalid-client-attestation-signature",
	"oid4vci-1_0-issuer-fail-invalid-client-attestation-pop-signature",
	"oid4vci-1_0-issuer-fail-client-attestation-exp-in-past",
	"oid4vci-1_0-issuer-fail-client-attestation-no-sub",
	"oid4vci-1_0-issuer-fail-client-attestation-pop-wrong-aud",
	"oid4vci-1_0-issuer-fail-mismatched-client-attestation-pop-key",
	"oid4vci-1_0-issuer-fail-missing-proof",
	"oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm",
	"oid4vci-1_0-issuer-fail-unknown-credential-configuration",
	"oid4vci-1_0-issuer-fail-unknown-credential-identifier",
	"oid4vci-1_0-issuer-fail-on-access-token-in-query",
}

// mdocBattery is driven instead of haipBattery/baseBattery when
// -credential-format=mdoc — just the 2 already-known-working sanity
// modules, confirming cmd/conformance-issuer's own new MdocSigner
// wiring and mso_mdoc CredentialConfiguration issue a genuinely valid
// credential (DocType/NameSpaces/DeviceKey binding/IssuerAuth signature
// — real structural validation, see
// ParseMdocCredentialFromVCIIssuance.java) live against the suite, on
// top of the unit-level proof cmd/conformance-issuer's own
// TestFullFlow_MdocCredentialIssuance already gives. The other 40
// FAPI2SP-generic battery modules (PAR/DPoP/token-endpoint edge cases)
// don't exercise credential issuance format at all — vciCredentialFormat
// is read into AbstractVCIIssuerTestModule but never branched on
// anywhere else in the suite's own source — so re-running them under
// mdoc would just re-prove what haipBattery already proved under
// sd_jwt_vc, not new coverage.
var mdocBattery = []string{
	metadataTestName,
	happyFlowTestName,
}

// keyAttestationBattery, driven under
// -credential-proof-type-hint=attestation: the same 2 sanity modules
// mdocBattery drives (metadata-test, and happy-flow as a positive
// attestation-proof sanity check — proving a genuinely valid Key
// Attestation JWT issues a credential, not just that an invalid one is
// rejected), plus the one negative test this whole battery variant
// exists for. Restricted the same way mdocBattery is, for the same
// reason: the other 40 FAPI2SP-generic modules don't exercise proof
// type at all.
var keyAttestationBattery = []string{
	metadataTestName,
	happyFlowTestName,
	"oid4vci-1_0-issuer-fail-invalid-key-attestation-signature",
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	alias := flag.String("alias", "oid4vcgo-issuer", "suite plan alias — also the callback path segment; must match cmd/conformance-issuer's own registered redirect_uris")
	issuerBaseURL := flag.String("issuer", "https://conformance-issuer:8443", "cmd/conformance-issuer's own externally-reachable base URL (suite-network-internal hostname)")
	configOut := flag.String("config-out", "conformance/issuer/oidf-config/haip.config.json", "path to write cmd/conformance-issuer's own generated server config to")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-issuer container after writing the new config (for repeat runs against a container already restarted once)")
	basePlan := flag.Bool("base-plan", false, "drive the suite's own base (non-HAIP) \"oid4vci-1_0-issuer-test-plan\" instead of the default HAIP plan — see baseBattery's own doc comment")
	credentialFormat := flag.String("credential-format", "sd_jwt_vc", "credential_format variant to drive: \"sd_jwt_vc\" (default) or \"mdoc\" — mdoc restricts the driven module set to the 2 sanity-check modules (mdocBattery), since the other 40 FAPI2SP-generic battery modules don't exercise credential issuance format at all and are already proven under sd_jwt_vc")
	credentialEncryption := flag.String("credential-encryption", "plain", "vci_credential_encryption variant to drive with -base-plan: \"plain\" (default) or \"encrypted\" — only meaningful with -base-plan, since the HAIP plan's own module list entries always pin \"plain\" themselves regardless of this flag; cmd/conformance-issuer already supports encrypted responses unconditionally, so this just lets oid4vci-1_0-issuer-fail-unsupported-encryption-algorithm (self-SKIPPED under \"plain\") actually run")
	credentialProofTypeHint := flag.String("credential-proof-type-hint", "jwt", "vci.credential_proof_type_hint to drive with: \"jwt\" (default) or \"attestation\" — attestation restricts the driven module set to the 3 modules in keyAttestationBattery (metadata-test, happy-flow, fail-invalid-key-attestation-signature), the same restriction -credential-format mdoc applies, and for the same reason: none of the other 40 FAPI2SP-generic battery modules care which proof type is used")
	issuerInitiated := flag.Bool("issuer-initiated", false, "drive the HAIP plan's issuer_initiated flow variant instead of the default wallet_initiated one — this binary must construct and submit a Credential Offer to the suite's own exposed credential_offer_endpoint before each module can proceed, see submitCredentialOffer's own doc comment")
	flag.Parse()

	planName := "oid4vci-1_0-issuer-haip-test-plan"
	battery := haipBattery
	switch {
	case *credentialFormat == "mdoc":
		battery = mdocBattery
	case *credentialProofTypeHint == "attestation":
		battery = keyAttestationBattery
	}
	planVariant := map[string]string{"credential_format": *credentialFormat} //nolint:gosec // a suite variant selector value, not a credential
	if *basePlan {
		// The base plan's own module list entries pin no variant at all
		// (VCIIssuerTestPlan.java's own testModulesWithVariants() passes
		// an empty selector list to every ModuleListEntry) — every axis
		// the HAIP plan's own module list entries already fix must be
		// supplied here instead, matching what VCIIssuerTestPlanHaip.java
		// itself pins for the equivalent modules, just fapi_profile=vci
		// instead of vci_haip (confirmed live).
		planName = "oid4vci-1_0-issuer-test-plan"
		battery = baseBattery
		planVariant["client_auth_type"] = "client_attestation"
		planVariant["sender_constrain"] = "dpop"
		planVariant["fapi_request_method"] = "unsigned"
		planVariant["fapi_profile"] = "vci"
		planVariant["vci_grant_type"] = "authorization_code"
		planVariant["authorization_request_type"] = "simple"
		planVariant["vci_credential_encryption"] = *credentialEncryption
		planVariant["openid"] = "plain_oauth"
		planVariant["fapi_response_mode"] = "plain_response"
	}

	httpClient := insecureSuiteHTTPClient()

	run, err := generateRun(*alias, *issuerBaseURL)
	if err != nil {
		log.Fatalf("generate run: %v", err)
	}

	serverConfig, err := buildServerConfig(run)
	if err != nil {
		log.Fatalf("build server config: %v", err)
	}
	// 0o644, not 0o600: this file is bind-mounted read-only into
	// conformance-issuer's own container, which (like every
	// cmd/conformance-* image) runs as gcr.io/distroless/static-
	// debian12:nonroot's own fixed uid (65532) — a different uid than
	// whatever process writes this file on the host, so 0o600 leaves
	// the container itself unable to read its own config (confirmed
	// live in CI for the same pattern in conformance-verifier: "open
	// /config.json: permission denied"; every one of this binary's own
	// four legs failed to become ready in that same run). Every
	// key/cert here is throwaway, freshly generated per run — never a
	// real production secret — so a host-world-readable file is an
	// acceptable trade for a working readiness check.
	if err := os.WriteFile(*configOut, serverConfig, 0o644); err != nil {
		log.Fatalf("write %s: %v", *configOut, err)
	}
	log.Printf("wrote %s", *configOut)

	if !*skipDockerRestart {
		if err := restartIssuerContainer(); err != nil {
			log.Fatalf("restart conformance-issuer container: %v", err)
		}
		log.Printf("restarted conformance-issuer container, waiting for it to come up")
		if err := waitForIssuerReady(httpClient, *issuerBaseURL); err != nil {
			log.Fatalf("wait for conformance-issuer: %v", err)
		}
	}

	planConfig, err := buildPlanConfig(run, *credentialFormat, *credentialProofTypeHint)
	if err != nil {
		log.Fatalf("build plan config: %v", err)
	}

	if *issuerInitiated {
		planVariant["vci_authorization_code_flow_variant"] = "issuer_initiated"
	}
	// The same credentialConfigurationID selection buildPlanConfig
	// itself makes internally (config.go) — duplicated here rather
	// than returned from it, since only the issuer_initiated path
	// needs it, to build the Credential Offer this binary submits on
	// that plan's own behalf (see submitCredentialOffer).
	credentialConfigurationID := "IdentityCredential"
	if *credentialFormat == "mdoc" {
		credentialConfigurationID = "MobileDrivingLicence"
	}

	planID, modules, err := conformancesuite.CreatePlan(httpClient, *apiBase, planName, planVariant, planConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("created plan %s (alias %s), %d module instances enumerated", planID, run.alias, len(modules))
	log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)

	// The suite's own scripted browser usually fails to run
	// implicitCallback.html's JS (a Bootstrap 5.3.3 parse error in
	// this suite version, universal to every release supporting this
	// module family — see unblock.go's own doc comment), silently
	// stalling any module that reaches the authorization callback.
	// This poller runs for the rest of this run, unblocking those
	// modules the same way FAPIgo's own OpenID-Certified
	// cmd/conformance-as already has to.
	unblockCtx, cancelUnblock := context.WithCancel(context.Background())
	defer cancelUnblock()
	go unblockImplicitCallbacks(unblockCtx, httpClient, *apiBase, planID)

	inScope := make(map[string]bool, len(battery))
	for _, name := range battery {
		inScope[name] = true
	}

	summary := make(map[string]string)
	for _, m := range modules {
		if !inScope[m.TestModule] {
			continue
		}
		if _, already := summary[m.TestModule]; already {
			continue
		}
		log.Printf("--- %s ---", m.TestModule)
		outcome := runModule(httpClient, *apiBase, planID, m.TestModule, m.Variant, *issuerInitiated, *issuerBaseURL, credentialConfigurationID)
		summary[m.TestModule] = outcome
		log.Printf("%s: %s", m.TestModule, outcome)
	}

	log.Printf("=== summary ===")
	for _, name := range battery {
		outcome, ran := summary[name]
		if !ran {
			outcome = "NOT RUN (not found in plan's own module list)"
		}
		log.Printf("%-90s %s", name, outcome)
	}
}

func insecureSuiteHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // talks only to a locally-run, throwaway OIDF conformance suite instance and its own throwaway conformance-issuer container
		},
	}
}

// restartIssuerContainer rebuilds and recreates the conformance-issuer
// container so it picks up both the freshly-written (volume-mounted)
// config.json and, critically, this repo's own current source —
// --build is required, not optional: the binary itself (including
// whatever github.com/idfoundry/fapigo version go.mod currently pins)
// is baked into the image, not bind-mounted, so a plain
// --force-recreate silently keeps running a stale build against
// whatever source existed the last time this image was built —
// confirmed live: a real server-side fix already present in source
// appeared not to work at all, until rebuilding revealed the running
// container predated it by hours.
func restartIssuerContainer() error {
	// NOSONAR: go:S4036 -- this is a local developer CLI tool, run
	// directly from a shell (never a network-facing or multi-tenant
	// service): resolving "docker" walks the invoking developer's own
	// trusted PATH, the same one every other command they type already
	// trusts. exec.LookPath is used explicitly (rather than letting
	// exec.Command do the same lookup implicitly) so the resolved
	// absolute path is fixed before Command is built.
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find docker: %w", err)
	}
	cmd := exec.Command(dockerPath, "compose", "-f", "conformance/issuer/docker-compose.yml", "up", "-d", "--build", "--force-recreate") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals — see the NOSONAR comment above for the full justification
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// waitForIssuerReady polls issuerBaseURL's own OID4VCI metadata
// endpoint through the suite's own reverse proxy (the host only ever
// reaches this binary at the suite's own published port from outside
// the suite's docker network — apiBase's own host, not issuerBaseURL's
// suite-internal hostname, is reachable from here) — simplest reliable
// readiness signal: this loops on the host-published port instead,
// since that's the only address this script itself can dial.
func waitForIssuerReady(httpClient *http.Client, _ string) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://localhost:19448/.well-known/openid-credential-issuer", nil)
		if err == nil {
			res, doErr := httpClient.Do(req)
			if doErr == nil {
				_ = res.Body.Close()
				if res.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		if time.Now().After(deadline) {
			dumpIssuerContainerLogs()
			return fmt.Errorf("conformance-issuer did not become ready within 30s")
		}
		time.Sleep(1 * time.Second)
	}
}

// dumpIssuerContainerLogs prints the conformance-issuer container's
// own logs to stderr — best-effort, since a caller already has a real
// error to report regardless of whether this succeeds. Added after a
// real CI run silently masked this container never binding its port
// at all (every one of Issuer's four legs, every run) since nothing
// captured the container's own stdout/stderr before this.
func dumpIssuerContainerLogs() {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return
	}
	cmd := exec.Command(dockerPath, "compose", "-f", "conformance/issuer/docker-compose.yml", "logs", "--no-color", "--tail=200") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	out, runErr := cmd.CombinedOutput()
	log.Printf("container logs (conformance/issuer/docker-compose.yml):\n%s", out)
	if runErr != nil {
		log.Printf("docker compose logs: %v", runErr)
	}
}

// runModule creates one module instance and polls it to completion —
// no flow-driving at all, see the package doc comment for why.
// metadataSignedTestName is metadata-test-signed's own testName — named
// here (unlike other battery literals) because runModule needs to
// check for it specifically, alongside metadataTestName: both classes
// extend AbstractVciTest, not AbstractFAPI2SPFinalServerTestModule
// (VCIIssuerTestPlan.java's own doc comment), so neither ever goes
// through the authorization flow — or its own issuer_initiated
// Credential Offer step — at all, regardless of
// vci_authorization_code_flow_variant.
const metadataSignedTestName = "oid4vci-1_0-issuer-metadata-test-signed"

// vciIssuerTestNamePrefix is every OID4VCI-specific issuer module's own
// testName prefix (VCIIssuerTestPlanHaip's own vciTestModules() entries)
// — the only classes that ever wait for a Credential Offer under
// vci_authorization_code_flow_variant=issuer_initiated at all. The
// generic FAPI2SP battery modules (fapi2-security-profile-final-*,
// including the plan's own Discovery module) are plain
// AbstractFAPI2SPFinalServerTestModule subclasses that don't implement
// waitForCredentialOffer and don't apply this variant — confirmed live:
// driving the full battery under -issuer-initiated without this prefix
// check made every one of them either time out waiting for WAITING (an
// already-passing module that never needed a Credential Offer at all)
// or reach WAITING with no credential_offer_endpoint exposed, both
// unconditional errors, not a real regression in the modules
// themselves.
const vciIssuerTestNamePrefix = "oid4vci-1_0-issuer-"

func runModule(httpClient *http.Client, apiBase, planID, testName string, variant map[string]string, issuerInitiated bool, issuerBaseURL, credentialConfigurationID string) string {
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}

	needsCredentialOffer := issuerInitiated &&
		strings.HasPrefix(testName, vciIssuerTestNamePrefix) &&
		testName != metadataTestName && testName != metadataSignedTestName
	if needsCredentialOffer {
		if err := submitCredentialOffer(httpClient, apiBase, module.ID, issuerBaseURL, credentialConfigurationID); err != nil {
			return "ERROR: submit credential offer: " + err.Error() + " (module " + module.ID + ")"
		}
	}

	// 120s, not 60s: unlike cmd/conformance-wallet's own outbound-HTTP-only
	// flow, the suite's own internal headless browser renders and
	// clicks through the authorize/consent page itself here — real,
	// visible latency (confirmed live: a module still mid-flow at 60s
	// — already past PAR, redirect, and the consent click — got marked
	// ERROR by this binary's own too-short timeout, then the *next*
	// module's own plan-alias reuse collided with the still-finishing
	// previous one, cascading into a false "alias conflict"
	// INTERRUPTED on top of the real problem).
	status, result, err := conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, 120*time.Second)
	if err != nil {
		return "ERROR: " + err.Error() + " (module " + module.ID + ")"
	}
	return status + "=" + result + " (module " + module.ID + ", " + apiBase + "api/log/" + module.ID + ")"
}

// submitCredentialOffer drives the issuer_initiated flow variant's own
// starting step: wait for moduleID to reach WAITING (per the suite's
// own AbstractVCIIssuerTestModule.waitForCredentialOffer), read its
// exposed "credential_offer_endpoint" (GET /api/runner/{id} — the
// live, in-memory value; GET /api/info/{id}, this file's own
// WaitUntilWaiting/WaitUntilFinished's usual endpoint, never carries
// it, confirmed live), build a by-value Credential Offer naming
// issuerBaseURL/credentialConfigurationID with a fresh issuer_state,
// and GET that offer's own query parameters to the exposed endpoint —
// mirroring exactly what a real Wallet does scanning a QR code/deep
// link (a plain GET, "credential_offer" or "credential_offer_uri" in
// the query string, never both — see
// VCIValidateCredentialOfferRequestParams.java). The suite then drives
// the rest of the flow (PAR through Credential Endpoint) entirely on
// its own once this succeeds — see
// AbstractVCIIssuerTestModule.handleCredentialOffer — so this function
// returns as soon as the GET itself succeeds; runModule's own
// subsequent WaitUntilFinished call covers the rest.
func submitCredentialOffer(httpClient *http.Client, apiBase, moduleID, issuerBaseURL, credentialConfigurationID string) error {
	if err := conformancesuite.WaitUntilWaiting(httpClient, apiBase, moduleID, 30*time.Second); err != nil {
		return fmt.Errorf("wait for credential offer endpoint: %w", err)
	}
	exposed, err := conformancesuite.GetExposedValues(httpClient, apiBase, moduleID)
	if err != nil {
		return fmt.Errorf("get exposed values: %w", err)
	}
	endpoint := exposed["credential_offer_endpoint"]
	if endpoint == "" {
		return fmt.Errorf("module has no exposed credential_offer_endpoint")
	}

	issuerState, err := randomIssuerState()
	if err != nil {
		return fmt.Errorf("generate issuer_state: %w", err)
	}
	offer := oid4vci.CredentialOffer{
		CredentialIssuer:           issuerBaseURL,
		CredentialConfigurationIDs: []string{credentialConfigurationID},
		Grants: &oid4vci.Grants{
			AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: issuerState},
		},
	}
	offerURL, err := offer.AppendToURL(endpoint)
	if err != nil {
		return fmt.Errorf("build credential offer url: %w", err)
	}

	req, err := http.NewRequest(http.MethodGet, offerURL, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	body, status, err := conformancesuite.Do(httpClient, req)
	if err != nil {
		return fmt.Errorf("submit credential offer: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("submit credential offer: status %d: %s", status, body)
	}
	return nil
}

// randomIssuerState generates a fresh issuer_state value (RFC 7519-style
// opaque string, no structure the Wallet is expected to parse) for one
// Credential Offer — matching issuer.generateCredentialOfferReference's
// own entropy choice.
func randomIssuerState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// privateJWKSet builds a single-key private JWK Set ({"keys":[...]})
// for key, tagged with kid and an explicit "alg":"ES256" — the suite's
// own JWT-signing code has been found, repeatedly across this binary's
// sister cmd/conformance-wallet work, to require an explicit alg on
// every key it signs with ("No algorithm specified for key"), unlike
// conformancecert.JWKSet's own public-only, alg-less shape (which
// cmd/conformance-issuer's server-side verification tolerates fine,
// confirmed by the 21 already-passing modules using it). leafCertPEM,
// when non-empty, embeds the certificate's own DER as this key's own
// "x5c" member (RFC 7517 §4.7) — required when the suite itself signs
// with this key under HAIP (confirmed live: AbstractSignJWT.java's own
// "errorIfX5cMissing" path for the Client Attestation JWT), independent
// of whether the verifying party (cmd/conformance-issuer) ever looks at
// x5c at all.
func privateJWKSet(key *ecdsa.PrivateKey, kid, leafCertPEM string) (json.RawMessage, error) {
	priv, err := jwk.MarshalPrivate(key)
	if err != nil {
		return nil, err
	}
	entry := jwk.SetEntry{JWK: priv, Kid: kid, Alg: "ES256"}
	if leafCertPEM != "" {
		cert, err := conformancecert.ParseCertificatePEM(leafCertPEM)
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		entry.X5C = []string{base64.StdEncoding.EncodeToString(cert.Raw)}
	}
	return json.Marshal(jwk.Set{Keys: []jwk.SetEntry{entry}})
}

// publicJWK builds a single bare public JWK (no "keys" wrapper, no
// kid) with an explicit alg — the shape
// vci10issuer/condition/clientattestation/CreateClientAttestationJwt.java's
// own "cnf.jwk" claim needs verbatim (client.client_instance_key_public).
func publicJWK(pub *ecdsa.PublicKey) (string, error) {
	j, err := jwk.Marshal(pub)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(jwk.SetEntry{JWK: j, Alg: "ES256"})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// privateJWKRaw builds a single bare private JWK (no "keys" wrapper)
// with an explicit alg — the shape
// condition/client/CreateClientAttestationProofJwt.java's own
// client.client_instance_key needs: JWKUtil.createJwksObjectFromJwkObjects
// wraps a single bare JWK object into a JWK Set itself, so this must
// NOT already be wrapped.
func privateJWKRaw(key *ecdsa.PrivateKey) (string, error) {
	priv, err := jwk.MarshalPrivate(key)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(jwk.SetEntry{JWK: priv, Alg: "ES256"})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

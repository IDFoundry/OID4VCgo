// Command conformance-wallet drives oid4vcigo/wallet and
// fapigo/client headlessly through the OIDF conformance suite's own
// "oid4vci-1_0-wallet-haip-test-plan" ("OpenID for Verifiable
// Credential Issuance 1.0 Final/HAIP: Test a wallet") — specifically
// the wallet_initiated flow variant's 4 non-battery modules
// (VCIWalletTestCredentialIssuance,
// VCIWalletTestCredentialIssuanceWithNotification,
// VCIWalletTestBatchCredentialIssuance,
// VCIWalletTestClientAttestationChallenge), crossed with all 3 of the
// plan's own issuance-mode/encryption variants (immediate+plain,
// deferred+plain, immediate+encrypted), plus the plan's 4th
// module-list entry — the generic FAPI2SP client conformance battery,
// always at the fixed immediate+plain crossing. See
// conformance/wallet/README.md for what this covers and what's still
// open.
//
// Unlike this repo's other three conformance binaries, this one is a
// one-shot CLI tool, not a long-running HTTP server: for the OID4VCI
// Wallet role, the suite itself plays the entire Authorization Server
// and Credential Issuer (see flow.go's own doc comments), so this
// binary is the outbound HTTP client, the same shape as FAPIgo's own
// cmd/conformance-client.
//
// Usage:
//
//	go run ./cmd/conformance-wallet
//	go run ./cmd/conformance-wallet -suite https://localhost:8443/ -credential-configuration-id eu.europa.ec.eudi.pid.1 -scope eudi.pid.1
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// inScopeModules is this run's own testName -> credential count map —
// the wallet_initiated flow variant's 4 non-battery modules plus the
// plan's 4th module-list entry, the generic FAPI2SP client battery
// (see the package doc comment). Every module in this map requests
// exactly one credential except the batch one, which requests two
// (§8.2's own multi-proof example — enough to exercise a genuine batch
// without an arbitrary large count).
var inScopeModules = map[string]int{
	"oid4vci-1_0-wallet-test-credential-issuance":              1,
	"oid4vci-1_0-wallet-test-credential-issuance-notification": 1,
	"oid4vci-1_0-wallet-test-client-attestation-challenge":     1,
	"oid4vci-1_0-wallet-test-batch-credential-issuance":        2,

	// The HAIP plan's 4th module-list entry: the generic FAPI2SP client
	// conformance battery (FAPI2MessageSigningFinalClientTestPlan's own
	// module list, minus every id_token/JARM/OpenBanking-only module —
	// HAIP's wallet is plain_oauth+plain_response). Always run at the
	// fixed immediate+plain crossing (VCIWalletTestPlanHaip.java
	// hardcodes it for this entry specifically), so these share the
	// existing {immediate, plain} entry in inScopeCrossings below — no
	// new crossing needed. Exact testName strings confirmed against the
	// running suite's own /api/runner/available.
	"fapi2-security-profile-final-client-test-happy-path":                                                     1,
	"fapi2-security-profile-final-client-test-happy-path-no-dpop-nonce":                                       1,
	"fapi2-security-profile-final-client-test-discovery-issuer-mismatch":                                      1,
	"fapi2-security-profile-final-client-test-remove-authorization-response-iss":                              1,
	"fapi2-security-profile-final-client-test-invalid-authorization-response-iss":                             1,
	"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails":         1,
	"fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-missing-state-fails": 1,
	"fapi2-security-profile-final-client-test-token-endpoint-response-without-expires_in":                     1,
	"fapi2-security-profile-final-client-test-token-type-case-insensitivity":                                  1,
	"fapi2-security-profile-final-client-test-rs-dpop-auth-scheme-case-insensitivity":                         1,
}

// issuanceCrossing is one (vci_credential_issuance_mode,
// vci_credential_encryption) variant pair this run drives every
// in-scope module through.
type issuanceCrossing struct {
	issuanceMode string
	encryption   string
}

func (c issuanceCrossing) String() string { return c.issuanceMode + "+" + c.encryption }

// inScopeCrossings are the issuance-mode/encryption crossings this run
// drives — the HAIP plan's own 3 crossings for these 4 modules.
var inScopeCrossings = []issuanceCrossing{
	{issuanceMode: "immediate", encryption: "plain"},
	{issuanceMode: "deferred", encryption: "plain"},
	{issuanceMode: "immediate", encryption: "encrypted"},
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	// eu.europa.ec.eudi.pid.1/eudi.pid.1 are the suite's own fixed
	// jwt-proof-type fixture credential configuration id/scope
	// (confirmed live from a created module's own credential issuer
	// metadata — not an arbitrary tester-chosen name).
	credentialConfigurationID := flag.String("credential-configuration-id", "eu.europa.ec.eudi.pid.1", "credential_configuration_id to request — must match one the suite's own emulated Credential Issuer actually publishes")
	scope := flag.String("scope", "eudi.pid.1", "scope to request — must match the credential configuration's own \"scope\" value in the suite's emulated Credential Issuer metadata")
	dumpConfig := flag.Bool("dump-config", false, "print the generated suite-side plan configuration JSON and exit, instead of creating a plan — useful for probing the suite's own POST /api/plan validation by hand")
	flag.Parse()

	if *dumpConfig {
		walletRun, err := newWalletRun(*apiBase, *credentialConfigurationID, *scope)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(walletRun.planConfig); err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		return
	}

	if err := run(*apiBase, *credentialConfigurationID, *scope); err != nil {
		log.Fatal(err)
	}
}

func insecureSuiteHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // talks only to a locally-run, throwaway OIDF conformance suite instance
		},
	}
}

func run(apiBase, credentialConfigurationID, scope string) error {
	ctx := context.Background()
	httpClient := insecureSuiteHTTPClient()

	walletRun, err := newWalletRun(apiBase, credentialConfigurationID, scope)
	if err != nil {
		return err
	}

	planID, modules, err := createPlan(httpClient, apiBase, "oid4vci-1_0-wallet-haip-test-plan",
		map[string]string{"credential_format": "sd_jwt_vc"}, walletRun.planConfig) //nolint:gosec // false positive: a suite variant selector value, not a credential
	if err != nil {
		return err
	}
	log.Printf("created plan %s (alias %s), %d module instances enumerated", planID, walletRun.alias, len(modules))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	summary := make(map[string]string)
	for _, m := range modules {
		numCreds, ok := inScopeModules[m.TestModule]
		if !ok {
			continue
		}
		crossing, ok := matchCrossing(m.TestModule, m.Variant)
		if !ok {
			continue
		}
		key := m.TestModule + " [" + crossing.String() + "]"
		if _, already := summary[key]; already {
			// The suite lists this same module/variant crossing more
			// than once (shouldn't happen for this plan's own module
			// list, but skip defensively rather than double-run it).
			continue
		}
		log.Printf("--- %s ---", key)
		outcome := runModule(ctx, httpClient, apiBase, planID, m.TestModule, m.Variant, numCreds, crossing.encryption == "encrypted", walletRun)
		summary[key] = outcome
		log.Printf("%s: %s", key, outcome)
	}

	log.Printf("=== summary ===")
	for name := range inScopeModules {
		for _, crossing := range crossingsFor(name) {
			key := name + " [" + crossing.String() + "]"
			outcome, ran := summary[key]
			if !ran {
				outcome = "NOT RUN (not found in plan's own module list)"
			}
			log.Printf("%-70s %s", key, outcome)
		}
	}
	return nil
}

// batteryModulePrefix identifies the HAIP plan's 4th module-list entry
// (the generic FAPI2SP client battery) — those testNames, unlike the 4
// VCIWallet* modules, are never crossed with issuance-mode/encryption
// variants: VCIWalletTestPlanHaip.java hardcodes
// VCICredentialIssuanceMode=immediate/VCICredentialEncryption=plain for
// this entry specifically.
const batteryModulePrefix = "fapi2-security-profile-final-client-test-"

// crossingsFor reports which of inScopeCrossings apply to testName —
// all 3 for the 4 VCIWallet* modules, just immediate+plain for the
// battery (see batteryModulePrefix).
func crossingsFor(testName string) []issuanceCrossing {
	if strings.HasPrefix(testName, batteryModulePrefix) {
		return inScopeCrossings[:1]
	}
	return inScopeCrossings
}

// matchCrossing reports whether variant matches one of the crossings
// applicable to testName, returning the matching crossing.
func matchCrossing(testName string, variant map[string]string) (issuanceCrossing, bool) {
	for _, c := range crossingsFor(testName) {
		if variant["vci_credential_issuance_mode"] == c.issuanceMode && variant["vci_credential_encryption"] == c.encryption {
			return c, true
		}
	}
	return issuanceCrossing{}, false
}

// runModule creates one module instance, drives it via driveModule,
// and returns the suite's own graded verdict — the only thing that
// actually determines PASS/FAIL, per driveModule's own doc comment.
func runModule(ctx context.Context, httpClient *http.Client, apiBase, planID, testName string, variant map[string]string, numCreds int, encrypted bool, walletRun *walletRun) string {
	module, err := createModuleInstance(httpClient, apiBase, planID, testName, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}
	if err := waitUntilWaiting(httpClient, apiBase, module.ID, 10*time.Second); err != nil {
		return "ERROR: wait for module ready: " + err.Error()
	}

	driverErr := ""
	if err := driveModule(ctx, walletRun, module, testName, httpClient, numCreds, encrypted); err != nil {
		driverErr = err.Error()
	}

	status, result, err := waitUntilFinished(httpClient, apiBase, module.ID, 45*time.Second)
	if err != nil {
		if driverErr != "" {
			return "ERROR [driver: " + driverErr + "] (also: " + err.Error() + ")"
		}
		return "ERROR: " + err.Error() + " (module " + module.ID + ")"
	}
	outcome := status + "=" + result + " (module " + module.ID + ", " + apiBase + "api/log/" + module.ID + ")"
	if driverErr != "" {
		outcome += " [driver: " + driverErr + "]"
	}
	return outcome
}

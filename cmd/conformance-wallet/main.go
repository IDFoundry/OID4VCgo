// Command conformance-wallet drives oid4vcigo/wallet and
// fapigo/client headlessly through the OIDF conformance suite's own
// "oid4vci-1_0-wallet-haip-test-plan" ("OpenID for Verifiable
// Credential Issuance 1.0 Final/HAIP: Test a wallet") — specifically
// the wallet_initiated, immediate+plain crossing of its 4 non-battery
// modules (VCIWalletTestCredentialIssuance,
// VCIWalletTestCredentialIssuanceWithNotification,
// VCIWalletTestBatchCredentialIssuance,
// VCIWalletTestClientAttestationChallenge). See
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
	"log"
	"net/http"
	"time"
)

// inScopeModules is this run's own testName -> credential count map —
// the wallet_initiated, immediate+plain crossing's 4 non-battery
// modules (see the package doc comment). Every module in this map
// requests exactly one credential except the batch one, which requests
// two (§8.2's own multi-proof example — enough to exercise a genuine
// batch without an arbitrary large count).
var inScopeModules = map[string]int{
	"oid4vci-1_0-wallet-test-credential-issuance":              1,
	"oid4vci-1_0-wallet-test-credential-issuance-notification": 1,
	"oid4vci-1_0-wallet-test-client-attestation-challenge":     1,
	"oid4vci-1_0-wallet-test-batch-credential-issuance":        2,
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	// eu.europa.ec.eudi.pid.1/eudi.pid.1 are the suite's own fixed
	// jwt-proof-type fixture credential configuration id/scope
	// (confirmed live from a created module's own credential issuer
	// metadata — not an arbitrary tester-chosen name).
	credentialConfigurationID := flag.String("credential-configuration-id", "eu.europa.ec.eudi.pid.1", "credential_configuration_id to request — must match one the suite's own emulated Credential Issuer actually publishes")
	scope := flag.String("scope", "eudi.pid.1", "scope to request — must match the credential configuration's own \"scope\" value in the suite's emulated Credential Issuer metadata")
	flag.Parse()

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
		if !ok || m.Variant["vci_credential_issuance_mode"] != "immediate" || m.Variant["vci_credential_encryption"] != "plain" {
			continue
		}
		if _, already := summary[m.TestModule]; already {
			// The suite lists this same module/variant crossing more
			// than once (shouldn't happen for this plan's own module
			// list, but skip defensively rather than double-run it).
			continue
		}
		log.Printf("--- %s ---", m.TestModule)
		outcome := runModule(ctx, httpClient, apiBase, planID, m.TestModule, m.Variant, numCreds, walletRun)
		summary[m.TestModule] = outcome
		log.Printf("%s: %s", m.TestModule, outcome)
	}

	log.Printf("=== summary ===")
	for name := range inScopeModules {
		outcome, ran := summary[name]
		if !ran {
			outcome = "NOT RUN (not found in plan's own module list)"
		}
		log.Printf("%-70s %s", name, outcome)
	}
	return nil
}

// runModule creates one module instance, drives it via driveModule,
// and returns the suite's own graded verdict — the only thing that
// actually determines PASS/FAIL, per driveModule's own doc comment.
func runModule(ctx context.Context, httpClient *http.Client, apiBase, planID, testName string, variant map[string]string, numCreds int, walletRun *walletRun) string {
	module, err := createModuleInstance(httpClient, apiBase, planID, testName, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}
	if err := waitUntilWaiting(httpClient, apiBase, module.ID, 10*time.Second); err != nil {
		return "ERROR: wait for module ready: " + err.Error()
	}

	driverErr := ""
	if err := driveModule(ctx, walletRun, module, httpClient, numCreds); err != nil {
		driverErr = err.Error()
	}

	status, result, err := waitUntilFinished(httpClient, apiBase, module.ID, 45*time.Second)
	if err != nil {
		if driverErr != "" {
			return "ERROR [driver: " + driverErr + "] (also: " + err.Error() + ")"
		}
		return "ERROR: " + err.Error()
	}
	if driverErr != "" {
		return status + "=" + result + " [driver: " + driverErr + "]"
	}
	return status + "=" + result
}

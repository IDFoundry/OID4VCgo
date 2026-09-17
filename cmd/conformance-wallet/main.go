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

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcigo/wallet"
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

// runConfig bundles every flag main() parses — introduced once the
// flag list grew past a handful of positional parameters (adding the
// issuer_initiated flow variant's own listener settings).
type runConfig struct {
	apiBase                   string
	credentialConfigurationID string
	scope                     string
	proofType                 proofStrategy

	// issuerInitiated selects the HAIP plan's issuer_initiated flow
	// variant (vci_authorization_code_flow_variant) instead of the
	// default wallet_initiated one — see credentialoffer.go's own doc
	// comment for what this actually changes about the driven flow (and
	// why, despite the name, this binary never needs to actually
	// receive an inbound request for it). issuer_initiated_dc_api isn't
	// covered: it needs real Digital Credentials API browser-JS
	// interaction, the same scope cut this repo's own
	// cmd/conformance-wallet-vp already makes for its own dc_api.jwt
	// module lists.
	issuerInitiated bool

	// credentialOfferEndpoint becomes this run's own
	// vci.credential_offer_endpoint config value (plus
	// credentialOfferPath) — an OID4VCI Credential Offer's own
	// "how a real wallet would be reached" detail, but per
	// credentialoffer.go's own doc comment this binary never needs it
	// to be reachable at all, so the default is a plausible-looking but
	// entirely inert placeholder. Only used when issuerInitiated is set.
	credentialOfferEndpoint string
}

func main() {
	var cfg runConfig
	flag.StringVar(&cfg.apiBase, "suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	// eu.europa.ec.eudi.pid.1/eudi.pid.1 are the suite's own fixed
	// jwt-proof-type fixture credential configuration id/scope
	// (confirmed live from a created module's own credential issuer
	// metadata — not an arbitrary tester-chosen name).
	flag.StringVar(&cfg.credentialConfigurationID, "credential-configuration-id", "eu.europa.ec.eudi.pid.1", "credential_configuration_id to request — must match one the suite's own emulated Credential Issuer actually publishes")
	flag.StringVar(&cfg.scope, "scope", "eudi.pid.1", "scope to request — must match the credential configuration's own \"scope\" value in the suite's emulated Credential Issuer metadata")
	proofTypeFlag := flag.String("proof-type", string(proofStrategyJWT), "Credential Request proof strategy: \"jwt\" (default, jwk-conveyed jwt-type proof), \"attestation\" (standalone Key Attestation JWT, Appendix F.3 / HAIP §4.5.1 — requires -credential-configuration-id eu.europa.ec.eudi.pid.1.attestation -scope eudi.pid.1.attestation), or \"jwt-key-attestation\" (jwt-type proof with a nested Key Attestation JWT header, Appendix D.1 — requires -credential-configuration-id eu.europa.ec.eudi.pid.1.jwt.keyattest -scope eudi.pid.1.jwt.keyattest)")
	flag.BoolVar(&cfg.issuerInitiated, "issuer-initiated", false, "drive the HAIP plan's issuer_initiated flow variant instead of the default wallet_initiated one — the suite hands this binary a Credential Offer to resolve instead of this binary calling /authorize directly")
	flag.StringVar(&cfg.credentialOfferEndpoint, "credential-offer-endpoint", "https://oid4vcigo-wallet.example.com", "base URL for this run's own vci.credential_offer_endpoint config value (only used with -issuer-initiated) — never actually dereferenced by this binary or, in practice, by the suite either (see credentialoffer.go), so the default is an inert placeholder")
	dumpConfig := flag.Bool("dump-config", false, "print the generated suite-side plan configuration JSON and exit, instead of creating a plan — useful for probing the suite's own POST /api/plan validation by hand")
	flag.Parse()

	cfg.proofType = proofStrategy(*proofTypeFlag)
	switch cfg.proofType {
	case proofStrategyJWT, proofStrategyAttestation, proofStrategyJWTKeyAttestation:
	default:
		log.Fatalf("invalid -proof-type %q: want jwt, attestation, or jwt-key-attestation", *proofTypeFlag)
	}

	if *dumpConfig {
		walletRun, err := newWalletRun(cfg)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := os.Stdout.Write(walletRun.planConfig); err != nil {
			log.Fatal(err)
		}
		fmt.Println()
		return
	}

	if err := run(cfg); err != nil {
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

func run(cfg runConfig) error {
	ctx := context.Background()
	httpClient := insecureSuiteHTTPClient()

	walletRun, err := newWalletRun(cfg)
	if err != nil {
		return err
	}

	var offerWallet *wallet.Wallet
	if cfg.issuerInitiated {
		offerWallet, err = newWallet(httpClient)
		if err != nil {
			return fmt.Errorf("build credential offer wallet: %w", err)
		}
	}

	planVariant := map[string]string{"credential_format": "sd_jwt_vc"} //nolint:gosec // false positive: a suite variant selector value, not a credential
	if cfg.issuerInitiated {
		planVariant["vci_authorization_code_flow_variant"] = "issuer_initiated"
	}
	planID, modules, err := conformancesuite.CreatePlan(httpClient, cfg.apiBase, "oid4vci-1_0-wallet-haip-test-plan", planVariant, walletRun.planConfig)
	if err != nil {
		return err
	}
	log.Printf("created plan %s (alias %s), %d module instances enumerated", planID, walletRun.alias, len(modules))
	log.Printf("plan detail: %splan-detail.html?plan=%s", cfg.apiBase, planID)

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
		outcome := runModule(ctx, httpClient, cfg.apiBase, planID, m.TestModule, m.Variant, numCreds, crossing.encryption == "encrypted", walletRun, offerWallet)
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
// offerWallet is non-nil only for the issuer_initiated flow variant —
// see credentialoffer.go's own doc comment for why the offer has to
// be captured here, before waitUntilWaiting, rather than inside
// driveModule alongside everything else it drives.
func runModule(ctx context.Context, httpClient *http.Client, apiBase, planID, testName string, variant map[string]string, numCreds int, encrypted bool, walletRun *walletRun, offerWallet *wallet.Wallet) string {
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
	}

	var offer *oid4vci.CredentialOffer
	// The FAPI2SP battery modules extend AbstractTestModule directly,
	// not AbstractVCIWalletTest — they have no prepareCredentialOffer()
	// step at all and never log a credential offer redirect url
	// regardless of vci_authorization_code_flow_variant, so waiting for
	// one here would just time out every time. They behave identically
	// under both flow variants; only the 4 VCIWalletTest* modules
	// actually branch on it.
	if offerWallet != nil && !strings.HasPrefix(testName, batteryModulePrefix) {
		offerURL, offerErr := waitForCredentialOfferRedirectURL(httpClient, apiBase, module.ID, 10*time.Second)
		if offerErr != nil {
			return "ERROR: wait for credential offer: " + offerErr.Error()
		}
		resolved, offerErr := offerWallet.ResolveCredentialOffer(ctx, offerURL)
		if offerErr != nil {
			return "ERROR: resolve credential offer: " + offerErr.Error()
		}
		offer = &resolved
	}

	if err := conformancesuite.WaitUntilWaiting(httpClient, apiBase, module.ID, 10*time.Second); err != nil {
		return "ERROR: wait for module ready: " + err.Error()
	}

	driverErr := ""
	if err := driveModule(ctx, walletRun, module, testName, httpClient, numCreds, encrypted, offer); err != nil {
		driverErr = err.Error()
	}

	status, result, err := conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, 45*time.Second)
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

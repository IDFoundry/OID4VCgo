// Command run-fapi2sp-battery drives the HAIP issuer test plan's own
// generic FAPI2SP client conformance battery
// (VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules(), 39 modules) plus
// its own Discovery module (a separate ModuleListEntry) against a real,
// locally-run OIDF conformance suite instance and a real
// cmd/conformance-issuer — the suite plays the FAPI2 client/wallet, this
// binary's job is entirely config generation and result polling, not
// driving any flow itself (see the package doc comment below for why).
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
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// battery is every testName this binary drives — the HAIP issuer
// plan's own Discovery module (its own ModuleListEntry, no VCI variant
// parameters) plus the 39-module generic FAPI2SP client battery
// (VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules()), confirmed
// against the suite's own Java source by set-subtracting
// FAPI2MessageSigningFinalTestPlan.testModules minus the signing-only
// removals in FAPI2SPFinalTestPlan.fapi2SPtestModules() minus the
// nonce/OIDC-only, private_key_jwt-only, and profile-specific removals
// VCIIssuerTestPlanHaip.vciFapi2SPFinalTestModules() itself applies —
// not guessed, and cross-checked against every module's own
// @PublishTestModule testName. Also includes the two already-known-
// passing sanity modules (metadata, happy-flow) first, to confirm this
// binary's freshly-generated config is behavior-preserving before
// spending time on the 40 modules nothing has ever driven.
var battery = []string{
	// Sanity check: already-passing modules, confirming the freshly
	// generated config/keys are behavior-preserving.
	"oid4vci-1_0-issuer-metadata-test",
	"oid4vci-1_0-issuer-happy-flow",

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

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	alias := flag.String("alias", "oid4vcigo-issuer", "suite plan alias — also the callback path segment; must match cmd/conformance-issuer's own registered redirect_uris")
	issuerBaseURL := flag.String("issuer", "https://conformance-issuer:8443", "cmd/conformance-issuer's own externally-reachable base URL (suite-network-internal hostname)")
	configOut := flag.String("config-out", "conformance/issuer/oidf-config/haip.config.json", "path to write cmd/conformance-issuer's own generated server config to")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-issuer container after writing the new config (for repeat runs against a container already restarted once)")
	flag.Parse()

	httpClient := insecureSuiteHTTPClient()

	run, err := generateRun(*alias, *issuerBaseURL)
	if err != nil {
		log.Fatalf("generate run: %v", err)
	}

	serverConfig, err := buildServerConfig(run)
	if err != nil {
		log.Fatalf("build server config: %v", err)
	}
	if err := os.WriteFile(*configOut, serverConfig, 0o600); err != nil {
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

	planConfig, err := buildPlanConfig(run)
	if err != nil {
		log.Fatalf("build plan config: %v", err)
	}

	planID, modules, err := createPlan(httpClient, *apiBase, "oid4vci-1_0-issuer-haip-test-plan",
		map[string]string{"credential_format": "sd_jwt_vc"}, planConfig) //nolint:gosec // a suite variant selector value, not a credential
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
		outcome := runModule(httpClient, *apiBase, planID, m.TestModule, m.Variant)
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
	cmd := exec.Command("docker", "compose", "-f", "conformance/issuer/docker-compose.yml", "up", "-d", "--build", "--force-recreate")
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
			return fmt.Errorf("conformance-issuer did not become ready within 30s")
		}
		time.Sleep(1 * time.Second)
	}
}

// runModule creates one module instance and polls it to completion —
// no flow-driving at all, see the package doc comment for why.
func runModule(httpClient *http.Client, apiBase, planID, testName string, variant map[string]string) string {
	module, err := createModuleInstance(httpClient, apiBase, planID, testName, variant)
	if err != nil {
		return "ERROR: create module instance: " + err.Error()
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
	status, result, err := waitUntilFinished(httpClient, apiBase, module.ID, 120*time.Second)
	if err != nil {
		return "ERROR: " + err.Error() + " (module " + module.ID + ")"
	}
	return status + "=" + result + " (module " + module.ID + ", " + apiBase + "api/log/" + module.ID + ")"
}

// b64 base64url-encodes b without padding — every JWK coordinate this
// binary emits uses this encoding (RFC 7518 §6.2).
func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
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
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	d, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode private scalar: %w", err)
	}
	entry := map[string]any{
		"kty": pub.Kty, "crv": pub.Crv, "x": pub.X, "y": pub.Y, "alg": "ES256", "kid": kid,
		"d": b64(d),
	}
	if leafCertPEM != "" {
		cert, err := conformancecert.ParseCertificatePEM(leafCertPEM)
		if err != nil {
			return nil, fmt.Errorf("parse leaf certificate: %w", err)
		}
		entry["x5c"] = []string{base64.StdEncoding.EncodeToString(cert.Raw)}
	}
	return json.Marshal(map[string]any{"keys": []map[string]any{entry}})
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
	raw, err := json.Marshal(map[string]any{"kty": j.Kty, "crv": j.Crv, "x": j.X, "y": j.Y, "alg": "ES256"})
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
	pub, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return "", err
	}
	d, err := key.Bytes()
	if err != nil {
		return "", fmt.Errorf("encode private scalar: %w", err)
	}
	raw, err := json.Marshal(map[string]any{
		"kty": pub.Kty, "crv": pub.Crv, "x": pub.X, "y": pub.Y, "alg": "ES256",
		"d": b64(d),
	})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

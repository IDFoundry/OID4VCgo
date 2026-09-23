// Package conformanceverifier holds the pieces
// conformance/verifier/scripts/run-mdoc-module and
// conformance/verifier/scripts/run-sdjwt-modules both need —
// generating fresh key material, writing/restarting
// cmd/conformance-verifier's own config, building the suite's own
// plan-configuration body, and driving one module via the documented
// two-request interaction model — factored out once both scripts
// turned out to duplicate all of it near-verbatim (confirmed live by
// SonarCloud's own duplication gate on the PR that added the second
// script). Verifier-role-specific, unlike internal/conformancesuite
// (generic to the suite itself, shared across every role's own
// scripts).
package conformanceverifier

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// DockerComposeFile is the one conformance-verifier docker-compose.yml
// both scripts restart — a repo-root-relative path, since both scripts
// are only ever run via `go run` from the repo root (see either
// script's own Usage comment).
const DockerComposeFile = "conformance/verifier/docker-compose.yml"

// ConfigOutPath is where both scripts write cmd/conformance-verifier's
// own config.json — the one path docker-compose.yml mounts in.
const ConfigOutPath = "conformance/verifier/oidf-config/haip.config.json"

// PlanName is the one suite test plan both scripts create — the same
// oid4vp-1final-verifier-haip-test-plan, just under a different
// credential_format plan variant.
const PlanName = "oid4vp-1final-verifier-haip-test-plan"

const (
	restartTimeout = 30 * time.Second
	// uploadTimeout bounds fillUploadPlaceholder's own poll for the
	// suite's own upload placeholder to appear — 15s proved too tight
	// under GitHub Actions' variable CI load: two separate scheduled
	// runs each timed out here on a different, otherwise-passing
	// module (oid4vp-1final-verifier-happy-flow, -request-uri-fetched-
	// twice, -request-uri-method-post, -invalid-session-transcript —
	// no single module consistently, the signature of a too-tight
	// timeout racing variable CI load rather than a real functional
	// bug). 30s matches restartTimeout's own existing headroom.
	uploadTimeout = 30 * time.Second
)

// Config mirrors cmd/conformance-verifier's own Config — duplicated
// here (not imported: that package is main, unimportable) rather than
// promoted to a shared root/internal type, the same "small type,
// duplicated across a boundary Go can't otherwise cross" choice this
// repo already makes elsewhere (e.g.
// cmd/conformance-issuer/wiring.go's own copy of issuer-side wire
// shapes). CredentialFormat/Doctype/Namespace/MdocClaims are zero
// values for a caller building an "sd_jwt_vc" config (the default);
// VCT/Claims are zero values for a caller building an "mso_mdoc" one.
type Config struct {
	ListenAddr           string          `json:"listen_addr"`
	BaseURL              string          `json:"base_url"`
	TLSCertificatePEM    string          `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM     string          `json:"tls_private_key_pem"`
	ClientCertificatePEM string          `json:"client_certificate_pem"`
	ClientPrivateKeyPEM  string          `json:"client_private_key_pem"`
	CredentialIssuerJWK  json.RawMessage `json:"credential_issuer_jwk"`
	CredentialFormat     string          `json:"credential_format,omitempty"`
	VCT                  string          `json:"vct,omitempty"`
	Claims               []string        `json:"claims,omitempty"`
	Doctype              string          `json:"doctype,omitempty"`
	Namespace            string          `json:"namespace,omitempty"`
	MdocClaims           []string        `json:"mdoc_claims,omitempty"`
	MdocTrustAnchorPEM   string          `json:"mdoc_trust_anchor_pem,omitempty"`
}

// KeyMaterial is everything GenerateKeyMaterial produces: a caller
// fills in Config's own remaining role-specific fields (CredentialFormat
// etc.) before writing it out.
type KeyMaterial struct {
	Config                     Config
	ClientCACertPEM            string
	CredentialIssuerPrivateJWK jwk.SetEntry
}

// GenerateKeyMaterial builds a fresh throwaway TLS listener cert, OID4VP
// Client Identifier leaf+CA cert pair, and Credential Issuer signing
// key — everything either script needs, mirroring
// conformance/verifier/scripts/generate-config's own approach.
// clientCN/clientCACN name the leaf/CA certs (each script uses its own,
// so a stray container restart never trusts a mismatched cert).
func GenerateKeyMaterial(clientCN, clientCACN, internalBaseURL string) (KeyMaterial, error) {
	_, keyPEM, certPEM, caCertPEM, err := conformancecert.GenerateSignerAndCert(clientCN, clientCACN)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate client key/certificate: %w", err)
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-verifier", []string{"conformance-verifier", "localhost"})
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate tls cert: %w", err)
	}

	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate credential issuer key: %w", err)
	}
	issuerJWK, err := jwk.Marshal(&issuerKey.PublicKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("marshal credential issuer jwk: %w", err)
	}
	issuerJWKRaw, err := json.Marshal(issuerJWK)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("marshal credential issuer jwk: %w", err)
	}
	issuerPrivateJWKMaterial, err := jwk.MarshalPrivate(issuerKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("encode credential issuer private key: %w", err)
	}
	issuerPrivateJWK := jwk.SetEntry{JWK: issuerPrivateJWKMaterial, Alg: "ES256"}

	return KeyMaterial{
		Config: Config{
			ListenAddr:           ":8443",
			BaseURL:              internalBaseURL,
			TLSCertificatePEM:    tlsCertPEM,
			TLSPrivateKeyPEM:     tlsKeyPEM,
			ClientCertificatePEM: certPEM,
			ClientPrivateKeyPEM:  keyPEM,
			CredentialIssuerJWK:  issuerJWKRaw,
		},
		ClientCACertPEM:            caCertPEM,
		CredentialIssuerPrivateJWK: issuerPrivateJWK,
	}, nil
}

// WriteConfig marshals cfg to ConfigOutPath.
func WriteConfig(cfg Config) error {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal verifier config: %w", err)
	}
	// 0o644, not 0o600: this file is bind-mounted read-only into
	// conformance-verifier's own container, which (like every
	// cmd/conformance-* image) runs as gcr.io/distroless/static-
	// debian12:nonroot's own fixed uid (65532) — a different uid than
	// whatever process writes this file on the host, so 0o600 leaves
	// the container itself unable to read its own config. Confirmed
	// live in CI: "load config: read config: open /config.json:
	// permission denied", the container's own logs captured via the
	// new dumpContainerLogs below. Every key/cert here is throwaway,
	// freshly generated per run (see GenerateKeyMaterial) — never real
	// production secrets — so a host-world-readable file is an
	// acceptable trade for a working readiness check.
	if err := os.WriteFile(ConfigOutPath, raw, 0o644); err != nil { //nolint:gosec // G306: intentionally looser than 0600 — see the comment above; a throwaway CI config a differently-uid'd container must read
		return fmt.Errorf("write %s: %w", ConfigOutPath, err)
	}
	return nil
}

// RestartContainer rebuilds and restarts the conformance-verifier
// container so it picks up a freshly-written ConfigOutPath.
func RestartContainer() error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find docker: %w", err)
	}
	cmd := exec.Command(dockerPath, "compose", "-f", DockerComposeFile, "up", "-d", "--build", "--force-recreate") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// WaitReady polls verifierBase's own /result/<probe> route (any
// response at all, not a connection error, proves the TLS listener is
// up) through the host-published port. On a timeout it dumps the
// container's own logs to stderr before returning — a connection
// refused/timeout here means the container itself never bound its
// port, and without its own stdout/stderr nothing in run-all.sh's own
// output says why (confirmed missing: a real CI run's own captured
// logs showed only the polling timeout, nothing from the container
// itself, on a failure that turned out to be reproducible on every run).
func WaitReady(httpClient *http.Client, verifierBase string) error {
	deadline := time.Now().Add(restartTimeout)
	for {
		resp, err := httpClient.Get(verifierBase + "/result/readiness-probe")
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			dumpContainerLogs(DockerComposeFile)
			return fmt.Errorf("did not become ready within %s: %w", restartTimeout, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// dumpContainerLogs prints composeFile's own containers' logs to
// stderr — best-effort, since a caller already has a real error to
// report regardless of whether this succeeds.
func dumpContainerLogs(composeFile string) {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return
	}
	cmd := exec.Command(dockerPath, "compose", "-f", composeFile, "logs", "--no-color", "--tail=200") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	out, runErr := cmd.CombinedOutput()
	log.Printf("container logs (%s):\n%s", composeFile, out)
	if runErr != nil {
		log.Printf("docker compose logs: %v", runErr)
	}
}

// PlanConfig is the suite's own oid4vp-1final-verifier-haip-test-plan
// test-configuration body — confirmed against a real historical plan
// document (GET /api/plan/{id}), not guessed.
type PlanConfig struct {
	Alias       string           `json:"alias"`
	Description string           `json:"description"`
	Client      PlanConfigClient `json:"client"`
	Credential  PlanConfigCred   `json:"credential"`
}

type PlanConfigClient struct {
	RequestObjectTrustAnchorPEM string `json:"request_object_trust_anchor_pem"`
}

type PlanConfigCred struct {
	SigningJWK jwk.SetEntry `json:"signing_jwk"`
}

// placeholderPNGDataURI is
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go's own
// proven-working value.
const placeholderPNGDataURI = "data:image/png;base64," +
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA" +
	"AAYAAjCB0C8AAAAASUVORK5CYII="

// DriveModule creates one module instance within planID for testName
// and drives it exactly the way
// conformance/verifier/README.md's own "Interaction model, confirmed
// live" section documents: GET this binary's own /authorize to mint a
// session and get its "openid4vp://" deep link, then GET that same
// query string against the suite's own authorization_endpoint. Every
// module in this plan needs the same upload-placeholder fill —
// cmd/conformance-verifier's own POST /response always replies 200
// regardless of verification outcome (handlers.go's own
// handleResponse never returns a 4xx, for either a wallet-side parse
// error or a VerifyResponse rejection), so every module always takes
// the suite's own "success response, defer grading to a screenshot of
// the /result page" branch — confirmed by reading handleResponse
// directly, not assumed from any one module's own testSummary text.
// Filled here the same proven way
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go fills one
// for a different role's own modules.
func DriveModule(httpClient *http.Client, apiBase, verifierBase, planID, testName string, moduleVariant map[string]string) (status, result string, err error) {
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, moduleVariant)
	if err != nil {
		return "", "", fmt.Errorf("create module instance: %w", err)
	}

	noRedirect := &http.Client{
		Transport:     httpClient.Transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	authorizeResp, err := noRedirect.Get(verifierBase + "/authorize")
	if err != nil {
		return "", "", fmt.Errorf("GET %s/authorize: %w", verifierBase, err)
	}
	deepLink := authorizeResp.Header.Get("Location")
	_ = authorizeResp.Body.Close()
	if deepLink == "" {
		return "", "", fmt.Errorf("GET %s/authorize returned no Location header (status %d)", verifierBase, authorizeResp.StatusCode)
	}
	query, ok := strings.CutPrefix(deepLink, "openid4vp://")
	if !ok {
		return "", "", fmt.Errorf("GET %s/authorize Location %q does not start with openid4vp://", verifierBase, deepLink)
	}

	// noRedirect again: the suite's own final response, once its
	// internal wallet flow completes, redirects to a "result" URL
	// built from conformance-verifier's own suite-network-internal
	// hostname — unreachable from this host process, and irrelevant:
	// the module's grading already happened server-side by the time
	// any such redirect is issued.
	driveURL := module.URL + "/authorize" + query
	driveResp, err := noRedirect.Get(driveURL)
	if err != nil {
		return "", "", fmt.Errorf("GET %s: %w", driveURL, err)
	}
	_ = driveResp.Body.Close()

	if err := fillUploadPlaceholder(httpClient, apiBase, module.ID); err != nil {
		return "", "", fmt.Errorf("fill upload placeholder: %w", err)
	}

	return conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, restartTimeout)
}

// ModuleResult is one DriveModule call's own outcome, keyed by its own
// testName — both run-sdjwt-modules and run-mdoc-module accumulate a
// slice of these to print as a summary once every module has run.
type ModuleResult struct {
	TestName string
	Status   string
	Result   string
	Err      error
}

// DriveModules calls DriveModule for every testNames entry in order
// against the same planID/moduleVariant, logging each one's own
// outcome as it completes — the driving loop run-sdjwt-modules and
// run-mdoc-module both used to duplicate near-verbatim (confirmed live
// by SonarCloud's own duplication gate on the PR that added
// run-mdoc-module's own multi-module driving loop, mirroring this
// package's own doc comment about why it exists at all).
func DriveModules(httpClient *http.Client, apiBase, verifierBase, planID string, testNames []string, moduleVariant map[string]string) []ModuleResult {
	results := make([]ModuleResult, 0, len(testNames))
	for _, testName := range testNames {
		status, result, err := DriveModule(httpClient, apiBase, verifierBase, planID, testName, moduleVariant)
		res := ModuleResult{TestName: testName, Status: status, Result: result, Err: err}
		results = append(results, res)
		if err != nil {
			log.Printf("%s: ERROR: %v", testName, err)
		} else {
			log.Printf("%s: %s=%s", testName, status, result)
		}
	}
	return results
}

// PrintSummaryAndExit prints results as a "=== summary ===" block and
// calls os.Exit(1) if any result is unexpected — REVIEW is this plan's
// own legitimate terminal grade for every module here, not a failure:
// each one only reaches FINISHED at all because DriveModule's own
// upload-placeholder fill satisfied its own screenshot-evidence
// requirement — see DriveModule's own doc comment for why
// cmd/conformance-verifier's design means every module takes that
// branch, not just the positive-behavior ones.
func PrintSummaryAndExit(results []ModuleResult, apiBase, planID string) {
	log.Print("=== summary ===")
	allExpected := true
	for _, res := range results {
		if res.Err != nil || (res.Result != "PASSED" && res.Result != "REVIEW") {
			allExpected = false
		}
		log.Printf("%-55s %s=%s %v", res.TestName, res.Status, res.Result, res.Err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)
		os.Exit(1)
	}
}

func fillUploadPlaceholder(httpClient *http.Client, apiBase, moduleID string) error {
	deadline := time.Now().Add(uploadTimeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.Upload != "" {
					return postPlaceholder(httpClient, apiBase, moduleID, e.Upload)
				}
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no upload placeholder appeared within %s", uploadTimeout)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func postPlaceholder(httpClient *http.Client, apiBase, moduleID, placeholder string) error {
	url := fmt.Sprintf("%sapi/log/%s/images/%s", apiBase, moduleID, placeholder)
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(placeholderPNGDataURI))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	res, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	return nil
}

// Flags is the flag set both verifier conformance scripts define
// identically — only -alias's own default differs between them.
type Flags struct {
	APIBase              *string
	VerifierBase         *string
	VerifierInternalBase *string
	Alias                *string
	SkipDockerRestart    *bool
}

// DefineFlags registers Flags, defaulting -alias to defaultAlias. Call
// once, before flag.Parse().
func DefineFlags(defaultAlias string) Flags {
	return Flags{
		APIBase:              flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL"),
		VerifierBase:         flag.String("verifier-base", "https://localhost:19446", "cmd/conformance-verifier's own host-published base URL"),
		VerifierInternalBase: flag.String("verifier-internal-base", "https://conformance-verifier:8443", "cmd/conformance-verifier's own suite-network-internal base URL"),
		Alias:                flag.String("alias", defaultAlias, "suite plan alias"),
		SkipDockerRestart:    flag.Bool("skip-docker-restart", false, "skip restarting the conformance-verifier container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)"),
	}
}

// SetupParams is Setup's own input — everything a caller needs to
// supply beyond the shared Flags: the throwaway cert CNs (each script
// uses its own, so a stray container restart never trusts a
// mismatched cert), the plan's own description string, the plan-level
// credential_format variant value ("sd_jwt_vc" or "iso_mdl" — distinct
// from Config.CredentialFormat, which is empty for the sd_jwt_vc case
// since that's cmd/conformance-verifier's own default), and Configure,
// which sets whichever role-specific Config fields
// (CredentialFormat/Doctype/... or VCT/Claims) the caller needs before
// the config is written.
type SetupParams struct {
	Flags                Flags
	ClientCN, ClientCACN string
	PlanDescription      string
	PlanCredentialFormat string
	Configure            func(*Config)
}

// SetupResult is Setup's own output: the HTTP client and plan id every
// caller needs to go on and call DriveModule with.
type SetupResult struct {
	HTTPClient *http.Client
	PlanID     string
}

// Setup runs every step both scripts need before they can start
// driving modules: generate key material, apply the caller's own
// Configure callback, write/restart cmd/conformance-verifier's own
// config, build the suite's own plan config, and create the plan.
func Setup(params SetupParams) (SetupResult, error) {
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local conformance suite, self-signed certs throughout

	km, err := GenerateKeyMaterial(params.ClientCN, params.ClientCACN, *params.Flags.VerifierInternalBase)
	if err != nil {
		return SetupResult{}, fmt.Errorf("generate key material: %w", err)
	}
	if params.Configure != nil {
		params.Configure(&km.Config)
	}
	if km.Config.CredentialFormat == "mso_mdoc" {
		mdocTrustAnchorPEM, fetchErr := fetchMdocIACARootPEM(httpClient, *params.Flags.APIBase)
		if fetchErr != nil {
			return SetupResult{}, fmt.Errorf("fetch mdoc iaca root: %w", fetchErr)
		}
		km.Config.MdocTrustAnchorPEM = mdocTrustAnchorPEM
	}
	if err := WriteConfig(km.Config); err != nil {
		return SetupResult{}, fmt.Errorf("write config: %w", err)
	}
	log.Printf("wrote %s (credential_format=%s)", ConfigOutPath, params.PlanCredentialFormat)

	if !*params.Flags.SkipDockerRestart {
		if err := RestartContainer(); err != nil {
			return SetupResult{}, fmt.Errorf("restart conformance-verifier container: %w", err)
		}
		log.Print("restarted conformance-verifier container, waiting for it to come up")
		if err := WaitReady(httpClient, *params.Flags.VerifierBase); err != nil {
			return SetupResult{}, fmt.Errorf("wait for conformance-verifier: %w", err)
		}
	}

	pc := PlanConfig{
		Alias:       *params.Flags.Alias,
		Description: params.PlanDescription,
		Client:      PlanConfigClient{RequestObjectTrustAnchorPEM: km.ClientCACertPEM},
		Credential:  PlanConfigCred{SigningJWK: km.CredentialIssuerPrivateJWK},
	}
	pcRaw, err := json.Marshal(pc)
	if err != nil {
		return SetupResult{}, fmt.Errorf("marshal plan config: %w", err)
	}

	planVariant := map[string]string{"credential_format": params.PlanCredentialFormat, "response_mode": "direct_post.jwt"} //nolint:gosec // false positive: a suite variant selector value, not a credential
	planID, _, err := conformancesuite.CreatePlan(httpClient, *params.Flags.APIBase, PlanName, planVariant, pcRaw)
	if err != nil {
		return SetupResult{}, fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s)", planID, *params.Flags.Alias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *params.Flags.APIBase, planID)

	return SetupResult{HTTPClient: httpClient, PlanID: planID}, nil
}

// fetchMdocIACARootPEM fetches the suite's own well-known mdoc IACA
// root certificate — GET {apiBase}mdoc-iaca-root.pem, confirmed live
// (decoding a real "mso_mdoc" DeviceResponse's own IssuerAuth x5chain)
// to be a fixed, suite-wide constant ("certification.openid.net"),
// never a per-run/per-candidate value — served specifically so
// implementations under test can configure it as a trust anchor (see
// the suite's own MdocIacaRootEndpoint.java doc comment: "Implementations
// under test should configure this certificate as a trust anchor").
// Every mso_mdoc credential the suite emulates, whether playing Wallet
// (this role, Verifier tests) or Issuer (the Wallet role's own tests),
// signs under a Document Signer chaining to this one root.
func fetchMdocIACARootPEM(httpClient *http.Client, apiBase string) (string, error) {
	resp, err := httpClient.Get(apiBase + "mdoc-iaca-root.pem") //nolint:gosec,noctx // apiBase is the operator's own -suite flag value, not attacker-controlled
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %smdoc-iaca-root.pem: status %d: %s", apiBase, resp.StatusCode, body)
	}
	return string(body), nil
}

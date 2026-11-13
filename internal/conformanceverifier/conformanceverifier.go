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
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path"
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

// verifierService is conformance-verifier's docker compose service, and
// its hostname on the suite's network.
const verifierService = "conformance-verifier"

const (
	restartTimeout = 30 * time.Second
	// uploadTimeout bounds fillUploadPlaceholder's own poll for the
	// suite's own upload placeholder to appear. 15s, then 30s, both
	// proved too tight under GitHub Actions' own CI runners — a full
	// local run of conformance/scripts/run-all.sh (every Issuer/
	// Wallet/Verifier/Wallet-VP phase, fresh suite, the exact same
	// sequence and cumulative load CI runs) completed every module in
	// this poll well under 5s every time, ruling out a real functional
	// bug or a general "long sequential run degrades the suite"
	// pattern — CI's own shared runners are simply slower/more
	// resource-constrained than typical local hardware for this
	// specific interaction. 60s keeps this a fast, meaningful failure
	// signal if something genuinely breaks while giving CI's own
	// slower environment real headroom.
	uploadTimeout = 60 * time.Second
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
	CredentialIssuerJWK  json.RawMessage `json:"credential_issuer_jwk,omitempty"`
	CredentialFormat     string          `json:"credential_format,omitempty"`
	VCT                  string          `json:"vct,omitempty"`
	Claims               []string        `json:"claims,omitempty"`
	Doctype              string          `json:"doctype,omitempty"`
	Namespace            string          `json:"namespace,omitempty"`
	MdocClaims           []string        `json:"mdoc_claims,omitempty"`
	MdocTrustAnchorPEM   string          `json:"mdoc_trust_anchor_pem,omitempty"`
	// RejectUnverifiedResponses is always set here: see
	// cmd/conformance-verifier's Config, and DriveModule.
	RejectUnverifiedResponses bool `json:"reject_unverified_responses"`

	// The credential and status list trust Setup configures: see
	// cmd/conformance-verifier's Config.
	CredentialIssuerTrustAnchorsPEM   string `json:"credential_issuer_trust_anchors_pem,omitempty"`
	StatusListTrustAnchorsPEM         string `json:"status_list_trust_anchors_pem,omitempty"`
	StatusReferenceOptional           bool   `json:"status_reference_optional,omitempty"`
	StatusListTLSPinnedCertificatePEM string `json:"status_list_tls_pinned_certificate_pem,omitempty"`
	StatusListAllowPrivate            bool   `json:"status_list_allow_private,omitempty"`

	// Engine and Production select cmd/conformance-verifier's
	// transactions engine under its production setup (-transactions).
	Engine     string            `json:"engine,omitempty"`
	Production *ProductionConfig `json:"production,omitempty"`
}

// ProductionConfig mirrors cmd/conformance-verifier's own.
type ProductionConfig struct {
	DatabasePath string `json:"database_path"`
	SealingKey   string `json:"sealing_key"`
}

// EngineTransactions is cmd/conformance-verifier's Config.Engine for
// verifier.Transactions.
const EngineTransactions = "transactions"

// productionDatabasePath is the production store's SQLite file, in the
// container's /tmp: a fresh one each time the container is recreated.
const productionDatabasePath = "/tmp/conformance-verifier.sqlite"

// productionBuildTags builds cmd/conformance-verifier with its
// production store (the Dockerfile's GO_BUILD_TAGS).
const productionBuildTags = "conformance_production"

// newProductionConfig is a production setup with a fresh sealing key.
func newProductionConfig() (*ProductionConfig, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &ProductionConfig{DatabasePath: productionDatabasePath, SealingKey: base64.StdEncoding.EncodeToString(key)}, nil
}

// KeyMaterial is everything GenerateKeyMaterial produces: a caller
// fills in Config's own remaining role-specific fields (CredentialFormat
// etc.) before writing it out. CredentialIssuerCACertPEM issued the
// certificate CredentialIssuerPrivateJWK's x5c carries.
type KeyMaterial struct {
	Config                     Config
	ClientCACertPEM            string
	CredentialIssuerPrivateJWK jwk.SetEntry
	CredentialIssuerCACertPEM  string
}

// GenerateKeyMaterial builds a fresh throwaway TLS listener cert, OID4VP
// Client Identifier leaf+CA cert pair, and Credential Issuer signing
// key with a leaf certificate under a CA of its own — everything either
// script needs. The suite signs its "dc+sd-jwt" credentials and their
// Status List Tokens with that key, carrying the certificate as x5c
// (VP1FinalGenerateJwtStatusListToken in the suite's source), so the
// Verifier trusts both by the CA. clientCN/clientCACN name the leaf/CA
// certs (each script uses its own, so a stray container restart never
// trusts a mismatched cert).
func GenerateKeyMaterial(clientCN, clientCACN, internalBaseURL string) (KeyMaterial, error) {
	_, keyPEM, certPEM, caCertPEM, err := conformancecert.GenerateSignerAndCert(clientCN, clientCACN)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate client key/certificate: %w", err)
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM(verifierService, []string{verifierService, "localhost"})
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate tls cert: %w", err)
	}

	issuerKey, _, issuerCertPEM, issuerCACertPEM, err := conformancecert.GenerateSignerAndCert(clientCN+"-credential-issuer", clientCACN+"-credential-issuer")
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("generate credential issuer key/certificate: %w", err)
	}
	issuerCert, err := conformancecert.ParseCertificatePEM(issuerCertPEM)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("parse credential issuer certificate: %w", err)
	}
	issuerPrivateJWKMaterial, err := jwk.MarshalPrivate(issuerKey)
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("encode credential issuer private key: %w", err)
	}
	issuerPrivateJWK := jwk.SetEntry{JWK: issuerPrivateJWKMaterial, Alg: "ES256", X5C: []string{base64.StdEncoding.EncodeToString(issuerCert.Raw)}}

	return KeyMaterial{
		Config: Config{
			ListenAddr:           ":8443",
			BaseURL:              internalBaseURL,
			TLSCertificatePEM:    tlsCertPEM,
			TLSPrivateKeyPEM:     tlsKeyPEM,
			ClientCertificatePEM: certPEM,
			ClientPrivateKeyPEM:  keyPEM,

			RejectUnverifiedResponses: true,
		},
		ClientCACertPEM:            caCertPEM,
		CredentialIssuerPrivateJWK: issuerPrivateJWK,
		CredentialIssuerCACertPEM:  issuerCACertPEM,
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

// RestartContainer rebuilds the conformance-verifier image and
// restarts its container so it picks up a freshly-written
// ConfigOutPath, which it bind-mounts. Where the container already runs
// the image just built, as between one run's phases, it's restarted
// rather than recreated, keeping its address on the suite's network
// (docker compose up --build recreates the container even when the
// image is unchanged, so the choice is made here). The intermittent
// missing upload placeholders this was first meant to fix were the
// suite getting a module's first request before WAITING (DriveModule).
// buildTags is the Dockerfile's GO_BUILD_TAGS (docker-compose.yml takes
// it from CONFORMANCE_VERIFIER_GO_BUILD_TAGS): productionBuildTags for
// the transactions engine's production store, "" otherwise.
func RestartContainer(buildTags string) error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find docker: %w", err)
	}
	if err := os.Setenv("CONFORMANCE_VERIFIER_GO_BUILD_TAGS", buildTags); err != nil {
		return err
	}
	if err := runDocker(dockerPath, "compose", "-f", DockerComposeFile, "build"); err != nil {
		return err
	}
	if current, err := containerRunsBuiltImage(dockerPath); err != nil {
		return err
	} else if current {
		return runDocker(dockerPath, "compose", "-f", DockerComposeFile, "restart")
	}
	return runDocker(dockerPath, "compose", "-f", DockerComposeFile, "up", "-d")
}

// containerRunsBuiltImage reports whether the conformance-verifier
// container is running the image docker compose build last built.
func containerRunsBuiltImage(dockerPath string) (bool, error) {
	out, err := exec.Command(dockerPath, "compose", "-f", DockerComposeFile, "ps", "-q", verifierService).Output() //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	if err != nil {
		return false, fmt.Errorf("docker compose ps: %w", err)
	}
	container := strings.TrimSpace(string(out))
	if container == "" {
		return false, nil
	}
	out, err = exec.Command(dockerPath, "inspect", "-f", "{{.Image}}", container).Output() //nolint:gosec // dockerPath comes from exec.LookPath; container is docker's own ID
	if err != nil {
		return false, fmt.Errorf("docker inspect container: %w", err)
	}
	running := strings.TrimSpace(string(out))
	// The image docker compose names for the verifier project's service.
	out, err = exec.Command(dockerPath, "image", "inspect", "-f", "{{.Id}}", "verifier-conformance-verifier").Output() //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	if err != nil {
		return false, fmt.Errorf("docker image inspect: %w", err)
	}
	built := strings.TrimSpace(string(out))
	log.Printf("conformance-verifier container image %s, built image %s", running, built)
	return running == built, nil
}

func runDocker(dockerPath string, args ...string) error {
	cmd := exec.Command(dockerPath, args...) //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	return nil
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
// query string against the suite's own authorization_endpoint.
//
// cmd/conformance-verifier runs with reject_unverified_responses (see
// Config), so a presentation it verifies is answered 200 and the suite
// asks for a screenshot of the result page (filled here with a
// placeholder image, the same proven way
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go fills one,
// ending the module REVIEW), while one it refuses is answered 400 and
// the suite grades the module itself, without a screenshot. The
// result is then graded against the module's Expectation (Grade).
//
// The driver is the browser that asked: it keeps /authorize's cookies
// (the transactions engine's browser binding), and once the suite
// shows the Verifier's redirect_uri for it to visit, visits it, as the
// browser the Wallet sends back does — which redeems a same-device
// response_code under the transactions engine — before reading the
// result page with the same cookies.
func DriveModule(setup SetupResult, testName string, moduleVariant map[string]string) ModuleResult {
	httpClient, apiBase, verifierBase, planID := setup.HTTPClient, setup.APIBase, setup.VerifierBase, setup.PlanID
	expected, _ := expectationFor(testName)
	res := ModuleResult{TestName: testName, Expected: expected}
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, moduleVariant)
	if err != nil {
		res.Err = fmt.Errorf("create module instance: %w", err)
		return res
	}
	res.ModuleID = module.ID
	// The suite sets a module up asynchronously: a wallet request that
	// reaches it before WAITING can leave it stuck, and it then never
	// asks for its upload placeholder.
	if err := conformancesuite.WaitUntilWaiting(httpClient, apiBase, module.ID, restartTimeout); err != nil {
		res.Err = err
		return res
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		res.Err = err
		return res
	}
	// browser carries the cookies /authorize sets, the same jar for
	// every request a browser would make to the Verifier.
	noRedirect := &http.Client{
		Transport:     httpClient.Transport,
		Jar:           jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}
	authorizeResp, err := noRedirect.Get(verifierBase + "/authorize")
	if err != nil {
		res.Err = fmt.Errorf("GET %s/authorize: %w", verifierBase, err)
		return res
	}
	deepLink := authorizeResp.Header.Get("Location")
	_ = authorizeResp.Body.Close()
	query, ok := strings.CutPrefix(deepLink, "openid4vp://")
	if !ok {
		res.Err = fmt.Errorf("GET %s/authorize Location %q (status %d) is no openid4vp:// link", verifierBase, deepLink, authorizeResp.StatusCode)
		return res
	}
	sessionID, err := sessionIDOf(query)
	if err != nil {
		res.Err = err
		return res
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
		res.Err = fmt.Errorf("GET %s: %w", driveURL, err)
		return res
	}
	_ = driveResp.Body.Close()

	if err := fillUploadPlaceholder(httpClient, apiBase, module.ID); err != nil {
		res.Err = fmt.Errorf("fill upload placeholder: %w", err)
		return res
	}
	// After the placeholder, which the suite creates only once it has
	// logged the redirect_uri of a response the Verifier answered 200.
	if err := visitRedirectURI(httpClient, noRedirect, setup, module.ID); err != nil {
		res.Err = err
		return res
	}
	res.Status, res.Result, err = conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, restartTimeout)
	if err != nil {
		res.Err = err
		return res
	}
	res.VerifierOutcome, res.VerifierRefusal, err = verifierOutcome(noRedirect, verifierBase, sessionID)
	if err != nil {
		res.Err = err
		return res
	}
	entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, module.ID)
	if err != nil {
		res.Err = fmt.Errorf("fetch module log: %w", err)
		return res
	}
	res.Err = Grade(res.Expected, refusals[testName], res.Status, res.Result, res.VerifierOutcome, res.VerifierRefusal, entries)
	return res
}

// visitRedirectURI visits, with browser, the redirect_uri the
// Verifier's response endpoint returned for moduleID, which the suite
// logs for the tester's browser to visit: the address the Verifier
// gave it on the suite's network, rewritten to setup.VerifierBase. A
// module whose response the Verifier refused logs none. Any other
// address is never visited.
func visitRedirectURI(httpClient, browser *http.Client, setup SetupResult, moduleID string) error {
	entries, err := conformancesuite.FetchModuleLog(httpClient, setup.APIBase, moduleID)
	if err != nil {
		return fmt.Errorf("fetch module log: %w", err)
	}
	for _, e := range entries {
		if e.RedirectURI == "" {
			continue
		}
		rest, ok := strings.CutPrefix(e.RedirectURI, setup.VerifierInternalBase+"/")
		if !ok {
			return fmt.Errorf("the suite logged a redirect_uri %q outside %s", e.RedirectURI, setup.VerifierInternalBase)
		}
		resp, err := browser.Get(setup.VerifierBase + "/" + rest)
		if err != nil {
			return fmt.Errorf("visit the redirect_uri: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("visit the redirect_uri: status %d", resp.StatusCode)
		}
		return nil
	}
	return nil
}

// sessionIDOf is the cmd/conformance-verifier session a deep link's
// query string starts: its request_uri's last path segment
// (/request/{id}).
func sessionIDOf(query string) (string, error) {
	values, err := url.ParseQuery(strings.TrimPrefix(query, "?"))
	if err != nil {
		return "", fmt.Errorf("parse deep link query %q: %w", query, err)
	}
	requestURI, err := url.Parse(values.Get("request_uri"))
	if err != nil || !strings.HasPrefix(requestURI.Path, "/request/") {
		return "", fmt.Errorf("deep link query %q carries no /request/{id} request_uri", query)
	}
	return path.Base(requestURI.Path), nil
}

// Verifier outcomes, as cmd/conformance-verifier's result page reports
// them.
const (
	outcomeVerified = "verified"
	outcomeFailed   = "failed"
	outcomePending  = "pending"
)

// verifierOutcome reads what cmd/conformance-verifier decided for
// sessionID from its result page (GET /result/{id}, the page the
// suite's screenshot stands for): the Verifier's own verdict, which
// the suite can't see when it answered 200, and, when it failed, the
// page's text saying why.
func verifierOutcome(httpClient *http.Client, verifierBase, sessionID string) (outcome, refusal string, err error) {
	resp, err := httpClient.Get(verifierBase + "/result/" + url.PathEscape(sessionID)) //nolint:gosec,noctx // verifierBase is the operator's own -verifier-base flag
	if err != nil {
		return "", "", fmt.Errorf("GET result page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read result page: %w", err)
	}
	page := string(body)
	switch {
	case resp.StatusCode != http.StatusOK:
		return "", "", fmt.Errorf("GET result page: status %d", resp.StatusCode)
	case strings.Contains(page, "<h1>Verification succeeded</h1>"):
		return outcomeVerified, "", nil
	case strings.Contains(page, "<h1>Verification failed</h1>"):
		return outcomeFailed, preText(page), nil
	case strings.Contains(page, "<h1>Pending</h1>"):
		return outcomePending, "", nil
	}
	return "", "", fmt.Errorf("result page reports no outcome: %.200s", page)
}

// preText is the text of page's <pre> elements, unescaped, one per
// line: where cmd/conformance-verifier's result page says why a
// presentation failed.
func preText(page string) string {
	var lines []string
	for {
		_, rest, ok := strings.Cut(page, "<pre>")
		if !ok {
			break
		}
		text, after, ok := strings.Cut(rest, "</pre>")
		if !ok {
			break
		}
		lines = append(lines, html.UnescapeString(text))
		page = after
	}
	return strings.Join(lines, "\n")
}

// ModuleResult is one DriveModule call's outcome: the suite's
// status/result, the Verifier's own (VerifierOutcome), the module's
// Expectation, and Err, set whenever any of them isn't as expected.
type ModuleResult struct {
	TestName        string
	ModuleID        string
	Expected        Expectation
	Status          string
	Result          string
	VerifierOutcome string
	// VerifierRefusal is the result page's text saying why the
	// Verifier refused the presentation, when it did.
	VerifierRefusal string
	Err             error
}

// DriveModules drives every module of the plan's own module list
// (setup.Modules, as CreatePlan returned it) that expectations names,
// in the plan's order and against moduleVariant, logging each outcome
// as it completes. A module the plan lists but expectations doesn't
// name fails the run (a new suite module is classified before it is
// trusted), unless notDriven gives the reason it isn't driven.
func DriveModules(setup SetupResult, moduleVariant map[string]string) []ModuleResult {
	planModules := setup.Modules
	results := make([]ModuleResult, 0, len(planModules))
	seen := make(map[string]bool, len(planModules))
	for _, m := range planModules {
		if seen[m.TestModule] {
			continue
		}
		seen[m.TestModule] = true
		if reason, skip := notDriven[m.TestModule]; skip {
			log.Printf("%s: not driven: %s", m.TestModule, reason)
			continue
		}
		var res ModuleResult
		if _, known := expectationFor(m.TestModule); known {
			res = DriveModule(setup, m.TestModule, moduleVariant)
		} else {
			res = ModuleResult{TestName: m.TestModule, Err: errors.New("the plan lists a module with no expectation: classify it in internal/conformanceverifier")}
		}
		results = append(results, res)
		log.Printf("%s: %s", res.TestName, res.line())
	}
	return results
}

func (res ModuleResult) line() string {
	verdict := fmt.Sprintf("%s=%s verifier=%s (want %s)", res.Status, res.Result, res.VerifierOutcome, res.Expected)
	if res.VerifierRefusal != "" {
		verdict += fmt.Sprintf(" refusal %q", res.VerifierRefusal)
	}
	if res.ModuleID != "" {
		verdict += " module " + res.ModuleID
	}
	if res.Err != nil {
		verdict += ": UNEXPECTED: " + res.Err.Error()
	}
	return verdict
}

// PrintSummaryAndExit prints results as a "=== summary ===" block and
// calls os.Exit(1) if any module's verdict isn't the one its
// Expectation names, or none was driven at all.
func PrintSummaryAndExit(results []ModuleResult, apiBase, planID string) {
	log.Print("=== summary ===")
	allExpected := len(results) > 0
	for _, res := range results {
		if res.Err != nil {
			allExpected = false
		}
		log.Printf("%-60s %s", res.TestName, res.line())
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)
		os.Exit(1)
	}
}

// fillUploadPlaceholder fills the screenshot placeholder the suite
// creates once the Verifier answered a presentation 200. A module the
// Verifier answered with an error creates none, and finishes instead.
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
		info, infoErr := conformancesuite.FetchModuleInfo(httpClient, apiBase, moduleID)
		if infoErr == nil && (info.Status == "FINISHED" || info.Status == "INTERRUPTED") {
			return nil
		}
		if time.Now().After(deadline) {
			status := "unknown"
			if infoErr == nil {
				status = info.Status + " (result " + info.Result + ")"
			}
			return fmt.Errorf("no upload placeholder appeared within %s; the module is %s, log %sapi/log/%s", uploadTimeout, status, apiBase, moduleID)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func postPlaceholder(httpClient *http.Client, apiBase, moduleID, placeholder string) error {
	target := fmt.Sprintf("%sapi/log/%s/images/%s", apiBase, moduleID, placeholder)
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(placeholderPNGDataURI))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	body, status, err := conformancesuite.Do(httpClient, req)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("POST %s: status %d: %.200s", target, status, body)
	}
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
	Transactions         *bool
}

// DefineFlags registers Flags, defaulting -alias to defaultAlias. Call
// once, before flag.Parse().
func DefineFlags(defaultAlias string) Flags {
	return Flags{
		APIBase:              flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL"),
		VerifierBase:         flag.String("verifier-base", hostBase("CONFORMANCE_VERIFIER_HOST_PORT", "19446"), "cmd/conformance-verifier's own host-published base URL: https://localhost:$CONFORMANCE_VERIFIER_HOST_PORT by default, the port conformance/verifier/docker-compose.yml publishes it on (19446 when unset)"),
		VerifierInternalBase: flag.String("verifier-internal-base", "https://conformance-verifier:8443", "cmd/conformance-verifier's own suite-network-internal base URL"),
		Alias:                flag.String("alias", defaultAlias, "suite plan alias"),
		SkipDockerRestart:    flag.Bool("skip-docker-restart", false, "skip restarting the conformance-verifier container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)"),
		Transactions:         flag.Bool("transactions", false, "run cmd/conformance-verifier's transactions engine (verifier.Transactions) under its production setup: production assurance over a sealed SQLite store, built with the conformance_production tag"),
	}
}

// hostBase is https://localhost on the port portEnv names, or on
// defaultPort when it's unset: where a harness's docker-compose.yml
// publishes its container on the host.
func hostBase(portEnv, defaultPort string) string {
	port := os.Getenv(portEnv)
	if port == "" {
		port = defaultPort
	}
	return "https://localhost:" + port
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
// caller needs to go on and call DriveModules with, and the plan's own
// module list.
type SetupResult struct {
	HTTPClient *http.Client
	PlanID     string
	Modules    []conformancesuite.PlanModule

	// APIBase, VerifierBase and VerifierInternalBase are the flags':
	// the suite's base URL, and cmd/conformance-verifier's from this
	// host and on the suite's network.
	APIBase, VerifierBase, VerifierInternalBase string
	// Engine is cmd/conformance-verifier's Config.Engine.
	Engine string
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
	if err := configureTrust(httpClient, *params.Flags.APIBase, &km); err != nil {
		return SetupResult{}, err
	}
	buildTags := ""
	if *params.Flags.Transactions {
		km.Config.Engine = EngineTransactions
		if km.Config.Production, err = newProductionConfig(); err != nil {
			return SetupResult{}, fmt.Errorf("generate the production setup: %w", err)
		}
		buildTags = productionBuildTags
	}
	if err := WriteConfig(km.Config); err != nil {
		return SetupResult{}, fmt.Errorf("write config: %w", err)
	}
	log.Printf("wrote %s (credential_format=%s, engine=%q)", ConfigOutPath, params.PlanCredentialFormat, km.Config.Engine)

	if !*params.Flags.SkipDockerRestart {
		if err := RestartContainer(buildTags); err != nil {
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
	planID, modules, err := conformancesuite.CreatePlan(httpClient, *params.Flags.APIBase, PlanName, planVariant, pcRaw)
	if err != nil {
		return SetupResult{}, fmt.Errorf("create plan: %w", err)
	}
	log.Printf("created plan %s (alias %s)", planID, *params.Flags.Alias)
	log.Printf("plan detail: %splan-detail.html?plan=%s", *params.Flags.APIBase, planID)

	return SetupResult{
		HTTPClient: httpClient, PlanID: planID, Modules: modules,
		APIBase: *params.Flags.APIBase, VerifierBase: *params.Flags.VerifierBase, VerifierInternalBase: *params.Flags.VerifierInternalBase,
		Engine: km.Config.Engine,
	}, nil
}

// configureTrust sets the issuer and status list trust km.Config's
// format needs: the credential issuer's CA ("dc+sd-jwt"), or the
// suite's IACA root ("mso_mdoc"), trusted for the credential and its
// status and identifier lists alike. The lists are fetched from the
// suite's own address on the Docker network, a private one, over TLS
// pinned to the certificate the suite serves apiBase with: the same
// nginx serves both, with one self-signed certificate naming only
// "localhost", in its subject. A credential with no status reference is accepted, as
// present-credential-without-status requires.
func configureTrust(httpClient *http.Client, apiBase string, km *KeyMaterial) error {
	cfg := &km.Config
	if cfg.CredentialFormat == "mso_mdoc" {
		mdocTrustAnchorPEM, err := fetchMdocIACARootPEM(httpClient, apiBase)
		if err != nil {
			return fmt.Errorf("fetch mdoc iaca root: %w", err)
		}
		cfg.MdocTrustAnchorPEM = mdocTrustAnchorPEM
		cfg.StatusListTrustAnchorsPEM = mdocTrustAnchorPEM
	} else {
		cfg.CredentialIssuerTrustAnchorsPEM = km.CredentialIssuerCACertPEM
		cfg.StatusListTrustAnchorsPEM = km.CredentialIssuerCACertPEM
	}
	suiteCertPEM, err := fetchTLSCertificatePEM(httpClient, apiBase)
	if err != nil {
		return fmt.Errorf("fetch the suite's tls certificate: %w", err)
	}
	cfg.StatusListTLSPinnedCertificatePEM = suiteCertPEM
	cfg.StatusListAllowPrivate = true
	cfg.StatusReferenceOptional = true
	return nil
}

// fetchTLSCertificatePEM is the certificate the suite at apiBase
// presents, PEM-encoded, read over httpClient, which verifies none: it's
// pinned, not trusted by a chain.
func fetchTLSCertificatePEM(httpClient *http.Client, apiBase string) (string, error) {
	resp, err := httpClient.Get(apiBase + "api/server") //nolint:gosec,noctx // apiBase is the operator's own -suite flag value, not attacker-controlled
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("%s presented no TLS certificate", apiBase)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: resp.TLS.PeerCertificates[0].Raw})), nil
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

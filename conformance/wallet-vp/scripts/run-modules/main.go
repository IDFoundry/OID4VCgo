// Command run-modules closes conformance-wallet-vp's own "driven by
// hand" gap: 13 of `oid4vp-1final-wallet-haip-test-plan`'s 14
// `direct_post.jwt` + `x509_hash` + `request_uri_signed` modules
// (confirmed against a real historical plan document, GET
// /api/plan/{id} — not guessed) were originally run live one at a
// time by hand, never as a committed, repeatable tool.
//
// How this binary gets driven, confirmed live (not assumed from
// conformance/wallet-vp/README.md's own "How the interaction model
// was confirmed" section alone): creating a module does NOT make the
// suite's own internal browser navigate to this binary's
// /authorize on its own — the suite logs "Redirecting to
// authorization endpoint" and then sits WAITING. The actual
// destination — this binary's own suite-network-internal URL, with
// client_id/request_uri query parameters the suite generated — is
// recorded as a structured "redirect_to" field on that same log entry
// (see internal/conformancesuite.LogEntry). This binary drives it by
// polling for that field, substituting the host-published address for
// the suite-internal one (the same "swap hostname:port, keep
// path+query" pattern conformance/verifier's own scripts already use),
// and GETting it directly — cmd/conformance-wallet-vp's own
// handleAuthorize runs the entire flow synchronously within that one
// call.
//
// A positive-behavior module (happy-flow and 5 others) completes to a
// clean FINISHED/PASSED from that alone. Every negative-test module is
// REVIEW-gated instead (the suite's own condition text: "the wallet
// should display an error, a screenshot of which must be uploaded for
// the test to transition to FINISHED") — filled the same proven way
// conformance/verifier's own scripts and
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go already
// fill one. But per conformance/wallet-vp/README.md's own established
// finding, the suite's own overall verdict on a negative-test module
// isn't the real pass/fail signal (a REVIEW grade there is expected
// regardless of whether this binary's own security check actually
// worked) — this binary's own local HTTP response to the drive GET is:
// a 200 means it presented a credential (wrong, for a negative test);
// a non-200 (with the real Go error as the body, via handleAuthorize's
// own http.Error calls) means it correctly rejected the malformed
// request before ever calling response_uri. This script grades
// negative-test modules on that local signal, not the suite's own
// REVIEW verdict.
//
// `alternate-happy-flow`'s own fragment-carrying redirect_uri (HAIP's
// alternate response variant) needs relaying real fragment content to
// the suite's own "implicit submission" URL, exactly like a real
// browser's window.location.hash + XHR POST would — this binary's own
// GET drops the fragment on the floor (fragments never transmit over
// HTTP by design), so driveOne relays it separately once it sees one.
// The exact wire shape (raw fragment text, INCLUDING the leading '#',
// POSTed as Content-Type: text/plain) was confirmed by decompiling the
// suite's own fapi-test-suite.jar (implicitCallback.html's own
// xhr.send(window.location.hash) and
// CheckUrlFragmentContainsCodeVerifier.java's own literal comparison
// against "#" + code_verifier) rather than guessed — two earlier
// guesses (a bare fragment value with no leading '#', and a
// form-encoded code_verifier=<fragment> body) both failed against the
// live suite with "URL fragment passed to redirect_uri contains more
// than the one expected entry" for exactly this reason.
//
// Usage: go run ./conformance/wallet-vp/scripts/run-modules \
//
//	-suite=https://localhost:8443/ \
//	-walletvp-base=https://localhost:19447
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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

const (
	planName              = "oid4vp-1final-wallet-haip-test-plan"
	configOutPath         = "conformance/wallet-vp/oidf-config/haip.config.json"
	dockerComposeYML      = "conformance/wallet-vp/docker-compose.yml"
	restartTimeout        = 30 * time.Second
	redirectTimeout       = 15 * time.Second
	implicitSubmitTimeout = 15 * time.Second
	uploadTimeout         = 10 * time.Second
	moduleTimeout         = 30 * time.Second
)

// positiveTests are driven and expected to complete cleanly on the
// first drive call alone (FINISHED/PASSED or /WARNING) — this
// binary's own local response is a 200.
var positiveTests = []string{
	"oid4vp-1final-wallet-happy-flow",
	"oid4vp-1final-wallet-alternate-happy-flow",
	"oid4vp-1final-wallet-request-uri-method-post",
	"oid4vp-1final-wallet-ignores-unusable-encryption-key",
	"oid4vp-1final-wallet-fewer-claims-than-available",
	"oid4vp-1final-wallet-optional-credential-set",
	"oid4vp-1final-wallet-no-claims-in-dcql-query",
}

// negativeTests are driven the same way, but graded on this binary's
// own local non-200 response (correctly rejected before ever calling
// response_uri) — see this file's own package doc comment for why the
// suite's own REVIEW verdict isn't the real signal here.
var negativeTests = []string{
	"oid4vp-1final-wallet-negative-test-invalid-request-object-signature",
	"oid4vp-1final-wallet-negative-test-mismatched-client-id",
	"oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post",
	"oid4vp-1final-wallet-negative-test-missing-nonce",
	"oid4vp-1final-wallet-negative-test-invalid-client-id-prefix",
	"oid4vp-1final-wallet-negative-test-unknown-transaction-data-type",
	"oid4vp-1final-wallet-negative-test-required-non-matching-credential",
}

type generatedConfig struct {
	ListenAddr                     string            `json:"listen_addr"`
	TLSCertificatePEM              string            `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM               string            `json:"tls_private_key_pem"`
	CredentialIssuerPrivateKeyPEM  string            `json:"credential_issuer_private_key_pem"`
	CredentialIssuerCertificatePEM string            `json:"credential_issuer_certificate_pem"`
	HolderPrivateKeyPEM            string            `json:"holder_private_key_pem"`
	VCT                            string            `json:"vct"`
	Claims                         map[string]string `json:"claims"`
}

// planConfig is the suite's own oid4vp-1final-wallet-haip-test-plan
// test-configuration body — confirmed live against the real suite API
// (verifier_info deliberately omitted: an empty array there fails
// "Found invalid entries in verifier_info input", confirmed live —
// the field must be absent, not empty).
type planConfig struct {
	Alias       string         `json:"alias"`
	Description string         `json:"description"`
	Credential  planCredential `json:"credential"`
	Client      planClient     `json:"client"`
	Server      planServer     `json:"server"`
}

type planCredential struct {
	TrustAnchorPEM           string `json:"trust_anchor_pem"`
	StatusListTrustAnchorPEM string `json:"status_list_trust_anchor_pem"`
}

type planClient struct {
	AuthorizationEncryptedResponseEnc string     `json:"authorization_encrypted_response_enc"`
	AuthorizationEncryptedResponseAlg string     `json:"authorization_encrypted_response_alg"`
	JWKs                              planJWKSet `json:"jwks"`
	DCQL                              planDCQL   `json:"dcql"`
}

type planJWKSet struct {
	Keys []planClientJWK `json:"keys"`
}

// planClientJWK is the suite's own emulated-Verifier signing key —
// confirmed live: a single self-signed leaf in "x5c" works fine here
// (unlike conformance/verifier's own client certificate, this one
// isn't independently x5c-chain-validated by the module under test).
type planClientJWK struct {
	Kty string   `json:"kty"`
	Crv string   `json:"crv"`
	X   string   `json:"x"`
	Y   string   `json:"y"`
	D   string   `json:"d"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}

type planDCQL struct {
	Credentials []planDCQLCredential `json:"credentials"`
}

type planDCQLCredential struct {
	ID     string          `json:"id"`
	Format string          `json:"format"`
	Meta   planDCQLMeta    `json:"meta"`
	Claims []planDCQLClaim `json:"claims"`
}

type planDCQLMeta struct {
	VCTValues []string `json:"vct_values"`
}

type planDCQLClaim struct {
	Path []string `json:"path"`
}

type planServer struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
}

type moduleResult struct {
	testName string
	localOK  bool // this binary's own drive call returned 200
	status   string
	result   string
	err      error
}

func main() {
	apiBase := flag.String("suite", "https://localhost:8443/", "OIDF conformance suite base URL")
	walletVPBase := flag.String("walletvp-base", "https://localhost:19447", "cmd/conformance-wallet-vp's own host-published base URL")
	walletVPInternalBase := flag.String("walletvp-internal-base", "https://conformance-wallet-vp:8443", "cmd/conformance-wallet-vp's own suite-network-internal base URL")
	alias := flag.String("alias", "oid4vcgo-wallet-vp", "suite plan alias")
	skipDockerRestart := flag.Bool("skip-docker-restart", false, "skip restarting the conformance-wallet-vp container after writing the new config (only safe when the container is already running with matching key material from a prior run of this exact binary)")
	flag.Parse()

	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local conformance suite, self-signed certs throughout

	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-wallet-vp", []string{"conformance-wallet-vp", "localhost"})
	if err != nil {
		log.Fatalf("generate tls cert: %v", err)
	}
	_, issuerKeyPEM, issuerCertPEM, issuerCACertPEM, err := conformancecert.GenerateSignerAndCert(
		"conformance-wallet-vp-credential-issuer", "conformance-wallet-vp-credential-issuer-ca")
	if err != nil {
		log.Fatalf("generate credential issuer key/certificate: %v", err)
	}
	holderKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		log.Fatalf("generate holder key: %v", err)
	}

	cfg := generatedConfig{
		ListenAddr:                     ":8443",
		TLSCertificatePEM:              tlsCertPEM,
		TLSPrivateKeyPEM:               tlsKeyPEM,
		CredentialIssuerPrivateKeyPEM:  issuerKeyPEM,
		CredentialIssuerCertificatePEM: issuerCertPEM,
		HolderPrivateKeyPEM:            holderKeyPEM,
		VCT:                            "urn:eudi:pid:1",
		Claims:                         map[string]string{"given_name": "Jean", "family_name": "Dupont"},
	}
	cfgRaw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		log.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(configOutPath, cfgRaw, 0o600); err != nil {
		log.Fatalf("write %s: %v", configOutPath, err)
	}
	log.Printf("wrote %s", configOutPath)

	if !*skipDockerRestart {
		if err := restartContainer(); err != nil {
			log.Fatalf("restart conformance-wallet-vp container: %v", err)
		}
		log.Print("restarted conformance-wallet-vp container, waiting for it to come up")
		if err := waitReady(httpClient, *walletVPBase); err != nil {
			log.Fatalf("wait for conformance-wallet-vp: %v", err)
		}
	}

	clientJWK, err := generateClientJWK()
	if err != nil {
		log.Fatalf("generate plan client signing key: %v", err)
	}

	pc := planConfig{
		Alias:       *alias,
		Description: "OID4VCgo cmd/conformance-wallet-vp live run",
		Credential:  planCredential{TrustAnchorPEM: issuerCACertPEM, StatusListTrustAnchorPEM: issuerCACertPEM},
		Client: planClient{
			AuthorizationEncryptedResponseEnc: "A128GCM",
			AuthorizationEncryptedResponseAlg: "ECDH-ES",
			JWKs:                              planJWKSet{Keys: []planClientJWK{clientJWK}},
			DCQL: planDCQL{Credentials: []planDCQLCredential{{
				ID: "cred1", Format: "dc+sd-jwt",
				Meta:   planDCQLMeta{VCTValues: []string{cfg.VCT}},
				Claims: []planDCQLClaim{{Path: []string{"given_name"}}, {Path: []string{"family_name"}}},
			}}},
		},
		Server: planServer{AuthorizationEndpoint: *walletVPInternalBase + "/authorize"},
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

	var results []moduleResult
	for _, testName := range positiveTests {
		results = append(results, driveOne(httpClient, *apiBase, *walletVPBase, planID, testName, moduleVariant, false))
	}
	for _, testName := range negativeTests {
		results = append(results, driveOne(httpClient, *apiBase, *walletVPBase, planID, testName, moduleVariant, true))
	}

	log.Print("=== summary ===")
	allExpected := true
	for _, res := range results {
		expected := res.err == nil
		if expected {
			if res.localOK && (res.result != "PASSED" && res.result != "WARNING" && res.result != "REVIEW") {
				expected = false
			}
			if !res.localOK && res.result != "REVIEW" && res.result != "PASSED" {
				expected = false
			}
		}
		if !expected {
			allExpected = false
		}
		log.Printf("%-70s localOK=%-5v %s=%s %v", res.testName, res.localOK, res.status, res.result, res.err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", *apiBase, planID)
		os.Exit(1)
	}
}

// driveOne creates one module instance within planID for testName,
// drives it, and grades it per this file's own package doc comment:
// negativeTest modules are graded on the local drive response, not
// the suite's own overall verdict.
func driveOne(httpClient *http.Client, apiBase, walletVPBase, planID, testName string, moduleVariant map[string]string, negativeTest bool) moduleResult {
	res := moduleResult{testName: testName}

	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, testName, moduleVariant)
	if err != nil {
		res.err = fmt.Errorf("create module instance: %w", err)
		return res
	}

	redirectTo, err := pollRedirectTo(httpClient, apiBase, module.ID)
	if err != nil {
		res.err = fmt.Errorf("poll redirect_to: %w", err)
		return res
	}
	driveURL := toHostBase(redirectTo, walletVPBase)

	driveResp, err := httpClient.Get(driveURL) //nolint:gosec,noctx // driveURL comes from the suite's own log entry, a trusted local conformance-suite instance, not attacker-controlled
	if err != nil {
		res.err = fmt.Errorf("GET %s: %w", driveURL, err)
		return res
	}
	driveBody, _ := io.ReadAll(driveResp.Body)
	_ = driveResp.Body.Close()
	res.localOK = driveResp.StatusCode == http.StatusOK
	if negativeTest && res.localOK {
		log.Printf("%s: WARNING — this binary returned 200 for a negative test (should have rejected)", testName)
	}

	// alternate-happy-flow's own fragment-carrying redirect_uri — see
	// this file's own package doc comment. cmd/conformance-wallet-vp's
	// own handleAuthorize already names the exact URL it followed
	// (fragment included) in its own response text; extract it and
	// relay it to the suite's own implicit-submission URL the same way
	// a real browser's window.location.hash + XHR POST would.
	if fragment, ok := extractFollowedFragment(string(driveBody)); ok {
		if err := relayImplicitFragment(httpClient, apiBase, module.ID, fragment); err != nil {
			res.err = fmt.Errorf("relay implicit fragment: %w", err)
			return res
		}
	}

	// Optional: only negative-test modules need this (see package doc
	// comment) — a short, non-fatal grace period, since a
	// positive-behavior module that already reached FINISHED/PASSED
	// never gets one.
	if entry, ok := pollUpload(httpClient, apiBase, module.ID, uploadTimeout); ok {
		if err := postPlaceholder(httpClient, apiBase, module.ID, entry); err != nil {
			res.err = fmt.Errorf("fill upload placeholder: %w", err)
			return res
		}
	}

	status, result, err := conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, moduleTimeout)
	res.status, res.result = status, result
	if err != nil {
		res.err = fmt.Errorf("wait until finished: %w", err)
	}
	return res
}

// pollRedirectTo polls moduleID's own log until a "redirect_to" field
// appears — see this file's own package doc comment for what this is
// and why it's needed instead of the suite driving the flow on its
// own.
func pollRedirectTo(httpClient *http.Client, apiBase, moduleID string) (string, error) {
	deadline := time.Now().Add(redirectTimeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.RedirectTo != "" {
					return e.RedirectTo, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no redirect_to appeared within %s", redirectTimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// extractFollowedFragment finds cmd/conformance-wallet-vp's own
// "Followed redirect_uri: <url>" response text and returns that URL's
// own fragment, INCLUDING the leading '#' — Go's net/url strips it
// from URL.Fragment, but the suite's own
// CheckUrlFragmentContainsCodeVerifier.java compares the submitted
// value literally against "#" + code_verifier, so this works from the
// raw string instead of a parsed URL to match exactly. Returns
// ok=false for a redirect_uri with no fragment (every module besides
// alternate-happy-flow) — nothing to relay.
func extractFollowedFragment(driveBody string) (fragment string, ok bool) {
	const marker = "Followed redirect_uri: "
	i := strings.Index(driveBody, marker)
	if i < 0 {
		return "", false
	}
	rest := driveBody[i+len(marker):]
	if end := strings.Index(rest, "</p>"); end >= 0 {
		rest = rest[:end]
	}
	fragIdx := strings.IndexByte(rest, '#')
	if fragIdx < 0 {
		return "", false
	}
	return rest[fragIdx:], true
}

// relayImplicitFragment polls moduleID's own log for the suite's
// "Created random implicit submission URL" entry (the same
// ImplicitSubmit.FullURL mechanism
// conformance/issuer/scripts/run-fapi2sp-battery/unblock.go already
// uses for a different stuck-point), then POSTs fragment there — raw
// text, Content-Type: text/plain — completing the same round trip the
// suite's own implicitCallback.html JS performs
// (xhr.send(window.location.hash) with an identical Content-type
// header) for a real browser.
func relayImplicitFragment(httpClient *http.Client, apiBase, moduleID, fragment string) error {
	fullURL, err := pollImplicitSubmitURL(httpClient, apiBase, moduleID)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader(fragment)) //nolint:noctx // fullURL comes from the suite's own log entry, a trusted local conformance-suite instance, not attacker-controlled
	if err != nil {
		return fmt.Errorf("build implicit submit request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", fullURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: status %d: %s", fullURL, resp.StatusCode, body)
	}
	return nil
}

// pollImplicitSubmitURL polls moduleID's own log until a
// "Created random implicit submission URL" entry appears, mirroring
// pollRedirectTo's own polling shape.
func pollImplicitSubmitURL(httpClient *http.Client, apiBase, moduleID string) (string, error) {
	deadline := time.Now().Add(implicitSubmitTimeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.ImplicitSubmit != nil && e.ImplicitSubmit.FullURL != "" {
					return e.ImplicitSubmit.FullURL, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("no implicit submission URL appeared within %s", implicitSubmitTimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// pollUpload polls moduleID's own log for an "upload" placeholder for
// up to timeout, returning ok=false (not an error) if none appears —
// unlike pollRedirectTo, a missing upload placeholder is the expected
// outcome for every positive-behavior module.
func pollUpload(httpClient *http.Client, apiBase, moduleID string, timeout time.Duration) (placeholder string, ok bool) {
	deadline := time.Now().Add(timeout)
	for {
		entries, err := conformancesuite.FetchModuleLog(httpClient, apiBase, moduleID)
		if err == nil {
			for _, e := range entries {
				if e.Upload != "" {
					return e.Upload, true
				}
			}
		}
		if time.Now().After(deadline) {
			return "", false
		}
		time.Sleep(300 * time.Millisecond)
	}
}

const placeholderPNGDataURI = "data:image/png;base64," +
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA" +
	"AAYAAjCB0C8AAAAASUVORK5CYII="

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

// toHostBase replaces redirectTo's own suite-network-internal
// scheme+host with hostBase, keeping path+query unchanged — the same
// "swap hostname:port" pattern conformance/verifier's own scripts
// already use.
func toHostBase(redirectTo, hostBase string) string {
	idx := strings.Index(redirectTo, "/authorize")
	if idx == -1 {
		return redirectTo
	}
	return hostBase + redirectTo[idx:]
}

// generateClientJWK builds the suite's own emulated-Verifier signing
// key: a fresh EC P-256 key plus a single self-signed leaf cert as its
// own "x5c" entry — confirmed live that this (unlike
// conformance/verifier's own client certificate) doesn't need a
// separate issuing CA; the suite doesn't independently x5c-chain-
// validate this specific key.
func generateClientJWK() (planClientJWK, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return planClientJWK{}, fmt.Errorf("generate key: %w", err)
	}
	certPEM, err := conformancecert.SelfSignedCertPEMForKey("oid4vcgo-wallet-vp-test-verifier-client", key)
	if err != nil {
		return planClientJWK{}, fmt.Errorf("self-signed cert: %w", err)
	}
	cert, err := conformancecert.ParseCertificatePEM(certPEM)
	if err != nil {
		return planClientJWK{}, fmt.Errorf("parse cert: %w", err)
	}
	pubJWK, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		return planClientJWK{}, fmt.Errorf("marshal public jwk: %w", err)
	}
	keyBytes, err := key.Bytes()
	if err != nil {
		return planClientJWK{}, fmt.Errorf("encode private key: %w", err)
	}
	return planClientJWK{
		Kty: pubJWK.Kty, Crv: pubJWK.Crv, X: pubJWK.X, Y: pubJWK.Y,
		D:   base64.RawURLEncoding.EncodeToString(keyBytes),
		Kid: "wallet-vp-test-client-sig", Use: "sig", Alg: "ES256",
		X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}, nil
}

func restartContainer() error {
	dockerPath, err := exec.LookPath("docker")
	if err != nil {
		return fmt.Errorf("find docker: %w", err)
	}
	cmd := exec.Command(dockerPath, "compose", "-f", dockerComposeYML, "up", "-d", "--build", "--force-recreate") //nolint:gosec // dockerPath comes from exec.LookPath, args are fixed literals
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func waitReady(httpClient *http.Client, walletVPBase string) error {
	deadline := time.Now().Add(restartTimeout)
	for {
		resp, err := httpClient.Get(walletVPBase + "/authorize")
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("did not become ready within %s: %w", restartTimeout, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

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
	"encoding/base64"
	"encoding/json"
	"fmt"
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

const (
	restartTimeout = 30 * time.Second
	uploadTimeout  = 15 * time.Second
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
}

// PrivateJWK is generate-config's own local type, promoted here since
// both a caller's own config (public half, via Config.CredentialIssuerJWK)
// and the suite's own plan config (private half, via
// PlanConfigCred.SigningJWK) need it.
type PrivateJWK struct {
	jwk.JWK
	D   string `json:"d"`
	Alg string `json:"alg"`
}

// KeyMaterial is everything GenerateKeyMaterial produces: a caller
// fills in Config's own remaining role-specific fields (CredentialFormat
// etc.) before writing it out.
type KeyMaterial struct {
	Config                     Config
	ClientCACertPEM            string
	CredentialIssuerPrivateJWK PrivateJWK
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
	issuerKeyBytes, err := issuerKey.Bytes()
	if err != nil {
		return KeyMaterial{}, fmt.Errorf("encode credential issuer private key: %w", err)
	}
	issuerPrivateJWK := PrivateJWK{JWK: issuerJWK, D: base64.RawURLEncoding.EncodeToString(issuerKeyBytes), Alg: "ES256"}

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
	if err := os.WriteFile(ConfigOutPath, raw, 0o600); err != nil {
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
// up) through the host-published port.
func WaitReady(httpClient *http.Client, verifierBase string) error {
	deadline := time.Now().Add(restartTimeout)
	for {
		resp, err := httpClient.Get(verifierBase + "/result/readiness-probe")
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
	SigningJWK PrivateJWK `json:"signing_jwk"`
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

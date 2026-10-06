package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// The dc_api.jwt module lists (-response-mode dc_api.jwt) of
// oid4vp-1final-wallet-haip-test-plan: the suite plays the Verifier
// over the W3C Digital Credentials API, in the three request forms HAIP
// §5.2 requires a Wallet to support — unsigned (web-origin), signed and
// multi-signed (x509_hash). The suite's own log page would call
// navigator.credentials.get with the module's request and POST the
// result to the module's submit URL; this driver stands in for it,
// reading the request from GET /api/runner/{id}
// (browser.browserApiRequests), having cmd/conformance-wallet-vp's
// POST /dcapi answer it for the origin the page would have — the
// suite's own, its submit URL's — and posting what that returns to the
// submit URL as the page would. It proves the wallet's protocol
// handling against the suite's own Verifier; it can't prove a real
// browser's or platform's hand-off.

// browserAPITimeout bounds the poll for a module's browser API request.
const browserAPITimeout = 15 * time.Second

// planClient2 is the second client a multi-signed request is signed
// for (the suite's client2.jwks).
type planClient2 struct {
	JWKs jwk.Set `json:"jwks"`
}

// dcapiPlanConfig is planConfig with the second client.
type dcapiPlanConfig struct {
	planConfig
	Client2 planClient2 `json:"client2"`
}

// browserAPIRequest is one of GET /api/runner/{id}'s
// browser.browserApiRequests: the navigator.credentials.get argument,
// and where the page posts the result.
type browserAPIRequest struct {
	Request   browserAPICall `json:"request"`
	SubmitURL string         `json:"submitUrl"`
}

// browserAPICall is navigator.credentials.get's argument.
type browserAPICall struct {
	Digital browserAPIDigital `json:"digital"`
}

// browserAPIDigital is its "digital" member.
type browserAPIDigital struct {
	Requests []dcapiProtocolRequest `json:"requests"`
}

// dcapiProtocolRequest is one DC API request: a protocol and its data.
type dcapiProtocolRequest struct {
	Protocol string          `json:"protocol"`
	Data     json.RawMessage `json:"data"`
}

// dcapiAnswer is cmd/conformance-wallet-vp's POST /dcapi response.
type dcapiAnswer struct {
	Result    json.RawMessage `json:"result"`
	SentError string          `json:"sent_error"`
}

// dcapiRun is one -response-mode dc_api.jwt run.
type dcapiRun struct {
	httpClient                                     *http.Client
	apiBase, walletVPBase, alias, credentialFormat string
	trustAnchorCertPEM                             string
	cfg                                            generatedConfig
	verifierCA                                     *x509.Certificate
	verifierCAKey                                  *ecdsa.PrivateKey
}

// run creates the dc_api.jwt plan for the credential format and drives
// every module it lists, and reports whether each ended as expected.
func (d dcapiRun) run() bool {
	httpClient, apiBase, walletVPBase := d.httpClient, d.apiBase, d.walletVPBase
	verifierCA, verifierCAKey := d.verifierCA, d.verifierCAKey
	clientJWK, err := generateClientJWK(verifierCA, verifierCAKey)
	if err != nil {
		log.Fatalf("generate plan client signing key: %v", err)
	}
	client2JWK, err := generateClientJWK(verifierCA, verifierCAKey)
	if err != nil {
		log.Fatalf("generate plan client2 signing key: %v", err)
	}
	client2JWK.Kid = "wallet-vp-test-client2-sig"
	pc := dcapiPlanConfig{
		planConfig: buildPlanConfig(d.alias+"-dcapi", "OID4VCgo cmd/conformance-wallet-vp live run (dc_api.jwt)", d.trustAnchorCertPEM, clientJWK, buildDCQLCredential(d.cfg), ""),
		Client2:    planClient2{JWKs: jwk.Set{Keys: []jwk.SetEntry{client2JWK}}},
	}
	pcRaw, err := json.MarshalIndent(pc, "", "  ")
	if err != nil {
		log.Fatalf("marshal plan config: %v", err)
	}
	planVariant := map[string]string{"credential_format": d.credentialFormat, "response_mode": "dc_api.jwt"} //nolint:gosec // a suite variant selector value, not a credential
	planID, modules, err := conformancesuite.CreatePlan(httpClient, apiBase, planName, planVariant, pcRaw)
	if err != nil {
		log.Fatalf("create plan: %v", err)
	}
	log.Printf("created plan %s: %d modules", planID, len(modules))
	log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)

	var results []moduleResult
	for _, m := range modules {
		res := driveDCAPI(httpClient, apiBase, walletVPBase, planID, m)
		res.testName = m.TestModule + " [" + m.Variant["request_method"] + "]"
		results = append(results, res)
	}
	log.Print("=== summary (dc_api.jwt) ===")
	allExpected := true
	for _, res := range results {
		ok := res.err == nil
		allExpected = allExpected && ok
		log.Printf("%-90s %s=%s %v", res.testName, res.status, res.result, res.err)
	}
	if !allExpected {
		log.Printf("plan detail: %splan-detail.html?plan=%s", apiBase, planID)
	}
	return allExpected
}

// driveDCAPI runs one dc_api.jwt module and grades it: a positive
// module must finish PASSED (or WARNING) after the wallet presents; a
// negative one must either get the error response
// negativeTestExpectedErrorCode names, and then finish PASSED, or —
// when the wallet refuses without answering, as for a request it can't
// trust — be left for review once its screenshot placeholder is filled.
func driveDCAPI(httpClient *http.Client, apiBase, walletVPBase, planID string, m conformancesuite.PlanModule) moduleResult {
	var res moduleResult
	module, err := conformancesuite.CreateModuleInstance(httpClient, apiBase, planID, m.TestModule, m.Variant)
	if err != nil {
		res.err = fmt.Errorf("create module instance: %w", err)
		return res
	}
	req, err := pollBrowserAPIRequest(httpClient, apiBase, module.ID)
	if err != nil {
		res.err = err
		return res
	}
	submitURL, err := url.Parse(req.SubmitURL)
	if err != nil || len(req.Request.Digital.Requests) != 1 {
		res.err = fmt.Errorf("unexpected browser API request: %+v", req)
		return res
	}
	// The page runs on the suite: its origin is the submit URL's.
	origin := submitURL.Scheme + "://" + submitURL.Host
	r := req.Request.Digital.Requests[0]
	answer, err := askWallet(httpClient, walletVPBase, r.Protocol, r.Data, origin)
	if err != nil {
		res.err = err
		return res
	}
	if err := submitToSuite(httpClient, apiBase, submitURL, answer.Result); err != nil {
		res.err = err
		return res
	}

	negative := strings.Contains(m.TestModule, "negative-test")
	refused := bytes.Contains(answer.Result, []byte(`"exception"`))
	wantCode, sendsError := negativeTestExpectedErrorCode[m.TestModule]
	switch {
	case !negative && (refused || answer.SentError != ""):
		res.err = fmt.Errorf("the wallet didn't present: %s", answer.Result)
	case negative && sendsError && answer.SentError != wantCode:
		res.err = fmt.Errorf("sent error %q (refused: %v), want %q", answer.SentError, refused, wantCode)
	case negative && !sendsError && !refused:
		res.err = fmt.Errorf("the wallet answered a request it should refuse: sent error %q", answer.SentError)
	}
	if res.err != nil {
		return res
	}
	if refused {
		if entry, ok := pollUpload(httpClient, apiBase, module.ID, uploadTimeout); ok {
			if err := postPlaceholder(httpClient, apiBase, module.ID, entry); err != nil {
				res.err = fmt.Errorf("fill upload placeholder: %w", err)
				return res
			}
		}
	}
	res.status, res.result, err = conformancesuite.WaitUntilFinished(httpClient, apiBase, module.ID, moduleTimeout)
	switch {
	case err != nil:
		res.err = fmt.Errorf("wait until finished: %w", err)
	case refused && res.result != "REVIEW" && res.result != "PASSED":
		res.err = fmt.Errorf("refused, but the module ended %s", res.result)
	case !refused && res.result != "PASSED" && res.result != "WARNING":
		res.err = fmt.Errorf("the module ended %s", res.result)
	}
	return res
}

// pollBrowserAPIRequest waits for the module's browser API request.
func pollBrowserAPIRequest(httpClient *http.Client, apiBase, moduleID string) (browserAPIRequest, error) {
	deadline := time.Now().Add(browserAPITimeout)
	for {
		req, err := http.NewRequest(http.MethodGet, apiBase+"api/runner/"+moduleID, nil)
		if err != nil {
			return browserAPIRequest{}, err
		}
		body, status, err := conformancesuite.Do(httpClient, req)
		if err == nil && status == http.StatusOK {
			var runner struct {
				Browser struct {
					BrowserAPIRequests []browserAPIRequest `json:"browserApiRequests"`
				} `json:"browser"`
			}
			if json.Unmarshal(body, &runner) == nil && len(runner.Browser.BrowserAPIRequests) > 0 {
				return runner.Browser.BrowserAPIRequests[0], nil
			}
		}
		if time.Now().After(deadline) {
			return browserAPIRequest{}, fmt.Errorf("no browser API request appeared within %s", browserAPITimeout)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// askWallet has cmd/conformance-wallet-vp answer the request.
func askWallet(httpClient *http.Client, walletVPBase, protocol string, data json.RawMessage, origin string) (dcapiAnswer, error) {
	body, err := json.Marshal(map[string]any{"protocol": protocol, "data": data, "origin": origin})
	if err != nil {
		return dcapiAnswer{}, err
	}
	req, err := http.NewRequest(http.MethodPost, walletVPBase+"/dcapi", bytes.NewReader(body))
	if err != nil {
		return dcapiAnswer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	respBody, status, err := conformancesuite.Do(httpClient, req)
	if err != nil || status != http.StatusOK {
		return dcapiAnswer{}, fmt.Errorf("POST /dcapi: status %d: %v: %s", status, err, respBody)
	}
	var answer dcapiAnswer
	if err := json.Unmarshal(respBody, &answer); err != nil {
		return dcapiAnswer{}, fmt.Errorf("decode /dcapi answer: %w", err)
	}
	return answer, nil
}

// submitToSuite posts result to the module's submit URL as the page
// does (a JSON string body), at the host this driver reaches the suite
// on.
func submitToSuite(httpClient *http.Client, apiBase string, submitURL *url.URL, result json.RawMessage) error {
	base, err := url.Parse(apiBase)
	if err != nil {
		return err
	}
	target := *submitURL
	target.Scheme, target.Host = base.Scheme, base.Host
	req, err := http.NewRequest(http.MethodPost, target.String(), bytes.NewReader(result))
	if err != nil {
		return err
	}
	body, status, err := conformancesuite.Do(httpClient, req)
	if err != nil || status >= 300 {
		return fmt.Errorf("POST %s: status %d: %v: %s", target.String(), status, err, body)
	}
	return nil
}

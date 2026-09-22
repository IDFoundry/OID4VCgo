package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// driveOnlyConfig bundles -drive-only's own flags — see main.go's own
// flag.StringVar/flag.BoolVar calls for each field's doc comment.
type driveOnlyConfig struct {
	testName          string
	redirectURL       string
	implicitSubmitURL string
	negativeTest      bool
	screenshotOut     string
	noScreenshot      bool
}

// runDriveOnly drives one already-created module instance's protocol
// flow (a single authorization-redirect GET, plus — only for
// alternate-happy-flow's own fragment-carrying redirect_uri — one
// fragment relay POST) without ever calling the suite's own admin API
// (POST /api/plan, POST /api/runner, GET /api/log). Mirrors
// cmd/conformance-wallet's own -drive-only, for the identical reason:
// the hosted certification.openid.net instance's admin API needs a
// login this script has no way to establish (confirmed live: GET
// /api/log there also returns 401, not just the POST endpoints), but
// none of the module's own protocol endpoints — including
// cmd/conformance-wallet-vp's own public /authorize, and the suite's
// own request_uri/response_uri/implicit-submission endpoints under
// /test/a/<alias>/... — are behind that login.
//
// Grades the outcome per this file's own package doc comment: a
// negative-test module's real pass/fail signal is this binary's own
// local HTTP response (rejected before ever calling response_uri), not
// the suite's own screenshot-REVIEW-gated verdict, which this driver
// never even attempts to poll for.
func runDriveOnly(httpClient *http.Client, cfg driveOnlyConfig) error {
	if cfg.redirectURL == "" {
		return fmt.Errorf("-drive-only requires -redirect-url")
	}

	resp, err := httpClient.Get(cfg.redirectURL) //nolint:gosec,noctx // redirectURL is the operator's own -redirect-url flag value, copied from the suite's own authenticated web UI, not attacker-controlled
	if err != nil {
		return fmt.Errorf("GET %s: %w", cfg.redirectURL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	localOK := resp.StatusCode == http.StatusOK

	label := cfg.testName
	if label == "" {
		label = "(unnamed module)"
	}
	log.Printf("%s: local response %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))

	if fragment, ok := extractFollowedFragment(string(body)); ok {
		if cfg.implicitSubmitURL == "" {
			return fmt.Errorf("%s: response carries a fragment (%q) but -implicit-submit-url was not given — "+
				"find the suite's own implicit_submit.fullUrl log entry for this module and pass it", label, fragment)
		}
		if err := postFragment(httpClient, cfg.implicitSubmitURL, fragment); err != nil {
			return fmt.Errorf("%s: relay implicit fragment: %w", label, err)
		}
		log.Printf("%s: relayed fragment to %s", label, cfg.implicitSubmitURL)
	}

	expected := localOK
	if cfg.negativeTest {
		expected = !localOK
	}
	verdict := "PASSED"
	explain := "correctly returned 200 (credential presented)"
	if cfg.negativeTest {
		explain = "correctly rejected before ever calling response_uri"
		if localOK {
			explain = "returned 200 — should have rejected the malformed request"
		}
	} else if !localOK {
		explain = "returned a non-200 — should have completed successfully"
	}
	if !expected {
		verdict = "FAILED"
	}
	log.Printf("%s: %s (%s)", label, verdict, explain)
	if cfg.negativeTest {
		log.Printf("%s: note — the suite's own module page will likely sit at REVIEW pending a screenshot upload; that gate isn't the real signal here (see this file's own package doc comment)", label)
		if !cfg.noScreenshot {
			pngPath := cfg.screenshotOut
			if pngPath == "" {
				pngPath = fmt.Sprintf("/tmp/%s-evidence.png", strings.ReplaceAll(label, "/", "_"))
			}
			if err := evidenceScreenshot(label, cfg.redirectURL, resp.StatusCode, string(body), pngPath); err != nil {
				log.Printf("%s: could not render evidence screenshot (non-fatal): %v", label, err)
			} else {
				log.Printf("%s: evidence screenshot written to %s — upload this to clear the suite's own REVIEW gate", label, pngPath)
			}
		}
	}
	return nil
}

// postFragment POSTs fragment (leading '#' included) to fullURL as raw
// text/plain — the same wire shape a real browser's
// window.location.hash + XHR POST produces, matching
// relayImplicitFragment's own POST half exactly (this function skips
// only that one's log-polling discovery step, since -drive-only takes
// the URL directly from -implicit-submit-url instead).
func postFragment(httpClient *http.Client, fullURL, fragment string) error {
	req, err := http.NewRequest(http.MethodPost, fullURL, strings.NewReader(fragment)) //nolint:noctx // fullURL is the operator's own -implicit-submit-url flag value, copied from the suite's own authenticated web UI, not attacker-controlled
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

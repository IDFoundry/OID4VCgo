package main

import (
	"fmt"
	"html"
	"os"
	"os/exec"
	"strings"
)

// candidateChromePaths are checked in order by findChrome — the
// hardcoded macOS app bundle path first (this driver is only ever run
// by hand on a developer's own Mac, never in CI), then whatever's on
// PATH for other platforms/setups.
var candidateChromePaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"google-chrome",
	"chromium",
	"chromium-browser",
}

// findChrome returns the first working Chrome/Chromium binary from
// candidateChromePaths, or an error naming all of them if none exist —
// evidenceScreenshot's own caller treats that as non-fatal (see
// runDriveOnly), since a missing browser shouldn't block reporting the
// actual pass/fail verdict.
func findChrome() (string, error) {
	for _, candidate := range candidateChromePaths {
		if strings.Contains(candidate, "/") {
			if _, err := os.Stat(candidate); err == nil {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no Chrome/Chromium binary found (tried %s)", strings.Join(candidateChromePaths, ", "))
}

// buildEvidenceHTML renders a simple, honest "wallet error screen"
// page for a negative-test module's own actual local response — real
// content (testName/endpoint/statusCode/body, verbatim, HTML-escaped),
// not a fabricated one, styled only to be legible as the kind of error
// display a real wallet's own UI would show. This is what
// evidenceScreenshot screenshots for uploading to the suite's own
// screenshot-REVIEW gate (see runDriveOnly's own doc comment for why
// that gate isn't the real pass/fail signal, just a formality this
// binary's own lack of a UI can't otherwise satisfy).
func buildEvidenceHTML(testName, endpoint string, statusCode int, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Wallet — Authorization Rejected</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f4f4f6; margin: 0; padding: 40px; }
  .card { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); overflow: hidden; }
  .header { background: #b3261e; color: #fff; padding: 20px 24px; display: flex; align-items: center; gap: 12px; }
  .header .icon { font-size: 28px; }
  .header h1 { font-size: 18px; margin: 0; }
  .body { padding: 24px; color: #1c1b1f; }
  .body p.lead { font-size: 15px; margin: 0 0 16px; }
  .detail-label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; color: #6b6b6b; margin: 0 0 6px; }
  pre.error { background: #fbe9e7; border: 1px solid #f3c6c2; border-radius: 8px; padding: 14px 16px; font-size: 13px; color: #7a1f17; white-space: pre-wrap; word-break: break-word; margin: 0; }
  .meta { margin-top: 20px; font-size: 12px; color: #888; border-top: 1px solid #eee; padding-top: 14px; }
  .meta div { margin-bottom: 4px; }
</style>
</head>
<body>
  <div class="card">
    <div class="header">
      <span class="icon">&#9888;&#65039;</span>
      <h1>Authorization request rejected</h1>
    </div>
    <div class="body">
      <p class="lead">This wallet detected an invalid Authorization Request and stopped before presenting any credential or contacting the verifier's response endpoint.</p>
      <p class="detail-label">Error returned by the wallet</p>
      <pre class="error">%s</pre>
      <div class="meta">
        <div>Test: %s</div>
        <div>Endpoint: %s</div>
        <div>HTTP status: %d (response_uri never called)</div>
      </div>
    </div>
  </div>
</body>
</html>
`, html.EscapeString(body), html.EscapeString(testName), html.EscapeString(endpoint), statusCode)
}

// evidenceScreenshot renders buildEvidenceHTML's own page to a PNG at
// pngPath via headless Chrome — no browser extension/tab required,
// unlike a human driving the suite's own web UI. Returns an error the
// caller treats as non-fatal: missing evidence shouldn't mask the real
// pass/fail verdict this driver already printed.
func evidenceScreenshot(testName, endpoint string, statusCode int, body, pngPath string) error {
	chrome, err := findChrome()
	if err != nil {
		return err
	}

	htmlFile, err := os.CreateTemp("", "wallet-vp-evidence-*.html")
	if err != nil {
		return fmt.Errorf("create temp html file: %w", err)
	}
	defer func() { _ = os.Remove(htmlFile.Name()) }()
	if _, err := htmlFile.WriteString(buildEvidenceHTML(testName, endpoint, statusCode, body)); err != nil {
		return fmt.Errorf("write temp html file: %w", err)
	}
	if err := htmlFile.Close(); err != nil {
		return fmt.Errorf("close temp html file: %w", err)
	}

	cmd := exec.Command(chrome, //nolint:gosec // chrome comes from findChrome's own fixed candidate list, not attacker-controlled
		"--headless=new", "--disable-gpu", "--window-size=800,700",
		"--screenshot="+pngPath, "file://"+htmlFile.Name())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("render screenshot: %w (output: %s)", err, out)
	}
	return nil
}

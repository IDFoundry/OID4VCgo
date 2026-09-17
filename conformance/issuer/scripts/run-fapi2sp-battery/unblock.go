// This file works around a real, universal bug in the OIDF
// conformance suite itself, not anything in either FAPIgo or
// OID4VCIgo: the suite's own scripted browser (HtmlUnit) usually fails
// to execute implicitCallback.html's own JavaScript, which is supposed
// to auto-POST an empty body to a per-visit "implicit submission" URL
// to let a stuck module continue (CreateRandomImplicitSubmitUrl.java /
// implicitCallback.html in the suite's own source) — HtmlUnit throws a
// syntax error parsing the page's Bootstrap 5.3.3 <script src> bundle.
// Every suite release that supports the FAPI2 Security Profile Final
// test plan family also carries this bug (Bootstrap was bumped to
// 5.3.3 in the exact same release that introduced that plan) — so
// unlike a code fix, there is no config change that avoids it, and
// FAPIgo's own OpenID-Certified cmd/conformance-as needs the identical
// workaround to drive this same underlying module family reliably
// (conformance/server/scripts/unblock-implicit-callback.py, go-fapi).
// Ported here in Go rather than shelling out to that Python script, to
// keep this binary self-contained and consistent with every other
// conformance/*/scripts/* tool in this repo.
//
// The Bootstrap failure is scoped to that one <script src> tag, not
// the whole page: a separate inline <script> block holding the real
// xhr.send() call still executes independently, and sometimes wins on
// its own before this poller ever gets there. So this isn't "the
// module always hangs" — it's "the module hangs often enough,
// unpredictably enough, that every run needs this regardless."
// Submitting again anyway when the browser's own JS already won isn't
// just redundant: the suite's own module-continuation logic isn't
// safe against being woken twice concurrently, corrupting the flow
// into two racing token exchanges over the same authorization code —
// see alreadySubmittedByBrowser below.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// firstImplicitSubmitExtraCycles gives only the very first
// implicit-submit URL a run ever sees extra deferral cycles beyond the
// normal one every later URL gets — the suite's own scripted browser
// needs a one-time, ~500ms cold start to render and execute JS on the
// very first callback page of the session; every later module reuses
// the already-warmed browser session and reliably wins the normal
// one-cycle deferral below on its own (ported from
// unblock-implicit-callback.py's own identical, live-confirmed
// finding).
const firstImplicitSubmitExtraCycles = 3

// placeholderGracePeriod bounds how long an "upload" placeholder
// (createBrowserInteractionPlaceholder() in the suite's own
// AbstractCondition.java — negative-test modules that land on a local
// error page and would otherwise ask a human to upload a screenshot)
// is left unfilled before this poller fills it itself with a 1x1 PNG,
// moving the module from WAITING to FINISHED with result=REVIEW.
// Placeholders are addressed by instance id, not a shared per-alias
// route the way implicit-submit URLs are, so there's no cross-module
// misrouting risk in waiting generously here — some modules create
// their own placeholder speculatively, well before their own success
// path has a chance to run, and filling it too early would force an
// otherwise-genuine PASS down to REVIEW.
const placeholderGracePeriod = 5 * time.Second

// placeholderPNGDataURI is a minimal valid 1x1 transparent PNG, sent
// as this run's own literal request body — content doesn't matter, the
// suite only validates it's a well-formed image under its own size
// limit. The endpoint expects the full "data:image/png;base64,..."
// URI as literal text, not raw decoded image bytes: confirmed live
// that POSTing the raw bytes (even byte-for-byte correct ones) gets
// "Only jpeg/png files accepted" every time — the suite parses this
// endpoint's own request body as a data URI string first (splitting
// on the comma, base64-decoding the remainder, then checking the
// declared MIME type), not as a raw image upload — matching
// unblock-implicit-callback.py's own PLACEHOLDER_PNG, which is
// likewise the data URI string itself (PLACEHOLDER_PNG.encode()),
// never decoded before sending.
const placeholderPNGDataURI = "data:image/png;base64," +
	"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAA" +
	"AAYAAjCB0C8AAAAASUVORK5CYII="

// implicitSubmitState tracks one pending "Created random implicit
// submission URL" entry this poller has seen but not yet acted on.
type implicitSubmitState struct {
	instanceID string
	cycles     int
}

// unblockImplicitCallbacks polls every module instance planID has
// created (via GET /api/plan/{planID}, whose own "modules[].instances"
// list grows live as this binary creates each module) and resolves the
// two kinds of stuck-waiting-for-a-human-or-browser conditions
// described in this file's own doc comment, until ctx is cancelled.
// Run this as a background goroutine alongside the module-driving loop
// in main.go.
func unblockImplicitCallbacks(ctx context.Context, httpClient *http.Client, apiBase, planID string) {
	submitted := make(map[string]bool)                   // implicit_submit fullUrl -> already POSTed once
	pending := make(map[string]*implicitSubmitState)     // fullUrl -> pending state
	uploaded := make(map[[2]string]bool)                 // (instanceID, placeholder) -> already filled once
	pendingPlaceholders := make(map[[2]string]time.Time) // (instanceID, placeholder) -> first seen
	active := make(map[string]bool)
	seenEver := make(map[string]bool)
	var firstImplicitURL string

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		instances, err := planInstances(httpClient, apiBase, planID)
		if err == nil {
			for _, id := range instances {
				if !seenEver[id] {
					seenEver[id] = true
					active[id] = true
				}
			}
		}

		for id := range active {
			info, err := fetchModuleInfo(httpClient, apiBase, id)
			if err != nil {
				continue
			}
			if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
				delete(active, id)
				continue
			}

			entries, err := fetchModuleLogRaw(httpClient, apiBase, id)
			if err != nil {
				continue
			}

			for _, e := range entries {
				if e.Msg == "Created random implicit submission URL" && e.ImplicitSubmit != nil && e.ImplicitSubmit.FullURL != "" {
					fullURL := e.ImplicitSubmit.FullURL
					if submitted[fullURL] {
						continue
					}
					st, ok := pending[fullURL]
					if !ok {
						pending[fullURL] = &implicitSubmitState{instanceID: id, cycles: 0}
						if firstImplicitURL == "" {
							firstImplicitURL = fullURL
						}
						continue
					}
					st.cycles++
					required := 1
					if fullURL == firstImplicitURL {
						required = 1 + firstImplicitSubmitExtraCycles
					}
					if st.cycles < required {
						continue
					}
					delete(pending, fullURL)
					submitted[fullURL] = true

					requestPath, ok := pathOf(fullURL)
					if !ok {
						continue
					}
					wantMsg := "Incoming HTTP request to " + requestPath
					alreadySubmittedByBrowser := false
					for _, e2 := range entries {
						if e2.Msg == wantMsg {
							alreadySubmittedByBrowser = true
							break
						}
					}
					if alreadySubmittedByBrowser {
						continue
					}
					postEmptyBody(ctx, httpClient, apiBase+requestPath[1:])
				}

				if e.Upload != "" {
					key := [2]string{id, e.Upload}
					if uploaded[key] {
						continue
					}
					if _, ok := pendingPlaceholders[key]; !ok {
						pendingPlaceholders[key] = time.Now()
					}
				}
			}
		}

		now := time.Now()
		for key, firstSeen := range pendingPlaceholders {
			if now.Sub(firstSeen) < placeholderGracePeriod {
				continue
			}
			delete(pendingPlaceholders, key)
			instanceID, placeholder := key[0], key[1]
			if !active[instanceID] {
				// Finished on its own during the grace period — never
				// actually needed.
				continue
			}
			uploaded[key] = true
			fillPlaceholder(ctx, httpClient, apiBase, instanceID, placeholder)
		}
	}
}

func postEmptyBody(ctx context.Context, httpClient *http.Client, url string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		log.Printf("unblock %s failed (not retrying): build request: %v", url, err)
		return
	}
	res, err := httpClient.Do(req)
	if err != nil {
		log.Printf("unblock %s failed (not retrying): %v", url, err)
		return
	}
	_ = res.Body.Close()
	log.Printf("unblocked: POST %s -> %d", url, res.StatusCode)
}

func fillPlaceholder(ctx context.Context, httpClient *http.Client, apiBase, instanceID, placeholder string) {
	url := fmt.Sprintf("%sapi/log/%s/images/%s", apiBase, instanceID, placeholder)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(placeholderPNGDataURI))
	if err != nil {
		log.Printf("fill placeholder %s/%s failed (not retrying): build request: %v", instanceID, placeholder, err)
		return
	}
	// text/plain, not image/png: matches unblock-implicit-callback.py's
	// own proven-working PLACEHOLDER_PNG upload exactly — the suite's
	// own endpoint parses the body as a data URI string regardless of
	// the declared content type, confirmed live via curl (a text/plain
	// declaration with the literal data URI text succeeds; the same
	// declaration with raw decoded image bytes gets rejected with
	// "Only jpeg/png files accepted").
	req.Header.Set("Content-Type", "text/plain")
	res, err := httpClient.Do(req)
	if err != nil {
		log.Printf("fill placeholder %s/%s failed (not retrying): %v", instanceID, placeholder, err)
		return
	}
	_ = res.Body.Close()
	log.Printf("filled placeholder %s/%s -> %d", instanceID, placeholder, res.StatusCode)
}

// This file works around a real, universal bug in the OIDF
// conformance suite itself, not anything in either FAPIgo or
// OID4VCgo: the suite's own scripted browser (HtmlUnit) usually fails
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

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
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

// unblockPoller holds every module-instance-tracking map
// unblockImplicitCallbacks needs across ticks. Splitting its single
// polling loop into small methods on this struct (rather than one
// large function with everything inlined) keeps each step's own
// cognitive complexity low — the loop itself does four genuinely
// separate things (discover new instances, poll each active one,
// react to two distinct kinds of stuck-waiting log entry, fill
// placeholders once their own grace period elapses) that don't need
// to be read together to be understood individually.
type unblockPoller struct {
	ctx        context.Context
	httpClient *http.Client
	apiBase    string
	planID     string

	submitted           map[string]bool                 // implicit_submit fullUrl -> already POSTed once
	pending             map[string]*implicitSubmitState // fullUrl -> pending state
	uploaded            map[[2]string]bool              // (instanceID, placeholder) -> already filled once
	pendingPlaceholders map[[2]string]time.Time         // (instanceID, placeholder) -> first seen
	active              map[string]bool
	seenEver            map[string]bool
	firstImplicitURL    string
}

// unblockImplicitCallbacks polls every module instance planID has
// created (via GET /api/plan/{planID}, whose own "modules[].instances"
// list grows live as this binary creates each module) and resolves the
// two kinds of stuck-waiting-for-a-human-or-browser conditions
// described in this file's own doc comment, until ctx is cancelled.
// Run this as a background goroutine alongside the module-driving loop
// in main.go.
func unblockImplicitCallbacks(ctx context.Context, httpClient *http.Client, apiBase, planID string) {
	p := &unblockPoller{
		ctx:                 ctx,
		httpClient:          httpClient,
		apiBase:             apiBase,
		planID:              planID,
		submitted:           make(map[string]bool),
		pending:             make(map[string]*implicitSubmitState),
		uploaded:            make(map[[2]string]bool),
		pendingPlaceholders: make(map[[2]string]time.Time),
		active:              make(map[string]bool),
		seenEver:            make(map[string]bool),
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		p.tick()
	}
}

// tick runs one polling pass: discover any module instances created
// since the last tick, react to each active instance's own current log,
// then fill any placeholder whose own grace period has now elapsed.
func (p *unblockPoller) tick() {
	p.discoverNewInstances()
	for id := range p.active {
		p.pollInstance(id)
	}
	p.fillDuePlaceholders()
}

func (p *unblockPoller) discoverNewInstances() {
	instances, err := conformancesuite.PlanInstances(p.httpClient, p.apiBase, p.planID)
	if err != nil {
		return
	}
	for _, id := range instances {
		if !p.seenEver[id] {
			p.seenEver[id] = true
			p.active[id] = true
		}
	}
}

// pollInstance fetches id's own current status and log, dropping it
// from tracking once it reaches a terminal status, otherwise reacting
// to every log entry it's produced so far.
func (p *unblockPoller) pollInstance(id string) {
	info, err := conformancesuite.FetchModuleInfo(p.httpClient, p.apiBase, id)
	if err != nil {
		return
	}
	if info.Status == "FINISHED" || info.Status == "INTERRUPTED" {
		delete(p.active, id)
		return
	}

	entries, err := conformancesuite.FetchModuleLog(p.httpClient, p.apiBase, id)
	if err != nil {
		return
	}
	for _, e := range entries {
		p.reactToLogEntry(id, entries, e)
	}
}

func (p *unblockPoller) reactToLogEntry(id string, entries []conformancesuite.LogEntry, e conformancesuite.LogEntry) {
	if e.Msg == "Created random implicit submission URL" && e.ImplicitSubmit != nil && e.ImplicitSubmit.FullURL != "" {
		p.handleImplicitSubmitURL(id, entries, e.ImplicitSubmit.FullURL)
	}
	if e.Upload != "" {
		p.notePlaceholder(id, e.Upload)
	}
}

// handleImplicitSubmitURL defers each newly seen implicit-submit URL
// by one cycle (extra cycles for the very first one this run ever
// sees) to give the browser's own JS a chance to win the race first,
// then POSTs it itself unless the browser already has.
func (p *unblockPoller) handleImplicitSubmitURL(id string, entries []conformancesuite.LogEntry, fullURL string) {
	if p.submitted[fullURL] {
		return
	}
	st, ok := p.pending[fullURL]
	if !ok {
		p.pending[fullURL] = &implicitSubmitState{instanceID: id, cycles: 0}
		if p.firstImplicitURL == "" {
			p.firstImplicitURL = fullURL
		}
		return
	}
	st.cycles++
	required := 1
	if fullURL == p.firstImplicitURL {
		required = 1 + firstImplicitSubmitExtraCycles
	}
	if st.cycles < required {
		return
	}
	delete(p.pending, fullURL)
	p.submitted[fullURL] = true

	requestPath, ok := conformancesuite.PathOf(fullURL)
	if !ok {
		return
	}
	if browserAlreadySubmitted(entries, requestPath) {
		return
	}
	postEmptyBody(p.ctx, p.httpClient, p.apiBase+requestPath[1:])
}

// browserAlreadySubmitted reports whether the module's own log already
// shows an inbound request to requestPath — submitting again anyway
// would corrupt the flow into two racing token exchanges over the same
// authorization code (see this file's own package doc comment).
func browserAlreadySubmitted(entries []conformancesuite.LogEntry, requestPath string) bool {
	wantMsg := "Incoming HTTP request to " + requestPath
	for _, e := range entries {
		if e.Msg == wantMsg {
			return true
		}
	}
	return false
}

func (p *unblockPoller) notePlaceholder(id, placeholder string) {
	key := [2]string{id, placeholder}
	if p.uploaded[key] {
		return
	}
	if _, ok := p.pendingPlaceholders[key]; !ok {
		p.pendingPlaceholders[key] = time.Now()
	}
}

func (p *unblockPoller) fillDuePlaceholders() {
	now := time.Now()
	for key, firstSeen := range p.pendingPlaceholders {
		if now.Sub(firstSeen) < placeholderGracePeriod {
			continue
		}
		delete(p.pendingPlaceholders, key)
		instanceID, placeholder := key[0], key[1]
		if !p.active[instanceID] {
			// Finished on its own during the grace period — never
			// actually needed.
			continue
		}
		p.uploaded[key] = true
		fillPlaceholder(p.ctx, p.httpClient, p.apiBase, instanceID, placeholder)
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

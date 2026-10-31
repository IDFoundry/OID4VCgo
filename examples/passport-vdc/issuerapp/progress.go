package issuerapp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// An offer page follows its offer's progress — the wallet taking it,
// the approval, each credential issued — from a status endpoint only the
// browser that uploaded the passport can read (browserCookie). It
// reports coarse states, never passport data, codes or the offer.

// browserCookie names the browser that uploaded a passport, so only it
// reads that offer's progress.
const browserCookie = "passport_vdc_issuer_browser"

// A credential's progress.
const (
	credentialPending  = "pending"  // not issued yet
	credentialIssued   = "issued"   // issued
	credentialDeferred = "deferred" // held for an operator's review
	credentialApproved = "approved" // approved by the operator; issued on the wallet's next check
	credentialRefused  = "refused"  // refused by the operator
)

// An offer's coarse states.
const (
	offerWaiting    = "waiting"    // no wallet has taken it yet
	offerAuthorized = "authorized" // approved, or its PIN accepted: issuing
	offerDeferred   = "deferred"   // a credential awaits the operator, or the wallet's next check
	offerIssued     = "issued"     // every credential issued (or refused)
	offerRefused    = "refused"    // every credential refused
	offerDenied     = "denied"     // declined at the approval step
	offerExpired    = "expired"    // expired, or voided by wrong codes, before it was redeemed
	offerEnded      = "ended"      // unknown, forgotten, or another browser's
)

// Bounds on the progress kept.
const (
	maxProgress = 200
	// progressMargin is how much longer than its offer an offer's progress is kept: past
	// is kept: long enough for a review.
	progressMargin = reviewLifetime
)

// offerProgress is one offer's progress. It holds no passport data.
type offerProgress struct {
	id            string // names it in the status URL; not the transaction ID
	txID          string
	browser       string // the uploading browser's browserCookie
	preAuthorized bool
	formats       []string
	credentials   map[string]string // format → its progress
	authorized    bool
	declined      bool
	offerExpires  time.Time
	dropAt        time.Time
}

// progressBoard holds the offers' progress, by transaction ID and by ID.
type progressBoard struct {
	mu   sync.Mutex
	byTx map[string]*offerProgress
	byID map[string]*offerProgress
}

func newProgressBoard() *progressBoard {
	return &progressBoard{byTx: map[string]*offerProgress{}, byID: map[string]*offerProgress{}}
}

// add follows transaction txID's offer of configIDs for browser,
// returning the ID its status URL names.
func (p *progressBoard) add(now time.Time, txID, browser string, preAuthorized bool, configIDs []string, offerExpires time.Time) (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	op := &offerProgress{
		id: base64.RawURLEncoding.EncodeToString(b[:]), txID: txID, browser: browser, preAuthorized: preAuthorized,
		credentials: map[string]string{}, offerExpires: offerExpires, dropAt: offerExpires.Add(progressMargin),
	}
	for _, c := range configIDs {
		f := credentialFormat(c)
		op.formats = append(op.formats, f)
		op.credentials[f] = credentialPending
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	if len(p.byID) >= maxProgress {
		// The oldest goes: its page then shows the offer has ended.
		var oldest *offerProgress
		var oldestTx string
		for tx, v := range p.byTx {
			if oldest == nil || v.dropAt.Before(oldest.dropAt) {
				oldest, oldestTx = v, tx
			}
		}
		delete(p.byTx, oldestTx)
		delete(p.byID, oldest.id)
	}
	p.byTx[txID], p.byID[op.id] = op, op
	return op.id, nil
}

func (p *progressBoard) pruneLocked(now time.Time) {
	for tx, v := range p.byTx {
		if !now.Before(v.dropAt) {
			delete(p.byTx, tx)
			delete(p.byID, v.id)
		}
	}
}

// idOf is the ID of transaction txID's progress, or "".
func (p *progressBoard) idOf(txID string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.byTx[txID]; ok {
		return v.id
	}
	return ""
}

// update applies f to transaction txID's progress, if it's followed.
func (p *progressBoard) update(txID string, f func(*offerProgress)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if v, ok := p.byTx[txID]; ok {
		f(v)
	}
}

// setCredential records format's progress in transaction txID's offer.
func (p *progressBoard) setCredential(txID, format, state string) {
	p.update(txID, func(v *offerProgress) {
		if _, offered := v.credentials[format]; offered {
			v.credentials[format] = state
		}
	})
}

// snapshot is a copy of the progress under id, if browser may read it.
func (p *progressBoard) snapshot(now time.Time, id, browser string) (offerProgress, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pruneLocked(now)
	v, ok := p.byID[id]
	if !ok || browser == "" || subtle.ConstantTimeCompare([]byte(browser), []byte(v.browser)) != 1 {
		return offerProgress{}, false
	}
	c := *v
	c.credentials = make(map[string]string, len(v.credentials))
	for k, s := range v.credentials {
		c.credentials[k] = s
	}
	c.formats = slices.Clone(v.formats)
	return c, true
}

// offerStatus is what an offer page polls: the offer's coarse state,
// each credential's, and the steps the page shows, in words.
type offerStatus struct {
	State       string            `json:"state"`
	Credentials map[string]string `json:"credentials,omitempty"`
	Steps       []progressStep    `json:"steps,omitempty"`
	Summary     string            `json:"summary"`
	Final       bool              `json:"final"`
}

// progressStep is one step an offer page lists, with its state: "todo",
// "current", "done" or "failed".
type progressStep struct {
	Label string `json:"label"`
	State string `json:"state"`
}

// status is v's offerStatus; held reports whether its transaction is
// still held (it's gone once issued, expired or voided).
func (v offerProgress) status(now time.Time, held bool) offerStatus {
	st := offerStatus{State: v.state(now, held), Credentials: v.credentials}
	st.Summary, st.Final = summaries[st.State], finalStates[st.State]
	approve := "Approved"
	if v.preAuthorized {
		approve = "PIN accepted"
	}
	step := func(label string, state string) { st.Steps = append(st.Steps, progressStep{label, state}) }
	switch st.State {
	case offerWaiting:
		step("Waiting for the wallet", "current")
		step(approve, "todo")
	case offerExpired:
		step("The offer expired", "failed")
		step(approve, "todo")
	case offerDenied:
		step("The wallet took the offer", "done")
		step("Declined", "failed")
	default:
		step("The wallet took the offer", "done")
		step(approve, "done")
	}
	issuing := map[string]string{offerIssued: "done", offerRefused: "failed", offerAuthorized: "current", offerDeferred: "current"}[st.State]
	if issuing == "" {
		issuing = "todo"
	}
	step(v.credentialsLabel(), issuing)
	return st
}

// state is v's coarse state.
func (v offerProgress) state(now time.Time, held bool) string {
	var issued, refused, waiting int
	for _, s := range v.credentials {
		switch s {
		case credentialIssued:
			issued++
		case credentialRefused:
			refused++
		case credentialDeferred, credentialApproved:
			waiting++
		}
	}
	switch {
	case issued+refused == len(v.credentials) && issued > 0:
		return offerIssued
	case refused == len(v.credentials) && refused > 0:
		return offerRefused
	case waiting > 0:
		return offerDeferred
	case v.authorized:
		return offerAuthorized
	case !held || !now.Before(v.offerExpires):
		return offerExpired
	case v.declined:
		return offerDenied
	}
	return offerWaiting
}

// credentialsLabel is the last step: each credential and how it's
// doing, as "Credentials issued (mdoc ✓, SD-JWT VC ✓)".
func (v offerProgress) credentialsLabel() string {
	marks := map[string]string{
		credentialPending: "…", credentialIssued: "✓", credentialDeferred: "awaiting review",
		credentialApproved: "approved, on the wallet's next check", credentialRefused: "✗ refused",
	}
	parts := make([]string, 0, len(v.formats))
	for _, f := range v.formats {
		parts = append(parts, formatName(f)+" "+marks[v.credentials[f]])
	}
	return "Credentials issued (" + strings.Join(parts, ", ") + ")"
}

var summaries = map[string]string{
	offerWaiting:    "Waiting for the wallet…",
	offerAuthorized: "Approved. Issuing the credentials…",
	offerDeferred:   "Waiting for the operator's review…",
	offerIssued:     "Credentials issued.",
	offerRefused:    "The operator refused the credentials.",
	offerDenied:     "Declined at the approval step: nothing was issued. The offer still works until it expires.",
	offerExpired:    "The offer has expired.",
	offerEnded:      "This offer has ended.",
}

var finalStates = map[string]bool{offerIssued: true, offerRefused: true, offerExpired: true, offerEnded: true}

// browserID is r's browserCookie, or "".
func browserID(r *http.Request) string {
	if c, err := r.Cookie(browserCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	return ""
}

// ensureBrowserID returns r's browserCookie, setting a new one on w when
// it has none.
func ensureBrowserID(w http.ResponseWriter, r *http.Request) (string, error) {
	if id := browserID(r); id != "" {
		return id, nil
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b[:])
	http.SetCookie(w, &http.Cookie{
		Name: browserCookie, Value: id, Path: "/demo/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	return id, nil
}

// offerStatusFor is the status of the offer id, as r's browser may see it.
func (a *App) offerStatusFor(r *http.Request) offerStatus {
	v, ok := a.progress.snapshot(a.now(), r.PathValue("id"), browserID(r))
	if !ok {
		return offerStatus{State: offerEnded, Summary: summaries[offerEnded], Final: true}
	}
	return v.status(a.now(), a.transactions.held(v.txID))
}

// handleOfferStatus answers an offer page's polling: 404 "ended" for an
// unknown offer, or another browser's.
func (a *App) handleOfferStatus(w http.ResponseWriter, r *http.Request) {
	st := a.offerStatusFor(r)
	w.Header().Set(headerCacheControl, noStore)
	w.Header().Set(headerContentType, "application/json")
	if st.State == offerEnded {
		w.WriteHeader(http.StatusNotFound)
	}
	_ = json.NewEncoder(w).Encode(st)
}

// progressFrameTemplate is the offer's progress for a browser without
// JavaScript, in a frame on the offer page that refreshes itself.
var progressFrameTemplate = parsePage("progress", stepsPart+pageHead+`{{if not .Final}}<meta http-equiv="refresh" content="2">{{end}}
<style>body{padding:0;max-width:none;background:var(--surface)}</style></head><body>
{{template "steps" .}}
</body></html>`)

// stepsPart lists an offer's steps, and its summary in a live region.
const stepsPart = `{{define "steps"}}<p id="offer-live" class="progress-summary" role="status" aria-live="polite">{{if not .Final}}<span class="spinner" aria-hidden="true"></span> {{end}}{{.Summary}}</p>
<ol class="steps" id="offer-steps">{{range .Steps}}<li data-state="{{.State}}">{{.Label}}</li>{{end}}</ol>{{end}}`

// handleOfferProgress serves progressFrameTemplate.
func (a *App) handleOfferProgress(w http.ResponseWriter, r *http.Request) {
	st := a.offerStatusFor(r)
	status := http.StatusOK
	if st.State == offerEnded {
		status = http.StatusNotFound
	}
	renderPage(w, status, progressFrameTemplate, st, true)
}

// progressScript polls the offer's status every two seconds, updating
// its steps and announcing each change, until the offer is done.
const progressScript = `<script>
(function () {
	var section = document.getElementById("offer-progress");
	if (!section) return;
	var url = section.getAttribute("data-status"), live = document.getElementById("offer-live"), list = document.getElementById("offer-steps");
	var last = live.textContent.trim();
	function render(s) {
		list.textContent = "";
		(s.steps || []).forEach(function (step) {
			var li = document.createElement("li");
			li.setAttribute("data-state", step.state);
			li.textContent = step.label;
			list.appendChild(li);
		});
		if (s.summary !== last) {
			last = s.summary;
			live.textContent = s.summary;
			if (!s.final) {
				var spin = document.createElement("span");
				spin.className = "spinner";
				spin.setAttribute("aria-hidden", "true");
				live.prepend(spin, " ");
			}
		}
	}
	function poll() {
		fetch(url, {cache: "no-store", credentials: "same-origin"}).then(function (r) {
			return r.json();
		}).then(function (s) {
			render(s);
			if (!s.final) setTimeout(poll, 2000);
		}).catch(function () { setTimeout(poll, 2000); });
	}
	setTimeout(poll, 2000);
})();
</script>`

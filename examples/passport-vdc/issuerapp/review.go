package issuerapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demoui"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// Deferred issuance (OID4VCI 1.0 §9): a passport uploaded "for review"
// isn't issued at once. Its Credential Requests are deferred, each
// waiting in reviews until an operator approves or denies it on the
// /review page; the wallet's next poll of the Deferred Credential
// Endpoint then issues the credential, or is told it's denied.

const (
	// deferredPollInterval is how long the wallet is asked to wait
	// between polls.
	deferredPollInterval = 5 * time.Second
	// reviewLifetime bounds how long a deferred request waits for a
	// decision, and how long a decided one waits for the wallet's poll.
	reviewLifetime = time.Hour
	// maxReviews bounds how many deferred requests wait at once.
	maxReviews = 100
)

type reviewDecision int

const (
	reviewPending reviewDecision = iota
	reviewApproved
	reviewDenied
)

// review is one deferred Credential Request awaiting a decision. It keeps
// its own copy of the passport's Evidence, which the transaction drops
// once every offered credential is issued or deferred.
type review struct {
	evidence  passport.Evidence
	configID  string
	txID      string // the transaction it's from, whose offer page follows it
	createdAt time.Time
	decision  reviewDecision
}

// reviews holds deferred Credential Requests in memory, keyed by an
// unguessable reference: the DeferredTransactionRecord's Reference.
type reviews struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[string]*review
}

var (
	errTooManyReviews = errors.New("issuerapp: too many issuances are awaiting review")
	errUnknownReview  = errors.New("issuerapp: unknown or already-decided review")
)

func newReviews(now func() time.Time) *reviews {
	return &reviews{now: now, items: make(map[string]*review)}
}

// add holds e for configID, from transaction txID, until a decision,
// returning its reference.
func (r *reviews) add(e passport.Evidence, configID, txID string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("issuerapp: review reference: %w", err)
	}
	ref := base64.RawURLEncoding.EncodeToString(b[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.pruneLocked(now)
	if len(r.items) >= maxReviews {
		return "", errTooManyReviews
	}
	r.items[ref] = &review{evidence: e, configID: configID, txID: txID, createdAt: now}
	return ref, nil
}

// prune drops expired reviews, and their passport data.
func (r *reviews) prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(r.now())
}

func (r *reviews) pruneLocked(now time.Time) {
	for k, v := range r.items {
		if now.Sub(v.createdAt) >= reviewLifetime {
			delete(r.items, k)
		}
	}
}

// get returns the unexpired review under ref.
func (r *reviews) get(ref string) (review, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[ref]
	if !ok || r.now().Sub(v.createdAt) >= reviewLifetime {
		return review{}, false
	}
	return *v, true
}

// decide records an operator's decision on a pending review, returning
// the review.
func (r *reviews) decide(ref string, approve bool) (review, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[ref]
	if !ok || v.decision != reviewPending || r.now().Sub(v.createdAt) >= reviewLifetime {
		return review{}, errUnknownReview
	}
	v.decision = reviewDenied
	if approve {
		v.decision = reviewApproved
	}
	return *v, nil
}

// remove drops the review under ref, and its passport data.
func (r *reviews) remove(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.items, ref)
}

// ReviewEntry is a deferred issuance as the /review page shows it: no
// names or document number, only what the demo's operator decides on.
type ReviewEntry struct {
	Ref            string
	Format         string
	IssuingCountry string
	PassportExpiry string
	Expired        bool
	ChipAuth       string
	CreatedAt      time.Time
	Decision       string
	// Unchecked marks gmrtd's sample passport, which approving issues
	// without Passive Authentication.
	Unchecked bool
}

// Reviews lists the deferred issuances awaiting a decision or the
// wallet's next poll, oldest first.
func (a *App) Reviews() []ReviewEntry {
	a.reviews.mu.Lock()
	defer a.reviews.mu.Unlock()
	now := a.now()
	var out []ReviewEntry
	for ref, v := range a.reviews.items {
		if now.Sub(v.createdAt) >= reviewLifetime {
			continue
		}
		id := v.evidence.Identity
		out = append(out, ReviewEntry{
			Ref: ref, Format: credentialFormat(v.configID), IssuingCountry: id.IssuingCountry,
			PassportExpiry: id.ExpiryDate.Format(time.DateOnly), Expired: id.ExpiredAt(now), ChipAuth: v.evidence.Checks.ChipAuthenticity,
			CreatedAt: v.createdAt, Decision: [...]string{"awaiting review", "approved", "denied"}[v.decision],
			Unchecked: !v.evidence.Checks.PassiveAuthentication,
		})
	}
	slices.SortFunc(out, func(x, y ReviewEntry) int { return x.CreatedAt.Compare(y.CreatedAt) })
	return out
}

// pendingReviews counts the deferred issuances awaiting a decision.
func (a *App) pendingReviews() int {
	a.reviews.mu.Lock()
	defer a.reviews.mu.Unlock()
	now, n := a.now(), 0
	for _, v := range a.reviews.items {
		if v.decision == reviewPending && now.Sub(v.createdAt) < reviewLifetime {
			n++
		}
	}
	return n
}

// Review records the operator's decision on the deferred issuance ref;
// the wallet's next poll carries it out.
func (a *App) Review(ref string, approve bool) error {
	rv, err := a.reviews.decide(ref, approve)
	if err != nil {
		return err
	}
	state := credentialRefused
	if approve {
		state = credentialApproved
	}
	a.progress.setCredential(rv.txID, credentialFormat(rv.configID), state)
	return nil
}

// resolveDeferred is the Deferred Credential Endpoint's Resolve: on each
// poll it carries out the operator's decision on the transaction's
// review, if there is one yet. A review that's gone (expired, or lost
// to a restart) is denied, so the wallet stops polling.
func (a *App) resolveDeferred(ctx context.Context, _ issuer.Grant, transactionID string, tx issuer.DeferredTransactionRecord) error {
	rv, ok := a.reviews.get(tx.Reference)
	switch {
	case !ok, rv.decision == reviewDenied:
		a.reviews.remove(tx.Reference)
		if ok {
			a.progress.setCredential(rv.txID, credentialFormat(rv.configID), credentialRefused)
		}
		return a.issuer.DenyDeferredCredential(ctx, transactionID)
	case rv.decision == reviewPending:
		return nil
	}
	opts := credential.Options{Now: a.now(), IssuingCountry: demoCountry}
	mdocClaims, err := credential.MdocClaims(rv.evidence, opts)
	if err != nil {
		return err
	}
	sdjwtClaims, err := credential.SDJWTClaims(rv.evidence, a.vct, opts)
	if err != nil {
		return err
	}
	var statusIdxs []int
	err = a.issuer.IssueDeferredCredential(ctx, transactionID, issuer.DeferredIssuance{
		MdocClaims: mdocClaims, SDJWTClaims: sdjwtClaims,
		PerCredential: func(_ context.Context, c *issuer.CredentialInstance) error {
			idx, err := a.statusList.allocate(credentialFormat(rv.configID), !rv.evidence.Checks.PassiveAuthentication, a.now())
			if err != nil {
				return err
			}
			statusIdxs = append(statusIdxs, idx)
			a.withStatus(c, idx)
			return nil
		},
	})
	if err != nil {
		for _, idx := range statusIdxs {
			a.statusList.release(idx)
		}
		return err
	}
	a.reviews.remove(tx.Reference)
	a.progress.setCredential(rv.txID, credentialFormat(rv.configID), credentialIssued)
	return nil
}

type reviewPage struct {
	Header  demoui.Header
	Entries []ReviewEntry
	// Counts is what the review status reports now (reviewCounts): the
	// page reloads when it changes.
	Counts reviewCounts
}

var reviewTemplate = parsePage("review", pageHead+`<noscript><meta http-equiv="refresh" content="10"></noscript>
</head><body>
{{template "site-header" .Header}}
<main>
<h1>Issuances awaiting review</h1>
<p>A passport uploaded for review isn't issued at once: the wallet is told to wait, and checks back until an operator decides here. Its next check then gets the credential, or a refusal.</p>
<p id="review-live" class="note" role="status" aria-live="polite" data-pending="{{.Counts.Pending}}" data-total="{{.Counts.Total}}"></p>
{{if .Entries}}
<ul class="entries">
{{range .Entries}}<li class="card entry">
<p class="badges"><span class="badge">{{formatName .Format}}</span> {{if eq .Decision "awaiting review"}}<span class="badge warn">Awaiting review</span>{{else if eq .Decision "approved"}}<span class="badge ok">✓ Approved</span>{{else}}<span class="badge bad">✗ Denied</span>{{end}}{{if .Unchecked}} <span class="badge warn">⚠ Sample — not checked</span>{{end}}</p>
<dl class="facts">
<dt>Issuing country</dt><dd>{{.IssuingCountry}}</dd>
<dt>Passport expiry</dt><dd>{{dateWords .PassportExpiry}}{{if .Expired}} <span class="badge bad">Expired</span>{{end}}</dd>
<dt>Chip authentication</dt><dd>{{.ChipAuth}}</dd>
<dt>Uploaded</dt><dd><time datetime="{{.CreatedAt.Format "2006-01-02T15:04:05Z07:00"}}">{{.CreatedAt.Format "15:04:05"}}</time></dd>
</dl>
{{if eq .Decision "awaiting review"}}<form method="post" action="/demo/review/decision" class="actions"><input type="hidden" name="ref" value="{{.Ref}}"><button class="btn" name="decision" value="approve">Approve</button> <button class="btn secondary danger" name="decision" value="deny">Deny</button></form>
{{else}}<p class="note">Decided; waiting for the wallet's next check.</p>{{end}}
</li>
{{end}}</ul>
{{else}}
<p class="card empty">Nothing is awaiting review. New issuances appear here as wallets ask for them.</p>
{{end}}
<p class="note">Demo only: anyone who can reach this page can decide. It shows no names or document numbers.</p>
</main>
`+reviewScript+`
`+pageFoot)

// reviewScript checks the review status every three seconds and, when
// it changes, announces it and reloads the page — unless the operator
// is in the middle of a decision, when it offers a reload instead.
const reviewScript = `<script>
(function () {
	var live = document.getElementById("review-live");
	var pending = live.getAttribute("data-pending"), total = live.getAttribute("data-total");
	function poll() {
		fetch("/demo/review/status", {cache: "no-store"}).then(function (r) { return r.json(); }).then(function (s) {
			if (String(s.pending) === pending && String(s.total) === total) return setTimeout(poll, 3000);
			var more = s.pending - Number(pending);
			live.textContent = more > 0 ? more + (more === 1 ? " new issuance awaits" : " new issuances await") + " review." : "The list changed.";
			var active = document.activeElement;
			if (active && active.form) {
				var a = document.createElement("a");
				a.href = location.pathname;
				a.textContent = " Show it";
				live.appendChild(a);
				return;
			}
			setTimeout(function () { location.reload(); }, 1500);
		}).catch(function () { setTimeout(poll, 3000); });
	}
	setTimeout(poll, 3000);
})();
</script>`

// reviewCounts is what the review page polls: how many issuances await
// a decision, and how many are listed. Nothing about any passport.
type reviewCounts struct {
	Pending int `json:"pending"`
	Total   int `json:"total"`
}

func (a *App) reviewCounts(entries []ReviewEntry) reviewCounts {
	c := reviewCounts{Total: len(entries)}
	for _, e := range entries {
		if e.Decision == "awaiting review" {
			c.Pending++
		}
	}
	return c
}

func (a *App) handleReviewPage(w http.ResponseWriter, _ *http.Request) {
	entries := a.Reviews()
	renderPage(w, http.StatusOK, reviewTemplate, reviewPage{Header: a.header(pathReview), Entries: entries, Counts: a.reviewCounts(entries)}, true)
}

// handleReviewStatus answers the review page's polling.
func (a *App) handleReviewStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(headerCacheControl, noStore)
	w.Header().Set(headerContentType, "application/json")
	_ = json.NewEncoder(w).Encode(a.reviewCounts(a.Reviews()))
}

// handleReviewDecision records a decision. A cross-origin form post is
// refused, so another site can't decide through a visitor's browser.
func (a *App) handleReviewDecision(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		a.writeHTMLError(w, http.StatusForbidden, "cross-origin decision refused")
		return
	}
	if err := a.Review(r.FormValue("ref"), r.FormValue("decision") == "approve"); err != nil {
		a.writeHTMLError(w, http.StatusBadRequest, "unknown or already-decided review")
		return
	}
	http.Redirect(w, r, "/demo/review", http.StatusSeeOther)
}

// notifications records the wallets' Notification Requests (§11) for
// the /status page: the newest maxNotifications events.
type notifications struct {
	mu     sync.Mutex
	now    func() time.Time
	events []NotificationEvent
}

// NotificationEvent is one Notification Request a wallet sent.
type NotificationEvent struct {
	At          time.Time
	Event       oid4vci.NotificationEvent
	Description string
}

const maxNotifications = 50

// HandleNotification implements issuer.NotificationHandler.
func (n *notifications) HandleNotification(_ context.Context, _ string, event oid4vci.NotificationEvent, description string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.events = append([]NotificationEvent{{At: n.now(), Event: event, Description: description}}, n.events...)
	if len(n.events) > maxNotifications {
		n.events = n.events[:maxNotifications]
	}
	return nil
}

// Notifications lists the events wallets have sent, newest first.
func (a *App) Notifications() []NotificationEvent {
	a.notifications.mu.Lock()
	defer a.notifications.mu.Unlock()
	return slices.Clone(a.notifications.events)
}

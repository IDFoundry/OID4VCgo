package issuerapp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"sync"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
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

// add holds e for configID until a decision, returning its reference.
func (r *reviews) add(e passport.Evidence, configID string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("issuerapp: review reference: %w", err)
	}
	ref := base64.RawURLEncoding.EncodeToString(b[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	for k, v := range r.items {
		if now.Sub(v.createdAt) >= reviewLifetime {
			delete(r.items, k)
		}
	}
	if len(r.items) >= maxReviews {
		return "", errTooManyReviews
	}
	r.items[ref] = &review{evidence: e, configID: configID, createdAt: now}
	return ref, nil
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

// decide records an operator's decision on a pending review.
func (r *reviews) decide(ref string, approve bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.items[ref]
	if !ok || v.decision != reviewPending || r.now().Sub(v.createdAt) >= reviewLifetime {
		return errUnknownReview
	}
	v.decision = reviewDenied
	if approve {
		v.decision = reviewApproved
	}
	return nil
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
		})
	}
	slices.SortFunc(out, func(x, y ReviewEntry) int { return x.CreatedAt.Compare(y.CreatedAt) })
	return out
}

// Review records the operator's decision on the deferred issuance ref;
// the wallet's next poll carries it out.
func (a *App) Review(ref string, approve bool) error { return a.reviews.decide(ref, approve) }

// resolveDeferred is the Deferred Credential Endpoint's Resolve: on each
// poll it carries out the operator's decision on the transaction's
// review, if there is one yet. A review that's gone (expired, or lost
// to a restart) is denied, so the wallet stops polling.
func (a *App) resolveDeferred(ctx context.Context, _ issuer.Grant, transactionID string, tx issuer.DeferredTransactionRecord) error {
	rv, ok := a.reviews.get(tx.Reference)
	switch {
	case !ok, rv.decision == reviewDenied:
		a.reviews.remove(tx.Reference)
		return a.issuer.DenyDeferredCredential(ctx, transactionID)
	case rv.decision == reviewPending:
		return nil
	}
	opts := credential.Options{Now: a.now()}
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
			idx, err := a.statusList.allocate(credentialFormat(rv.configID), a.now())
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
	return nil
}

var reviewTemplate = template.Must(template.New("review").Parse(pageHead + `
<h1>Issuances awaiting review</h1>
<p>A passport uploaded for review isn't issued at once: the wallet is told to wait, and polls until an operator decides here. Its next poll then gets the credential, or a refusal.</p>
{{if .}}
<table>
<tr><th>Format</th><th>Issuing country</th><th>Passport expiry</th><th>Chip authentication evidence</th><th>Uploaded</th><th>Decision</th></tr>
{{range .}}
<tr><td><code>{{.Format}}</code></td><td>{{.IssuingCountry}}</td>
<td>{{.PassportExpiry}}{{if .Expired}} <span class="warn">expired</span>{{end}}</td>
<td>{{.ChipAuth}}</td>
<td>{{.CreatedAt.Format "15:04:05"}}</td>
<td>{{if eq .Decision "awaiting review"}}<form method="post" action="/review/decision"><input type="hidden" name="ref" value="{{.Ref}}"><button name="decision" value="approve">Approve</button> <button name="decision" value="deny">Deny</button></form>{{else}}{{.Decision}}; waiting for the wallet's poll{{end}}</td></tr>
{{end}}
</table>
{{else}}
<p>Nothing is awaiting review.</p>
{{end}}
<p class="note">Demo only: anyone who can reach this page can decide. It shows no names or document numbers.</p>
<p><a href="/">Issue another</a> · <a href="/status">Issued credentials</a></p>
` + pageFoot))

func (a *App) handleReviewPage(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = reviewTemplate.Execute(w, a.Reviews())
}

// handleReviewDecision records a decision. A cross-origin form post is
// refused, so another site can't decide through a visitor's browser.
func (a *App) handleReviewDecision(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.IssuerURL {
		writeHTMLError(w, http.StatusForbidden, "cross-origin decision refused")
		return
	}
	if err := a.Review(r.FormValue("ref"), r.FormValue("decision") == "approve"); err != nil {
		writeHTMLError(w, http.StatusBadRequest, "unknown or already-decided review")
		return
	}
	http.Redirect(w, r, "/review", http.StatusSeeOther)
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

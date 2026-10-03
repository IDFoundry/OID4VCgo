// Package webwallet is a browser front end for the passport-vdc demo
// wallet (walletapp): it shows the stored credentials, receives new ones
// from a credential offer, and — unlike the CLI — asks the holder before
// presenting, showing what the verifier asks for.
//
// It is a single-user demo on loopback: no login, and holder keys stored
// unencrypted, like the rest of walletapp. Every POST refuses a
// cross-origin request, and nothing is fetched on a GET, so another site
// can't make this wallet contact a server by linking to it.
package webwallet

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Config configures an App.
type Config struct {
	// WalletURL is this wallet's own base URL; its /callback is the
	// wallet's redirect URI, which the issuer must have registered.
	WalletURL string
	// Wallet configures receiving; its RedirectURI is set from
	// WalletURL.
	Wallet walletapp.Config
	// Store is where credentials are kept (shared with the CLI wallet).
	Store walletapp.Store
	// VerifierTrust decides which verifiers' requests are shown at all
	// (OpenID4VP §5.9.3) — see walletapp.LoadVerifierTrust.
	VerifierTrust wallet.VerifierTrust
}

// App is a running web wallet.
type App struct {
	cfg     Config
	handler http.Handler

	mu        sync.Mutex
	receiving *receiveOp                      // the one in-progress receive, if any
	pending   map[string]*pendingPresentation // consent screens awaiting a decision
	deferred  map[string]*deferredCredential  // credentials the issuer deferred, to poll
}

// deferredCredential is a credential the issuer deferred (OID4VCI 1.0
// §9), polled when the holder asks; it holds the access token in
// memory, so it doesn't survive a restart.
type deferredCredential struct {
	pending   *walletapp.Pending
	expiresAt time.Time
}

const (
	// deferredLifetime bounds how long a deferred credential is kept for
	// polling — the issuer's access token doesn't outlive it anyway.
	deferredLifetime = time.Hour
	// maxDeferred bounds how many are kept.
	maxDeferred = 20
)

type receiveOp struct {
	cancel context.CancelFunc
	// binding is the random value the browser that started the receive
	// holds in bindingCookie.
	binding  string
	authURL  chan string
	callback chan walletapp.Callback
	done     chan receiveResult
}

// bindingCookie binds a receive to the browser that started it: /callback
// completes the receive only from a browser holding its binding (RFC 9700
// §4.7), so another browser can't be made to complete it.
const bindingCookie = "passport_vdc_webwallet_receive"

type receiveResult struct {
	received []walletapp.Received
	pending  []*walletapp.Pending
	err      error
}

type pendingPresentation struct {
	prepared  *walletapp.Prepared
	expiresAt time.Time
}

// New builds an App.
func New(cfg Config) (*App, error) {
	if cfg.WalletURL == "" || cfg.Store.Dir == "" || cfg.VerifierTrust == nil {
		return nil, fmt.Errorf("webwallet: WalletURL, Store and VerifierTrust are required")
	}
	cfg.Wallet.RedirectURI = cfg.WalletURL + "/callback"
	a := &App{cfg: cfg, pending: map[string]*pendingPresentation{}, deferred: map[string]*deferredCredential{}}
	a.handler = a.routes()
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /receive", a.handleReceiveConfirm)
	mux.HandleFunc("POST /receive", a.sameOrigin(a.handleReceive))
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("GET /present", a.handlePresentConfirm)
	mux.HandleFunc("POST /present", a.sameOrigin(a.handlePresentConsent))
	mux.HandleFunc("POST /present/{id}", a.sameOrigin(a.handlePresentDecision))
	mux.HandleFunc("POST /deferred/{id}", a.sameOrigin(a.handleCheckDeferred))
	return mux
}

// webApprover hands the authorization URL to the browser handler and
// waits for the issuer's redirect back to /callback.
type webApprover struct {
	op  *receiveOp
	pin string // the PIN the holder typed with the offer, for a pre-authorized one
}

// PIN implements walletapp.PINApprover with the PIN the holder entered
// on the confirmation page.
func (w webApprover) PIN(context.Context, oid4vci.TxCode) (string, error) {
	if w.pin == "" {
		return "", errors.New("this offer needs the PIN the issuer gave you")
	}
	return w.pin, nil
}

func (w webApprover) Approve(ctx context.Context, authorizationURL string) (walletapp.Callback, error) {
	select {
	case w.op.authURL <- authorizationURL:
	case <-ctx.Done():
		return walletapp.Callback{}, ctx.Err()
	}
	select {
	case cb := <-w.op.callback:
		return cb, nil
	case <-ctx.Done():
		return walletapp.Callback{}, errors.New("timed out waiting for approval at the issuer")
	}
}

func (a *App) handleReceiveConfirm(w http.ResponseWriter, r *http.Request) {
	offer := r.URL.Query().Get("offer")
	issuer, preAuthorized := offerIssuer(offer)
	render(w, http.StatusOK, confirmReceiveTemplate, map[string]any{"Offer": offer, "Issuer": issuer, "PreAuthorized": preAuthorized})
}

// handleReceive starts receiving from an offer and sends the browser to
// the issuer's approval page.
func (a *App) handleReceive(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "malformed form")
		return
	}
	offer := strings.TrimSpace(r.PostForm.Get("offer"))
	if !strings.HasPrefix(offer, "openid-credential-offer://") {
		renderError(w, http.StatusBadRequest, "that isn't a credential offer link (openid-credential-offer://…)")
		return
	}

	binding, err := randomBinding()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "couldn't start receiving")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	op := &receiveOp{cancel: cancel, binding: binding, authURL: make(chan string), callback: make(chan walletapp.Callback, 1), done: make(chan receiveResult, 1)}
	a.mu.Lock()
	if a.receiving != nil {
		a.receiving.cancel() // a new receive replaces an abandoned one
	}
	a.receiving = op
	a.mu.Unlock()

	go func() {
		received, pending, err := walletapp.ReceiveDeferrable(ctx, a.cfg.Wallet, offer, webApprover{op: op, pin: strings.TrimSpace(r.PostForm.Get("pin"))})
		op.done <- receiveResult{received, pending, err}
	}()
	select {
	case authURL := <-op.authURL:
		http.SetCookie(w, &http.Cookie{
			Name: bindingCookie, Value: op.binding, Path: "/callback",
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, authURL, http.StatusSeeOther) // #nosec G710 -- the issuer's authorization URL, built by fapigo from discovered metadata
	case res := <-op.done:
		// A pre-authorized offer finishes here, with no trip to the
		// issuer's approval page.
		a.finishReceive(op)
		if res.err != nil {
			renderError(w, http.StatusBadGateway, "couldn't receive: "+res.err.Error())
			return
		}
		a.storeReceived(w, r, res)
	case <-time.After(30 * time.Second):
		a.finishReceive(op)
		renderError(w, http.StatusGatewayTimeout, "the issuer didn't respond")
	}
}

// handleCallback receives the issuer's redirect, completes the receive
// and stores the credentials. Only the browser that started the receive
// can complete it; the receive is claimed by its first callback, so a
// second one (a reload, a stray request) gets an error instead of
// waiting for a result that never comes.
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(bindingCookie)
	a.mu.Lock()
	op := a.receiving
	if op == nil || err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(op.binding)) != 1 {
		a.mu.Unlock()
		renderError(w, http.StatusBadRequest, "no credential is being received in this browser")
		return
	}
	a.receiving = nil
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: bindingCookie, Path: "/callback", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	op.callback <- walletapp.Callback{Query: r.URL.RawQuery}
	res := <-op.done
	a.finishReceive(op)
	if res.err != nil {
		renderError(w, http.StatusBadGateway, "receiving failed: "+res.err.Error())
		return
	}
	a.storeReceived(w, r, res)
}

// storeReceived stores what a receive got, keeps what the issuer
// deferred, and sends the browser home.
func (a *App) storeReceived(w http.ResponseWriter, r *http.Request, res receiveResult) {
	for _, rc := range res.received {
		if _, err := a.cfg.Store.Save(rc, time.Now()); err != nil {
			renderError(w, http.StatusInternalServerError, "couldn't store a credential")
			return
		}
	}
	for _, p := range res.pending {
		if err := a.addDeferred(p); err != nil {
			renderError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/?received=%d&deferred=%d", len(res.received), len(res.pending)), http.StatusSeeOther)
}

// addDeferred keeps p for the holder to poll from the home page.
func (a *App) addDeferred(p *walletapp.Pending) error {
	id, err := randomID()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, d := range a.deferred {
		if now.After(d.expiresAt) {
			delete(a.deferred, k)
		}
	}
	if len(a.deferred) >= maxDeferred {
		return errors.New("too many credentials are waiting for their issuers")
	}
	a.deferred[id] = &deferredCredential{pending: p, expiresAt: now.Add(deferredLifetime)}
	return nil
}

// handleCheckDeferred polls one deferred credential: it's stored once
// issued, dropped if denied, and otherwise left waiting.
func (a *App) handleCheckDeferred(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	d, ok := a.deferred[id]
	if ok && time.Now().After(d.expiresAt) {
		delete(a.deferred, id)
		ok = false
	}
	a.mu.Unlock()
	if !ok {
		renderError(w, http.StatusNotFound, "that credential is no longer waiting — receive it again")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	rc, err := d.pending.Poll(ctx)
	switch {
	case errors.Is(err, walletapp.ErrDenied):
		a.dropDeferred(id)
		http.Redirect(w, r, "/?denied=1", http.StatusSeeOther)
	case err != nil:
		renderError(w, http.StatusBadGateway, "checking failed: "+err.Error())
	case rc == nil:
		http.Redirect(w, r, "/?waiting=1", http.StatusSeeOther)
	default:
		if _, err := a.cfg.Store.Save(*rc, time.Now()); err != nil {
			renderError(w, http.StatusInternalServerError, "couldn't store the credential")
			return
		}
		a.dropDeferred(id)
		http.Redirect(w, r, "/?received=1", http.StatusSeeOther)
	}
}

func (a *App) dropDeferred(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.deferred, id)
}

// deferredCards lists the credentials waiting for their issuers.
func (a *App) deferredCards() []deferredCard {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	out := make([]deferredCard, 0, len(a.deferred))
	for id, d := range a.deferred {
		if now.Before(d.expiresAt) {
			out = append(out, deferredCard{ID: id, Format: d.pending.Format})
		}
	}
	slices.SortFunc(out, func(x, y deferredCard) int { return strings.Compare(x.Format, y.Format) })
	return out
}

func (a *App) finishReceive(op *receiveOp) {
	op.cancel()
	a.mu.Lock()
	if a.receiving == op {
		a.receiving = nil
	}
	a.mu.Unlock()
}

// sameOrigin refuses a request another site's page sent: one whose
// Origin isn't this wallet's. A request without Origin — from a
// non-browser client — is allowed.
func (a *App) sameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.WalletURL {
			renderError(w, http.StatusForbidden, "cross-origin request refused")
			return
		}
		next(w, r)
	}
}

// handlePresentConfirm shows a presentation request link and asks
// whether to review it. It fetches nothing: fetching the request
// happens on the POST that follows.
func (a *App) handlePresentConfirm(w http.ResponseWriter, r *http.Request) {
	link := strings.TrimSpace(r.URL.Query().Get("request"))
	if !strings.HasPrefix(link, "openid4vp://") {
		renderError(w, http.StatusBadRequest, "that isn't a presentation request link (openid4vp://…)")
		return
	}
	render(w, http.StatusOK, confirmPresentTemplate, map[string]string{"Request": link, "Host": requestHost(link)})
}

// handlePresentConsent verifies a presentation request and shows what
// it asks for. Nothing is sent until the holder chooses.
func (a *App) handlePresentConsent(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "malformed form")
		return
	}
	link := strings.TrimSpace(r.PostForm.Get("request"))
	if !strings.HasPrefix(link, "openid4vp://") {
		renderError(w, http.StatusBadRequest, "that isn't a presentation request link (openid4vp://…)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	prepared, err := walletapp.Prepare(ctx, link, a.cfg.Store, a.cfg.Wallet.HTTP, a.cfg.VerifierTrust)
	if err != nil {
		renderError(w, http.StatusBadRequest, err.Error())
		return
	}
	id, err := randomID()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "internal error")
		return
	}
	a.mu.Lock()
	for k, p := range a.pending {
		if time.Now().After(p.expiresAt) {
			delete(a.pending, k)
		}
	}
	a.pending[id] = &pendingPresentation{prepared: prepared, expiresAt: time.Now().Add(5 * time.Minute)}
	a.mu.Unlock()

	responseHost := prepared.ResponseURI
	if u, err := url.Parse(prepared.ResponseURI); err == nil {
		responseHost = u.Host
	}
	render(w, http.StatusOK, consentTemplate, consentPage{
		ID: id, VerifierName: prepared.VerifierName, VerifierID: prepared.VerifierClientID, ResponseHost: responseHost, Options: prepared.Options,
	})
}

// handlePresentDecision shares the chosen credential, or declines.
func (a *App) handlePresentDecision(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		renderError(w, http.StatusBadRequest, "malformed form")
		return
	}
	a.mu.Lock()
	p, ok := a.pending[r.PathValue("id")]
	delete(a.pending, r.PathValue("id"))
	a.mu.Unlock()
	if !ok || time.Now().After(p.expiresAt) {
		renderError(w, http.StatusBadRequest, "this request has expired — scan it again")
		return
	}
	if r.PostForm.Get("decision") != "share" {
		render(w, http.StatusOK, doneTemplate, map[string]string{"Message": "Declined — nothing was shared."})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	presented, err := p.prepared.Send(ctx, r.PostForm.Get("credential"))
	if err != nil {
		renderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if presented.RedirectURI != "" {
		// Same-device flow: back to the verifier's page (OpenID4VP §8.2).
		http.Redirect(w, r, presented.RedirectURI, http.StatusSeeOther) // #nosec G710 -- the verifier's redirect_uri, from its authenticated response; https checked in walletapp
		return
	}
	render(w, http.StatusOK, doneTemplate, map[string]string{
		"Message": "Shared " + strings.Join(presented.Credentials, ", ") + " with the verifier.",
	})
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	stored, err := a.cfg.Store.List()
	if err != nil {
		renderError(w, http.StatusInternalServerError, "couldn't read the wallet store")
		return
	}
	cards := make([]card, 0, len(stored))
	for i := len(stored) - 1; i >= 0; i-- { // newest first
		cards = append(cards, cardFor(stored[i]))
	}
	q := r.URL.Query()
	render(w, http.StatusOK, homeTemplate, homePage{
		Cards: cards, Received: q.Get("received"), Deferred: a.deferredCards(),
		Waiting: q.Get("waiting") != "", Denied: q.Get("denied") != "",
	})
}

// requestHost is the host a presentation request link's request_uri
// names, for the confirmation page ("" if it can't be read).
func requestHost(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(u.Query().Get("request_uri"))
	if err != nil {
		return ""
	}
	return ru.Host
}

// offerIssuer reads the credential_issuer from a by-value offer link,
// for the confirmation page ("" if it can't).
// offerIssuer reads a by-value offer link's issuer, and whether it's a
// pre-authorized code offer — "" and false for anything else, including
// a by-reference offer this page doesn't fetch.
func offerIssuer(link string) (issuer string, preAuthorized bool) {
	u, err := url.Parse(link)
	if err != nil {
		return "", false
	}
	var offer oid4vci.CredentialOffer
	if json.Unmarshal([]byte(u.Query().Get("credential_offer")), &offer) != nil {
		return "", false
	}
	return offer.CredentialIssuer, offer.Grants != nil && offer.Grants.PreAuthorizedCode != nil
}

func randomID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// randomBinding returns a random value binding a receive to a browser.
func randomBinding() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

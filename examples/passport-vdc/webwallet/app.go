// Package webwallet is a browser front end for the passport-vdc demo
// wallet (walletapp): it shows the stored credentials, receives new ones
// from a credential offer, and — unlike the CLI — asks the holder before
// presenting, showing what the verifier asks for.
//
// It is a single-user demo on loopback: no login, no CSRF protection,
// and holder keys stored unencrypted, like the rest of walletapp.
package webwallet

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
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
}

// App is a running web wallet.
type App struct {
	cfg     Config
	handler http.Handler

	mu        sync.Mutex
	receiving *receiveOp                      // the one in-progress receive, if any
	pending   map[string]*pendingPresentation // consent screens awaiting a decision
}

type receiveOp struct {
	cancel   context.CancelFunc
	authURL  chan string
	callback chan string
	done     chan receiveResult
}

type receiveResult struct {
	received []walletapp.Received
	err      error
}

type pendingPresentation struct {
	prepared  *walletapp.Prepared
	expiresAt time.Time
}

// New builds an App.
func New(cfg Config) (*App, error) {
	if cfg.WalletURL == "" || cfg.Store.Dir == "" {
		return nil, fmt.Errorf("webwallet: WalletURL and Store are required")
	}
	cfg.Wallet.RedirectURI = cfg.WalletURL + "/callback"
	a := &App{cfg: cfg, pending: map[string]*pendingPresentation{}}
	a.handler = a.routes()
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.handler.ServeHTTP(w, r) }

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.handleHome)
	mux.HandleFunc("GET /receive", a.handleReceiveConfirm)
	mux.HandleFunc("POST /receive", a.handleReceive)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("GET /present", a.handlePresentConsent)
	mux.HandleFunc("POST /present/{id}", a.handlePresentDecision)
	return mux
}

// webApprover hands the authorization URL to the browser handler and
// waits for the issuer's redirect back to /callback.
type webApprover struct{ op *receiveOp }

func (w webApprover) Approve(ctx context.Context, authorizationURL string) (string, error) {
	select {
	case w.op.authURL <- authorizationURL:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	select {
	case q := <-w.op.callback:
		return q, nil
	case <-ctx.Done():
		return "", errors.New("timed out waiting for approval at the issuer")
	}
}

func (a *App) handleReceiveConfirm(w http.ResponseWriter, r *http.Request) {
	offer := r.URL.Query().Get("offer")
	render(w, http.StatusOK, confirmReceiveTemplate, map[string]string{"Offer": offer, "Issuer": offerIssuer(offer)})
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	op := &receiveOp{cancel: cancel, authURL: make(chan string), callback: make(chan string, 1), done: make(chan receiveResult, 1)}
	a.mu.Lock()
	if a.receiving != nil {
		a.receiving.cancel() // a new receive replaces an abandoned one
	}
	a.receiving = op
	a.mu.Unlock()

	go func() {
		received, err := walletapp.Receive(ctx, a.cfg.Wallet, offer, webApprover{op})
		op.done <- receiveResult{received, err}
	}()
	select {
	case u := <-op.authURL:
		http.Redirect(w, r, u, http.StatusSeeOther) // #nosec G710 -- the issuer's authorization URL, built by fapigo from discovered metadata
	case res := <-op.done:
		a.finishReceive(op)
		renderError(w, http.StatusBadGateway, "couldn't start receiving: "+res.err.Error())
	case <-time.After(30 * time.Second):
		a.finishReceive(op)
		renderError(w, http.StatusGatewayTimeout, "the issuer didn't respond")
	}
}

// handleCallback receives the issuer's redirect, completes the receive
// and stores the credentials.
func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	op := a.receiving
	a.mu.Unlock()
	if op == nil {
		renderError(w, http.StatusBadRequest, "no credential is being received")
		return
	}
	op.callback <- r.URL.RawQuery
	res := <-op.done
	a.finishReceive(op)
	if res.err != nil {
		renderError(w, http.StatusBadGateway, "receiving failed: "+res.err.Error())
		return
	}
	for _, rc := range res.received {
		if _, err := a.cfg.Store.Save(rc, time.Now()); err != nil {
			renderError(w, http.StatusInternalServerError, "couldn't store a credential")
			return
		}
	}
	http.Redirect(w, r, fmt.Sprintf("/?received=%d", len(res.received)), http.StatusSeeOther)
}

func (a *App) finishReceive(op *receiveOp) {
	op.cancel()
	a.mu.Lock()
	if a.receiving == op {
		a.receiving = nil
	}
	a.mu.Unlock()
}

// handlePresentConsent verifies a presentation request and shows what
// it asks for. Nothing is sent until the holder chooses.
func (a *App) handlePresentConsent(w http.ResponseWriter, r *http.Request) {
	link := strings.TrimSpace(r.URL.Query().Get("request"))
	if !strings.HasPrefix(link, "openid4vp://") {
		renderError(w, http.StatusBadRequest, "that isn't a presentation request link (openid4vp://…)")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	prepared, err := walletapp.Prepare(ctx, link, a.cfg.Store, a.cfg.Wallet.HTTP)
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
		ID: id, VerifierID: prepared.VerifierClientID, ResponseHost: responseHost, Options: prepared.Options,
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
	presented, err := p.prepared.Send(ctx, r.PostForm.Get("format"))
	if err != nil {
		renderError(w, http.StatusBadGateway, err.Error())
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
	render(w, http.StatusOK, homeTemplate, homePage{Cards: cards, Received: r.URL.Query().Get("received")})
}

// offerIssuer reads the credential_issuer from a by-value offer link,
// for the confirmation page ("" if it can't).
func offerIssuer(link string) string {
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	var offer struct {
		CredentialIssuer string `json:"credential_issuer"`
	}
	if json.Unmarshal([]byte(u.Query().Get("credential_offer")), &offer) != nil {
		return ""
	}
	return offer.CredentialIssuer
}

func randomID() (string, error) {
	var b [18]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

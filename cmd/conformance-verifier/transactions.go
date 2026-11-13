package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"sync"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// newHandler builds the HTTP handler Config.Engine names, and the
// client_id the Verifier behind it serves as.
func newHandler(cfg Config) (http.Handler, string, error) {
	if cfg.Engine != engineTransactions {
		s, err := newServer(cfg)
		if err != nil {
			return nil, "", err
		}
		return s.routes(), s.v.ClientID(), nil
	}
	t, err := newTxServer(cfg)
	if err != nil {
		return nil, "", err
	}
	return t.routes(), t.v.ClientID(), nil
}

// bindingCookie holds the browser binding (verifier.BeginOptions) of
// the request the browser last began at /authorize: the redirect back
// from the Wallet, and the result page, read it.
const bindingCookie = "__Host-verifier-binding"

// bindingEntropyBytes is the browser binding's size before encoding.
const bindingEntropyBytes = 32

// txServer is the transactions engine: verifier.Transactions serves
// the presentation flow end to end, as a deployment's Verifier does.
// Every request is a same-device one (the suite's emulated Wallet is
// reached through the browser that asked, and HAIP 1.0 §5.1 requires
// the response endpoint's redirect_uri), bound to that browser by a
// cookie. Transactions' own handlers serve the Request Object and the
// response endpoint; this binary adds only what a Verifier's frontend
// adds: /authorize begins a request, /result takes the Wallet's
// redirect back and redeems its response_code, and /result/{id} shows
// the bound browser where its request is.
type txServer struct {
	cfg   Config
	v     *verifier.Verifier
	txs   *verifier.Transactions
	query dcql.Query

	// refusals is each request's latest refusal, as refusalLines
	// gives it (OnRefused): the result page shows it under LastError,
	// which records only a fixed description of its Reason, so the
	// drivers can grade why the Verifier refused, not only that it
	// did. A test harness's page: a deployment shows LastError alone.
	refusals sync.Map // request ID -> []string
}

// newTxServer builds the transactions engine cfg describes: under
// verifier.AssuranceProduction, over the sealed SQLite store
// openProductionStore opens, when cfg.Production is set, and otherwise
// under AssuranceDevelopment over an in-memory store.
func newTxServer(cfg Config) (*txServer, error) {
	assurance := verifier.AssuranceDevelopment
	var store verifier.TransactionStore = storage.NewVerifierTransactionStore()
	if cfg.Production != nil {
		assurance = verifier.AssuranceProduction
		var err error
		if store, err = openProductionStore(*cfg.Production); err != nil {
			return nil, err
		}
	}
	v, err := newVerifier(cfg, assurance)
	if err != nil {
		return nil, err
	}
	issuerKeys, mdocIssuerKeys, err := cfg.issuerKeyResolvers()
	if err != nil {
		return nil, err
	}
	status, err := cfg.statusPolicy()
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	query, err := (&server{cfg: cfg}).buildQuery()
	if err != nil {
		return nil, err
	}
	t := &txServer{cfg: cfg, v: v, query: query}
	txCfg := verifier.TransactionsConfig{
		RequestURIBase: cfg.BaseURL + "/request",
		// Each link asks for request_uri_method=post (OpenID4VP 1.0
		// §5.10), as the default engine's do: the suite's
		// request-uri-method-post module runs only for a request that
		// does.
		RequestURIMethodPost: true,
		RedirectURI:          cfg.BaseURL + "/result",
		Verify: verifier.VerifyResponseRequest{
			IssuerKeys: issuerKeys, MdocIssuerKeys: mdocIssuerKeys,
			MaxKeyBindingAge: maxKeyBindingAge,
			IssuerAuthorized: cfg.issuerAuthorized(),
		},
		OnRefused: func(_ context.Context, id string, err error) {
			// Quoted: its text may carry values the answer's sender chose.
			log.Printf("transaction %s: answer refused: %q", id, err.Error())
			t.refusals.Store(id, refusalLines(err))
		},
	}
	setStatusCheck(&txCfg, status, assurance)
	if t.txs, err = verifier.NewTransactions(v, store, txCfg); err != nil {
		return nil, err
	}
	return t, nil
}

// issuerAuthorized is the issuer authorization
// (VerifyResponseRequest.IssuerAuthorized) of an issuer this
// configuration trusts: the type the query asks for, its vct or
// doctype, and no other. Each run trusts one issuer CA (or IACA) for
// that one type.
func (c Config) issuerAuthorized() func(context.Context, verifier.IssuerAuthorization) error {
	allowed := c.VCT
	if c.CredentialFormat == "mso_mdoc" {
		allowed = c.Doctype
	}
	return func(_ context.Context, a verifier.IssuerAuthorization) error {
		if len(a.MatchedTypes) == 0 {
			return errors.New("the credential matched no requested type")
		}
		for _, t := range a.MatchedTypes {
			if t != allowed {
				return fmt.Errorf("the issuer isn't authorized for %q", t)
			}
		}
		return nil
	}
}

// setStatusCheck sets txCfg's status decision: status as its Status,
// or, without a status policy, NoStatusCheck. Under
// AssuranceProduction, NewTransactions refuses a Status whose Fetcher
// may reach private addresses (statuslist.Fetcher.HardenedForProduction),
// and the OIDF suite serves its status lists from its own container,
// on the private Docker network this binary shares with it: there, the
// same policy runs as the Accept instead (verifier.RequireValidStatus's
// documented alternative, whose Fetcher is the caller's to harden),
// checking exactly what Status would, before the answer completes.
func setStatusCheck(txCfg *verifier.TransactionsConfig, status *verifier.StatusPolicy, assurance verifier.AssuranceLevel) {
	switch {
	case status == nil:
		txCfg.NoStatusCheck = true
	case assurance == verifier.AssuranceProduction && !status.Checker.Fetcher.HardenedForProduction():
		log.Print("status lists are fetched from private addresses, which TransactionsConfig.Status refuses under production assurance: the status policy runs as the Accept")
		txCfg.NoStatusCheck = true
		txCfg.Accept = func(ctx context.Context, _ string, result verifier.VerifyResponseResult) error {
			return status.Check(ctx, result.Credentials...)
		}
	default:
		txCfg.Status = status
	}
}

// routes is the transactions engine's HTTP API.
func (t *txServer) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", t.handleAuthorize)
	// No method in the patterns: Transactions' handlers answer the
	// methods they don't support themselves (405).
	requestObjects := t.txs.RequestObjectHandler()
	mux.HandleFunc("/request/{id}", func(w http.ResponseWriter, r *http.Request) {
		// How the Wallet fetched it, which an interop run checks
		// (OpenID4VP 1.0 §5.10). Only a method the handler serves is
		// named: the sender chose the rest of the request.
		method := "another method"
		switch r.Method {
		case http.MethodGet:
			method = http.MethodGet
		case http.MethodPost:
			method = http.MethodPost
		}
		log.Printf("request object fetched with %s", method)
		requestObjects.ServeHTTP(w, r)
	})
	mux.Handle("/response", t.txs.ResponseHandler())
	mux.HandleFunc("GET /result", t.handleRedirectBack)
	mux.HandleFunc("GET /result/{id}", t.handleResult)
	return mux
}

// handleAuthorize begins a same-device request for the configured
// query, bound to the calling browser by a fresh random binding in
// bindingCookie, and redirects it to the request's openid4vp:// link.
func (t *txServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	buf := make([]byte, bindingEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	binding := base64.RawURLEncoding.EncodeToString(buf)
	begun, err := t.txs.BeginWith(r.Context(), verifier.BeginOptions{Query: t.query, BrowserBinding: binding, SameDevice: true})
	if err != nil {
		log.Printf("begin: %v", err)
		http.Error(w, "the request couldn't be begun", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: bindingCookie, Value: binding, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	log.Printf("transaction %s: begun", begun.ID)
	http.Redirect(w, r, begun.Link, http.StatusFound)
}

// browserBinding is the binding r's browser holds, or "".
func browserBinding(r *http.Request) string {
	c, err := r.Cookie(bindingCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// handleRedirectBack is the redirect_uri the Wallet sends the browser
// back to (TransactionsConfig.RedirectURI): it redeems the
// response_code for the bound browser's result (Transactions.Redeem)
// and shows it.
func (t *txServer) handleRedirectBack(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if code := q.Get("error"); code != "" && q.Get("response_code") == "" {
		writeResultPage(w, http.StatusOK, "Verification failed", "the wallet answered with an error: "+code)
		return
	}
	view, err := t.txs.Redeem(r.Context(), q.Get("response_code"), browserBinding(r))
	if err != nil {
		log.Printf("redeem: %v", err)
		writeResultPage(w, http.StatusForbidden, "No result", "no result for this response_code in this browser")
		return
	}
	log.Printf("transaction %s: result redeemed", view.ID)
	t.writeView(w, view)
}

// handleResult shows the bound browser its request's progress
// (Transactions.Lookup): what the suite's
// "verifier_verification_result_screenshot" stands for, and what the
// drivers grade the Verifier's own outcome by.
func (t *txServer) handleResult(w http.ResponseWriter, r *http.Request) {
	view, err := t.txs.Lookup(r.Context(), r.PathValue("id"), browserBinding(r))
	switch {
	case errors.Is(err, verifier.ErrTransactionUnknown):
		http.NotFound(w, r)
		return
	case errors.Is(err, verifier.ErrWrongBrowser):
		writeResultPage(w, http.StatusForbidden, "No result", "this request belongs to another browser")
		return
	case err != nil:
		log.Printf("lookup: %v", err)
		http.Error(w, "the request couldn't be read", http.StatusInternalServerError)
		return
	}
	t.writeView(w, view)
}

// writeView renders view as the result page: "Verification succeeded"
// with its claims once it's done; "Verification failed" for a request
// whose latest answer was refused (it stays open: Transactions leaves a
// refused request pending), or that ended without a result; "Pending"
// otherwise, including a verified answer whose browser hasn't been
// back with its response_code yet.
func (t *txServer) writeView(w http.ResponseWriter, view verifier.TransactionView) {
	switch view.Status {
	case verifier.TransactionDone:
		var claims []string
		if view.Result != nil {
			for _, cred := range view.Result.Credentials {
				c, _ := json.MarshalIndent(cred.Claims, "", "  ")
				claims = append(claims, cred.CredentialQueryID+": "+string(c))
			}
		}
		writeResultPage(w, http.StatusOK, "Verification succeeded", claims...)
	case verifier.TransactionClosed, verifier.TransactionExpired:
		writeResultPage(w, http.StatusOK, "Verification failed", fmt.Sprintf("the request ended without a result (status %d): %s", view.Status, view.LastError))
	default:
		if view.Status == verifier.TransactionPending && view.LastError != "" {
			lines := []string{view.LastError}
			if refusal, ok := t.refusals.Load(view.ID); ok {
				lines = append(lines, refusal.([]string)...)
			}
			writeResultPage(w, http.StatusOK, "Verification failed", lines...)
			return
		}
		writeResultPage(w, http.StatusOK, "Pending", fmt.Sprintf("request %s has no verified result yet", view.ID))
	}
}

// refusalLines is how a result page reports err, a refused answer: its
// verifier.Reason, on a line of its own as "reason: <reason>" when it
// carries one, and its text.
func refusalLines(err error) []string {
	var verr *verifier.Error
	if errors.As(err, &verr) {
		return []string{refusalReasonPrefix + string(verr.Reason()), err.Error()}
	}
	return []string{err.Error()}
}

// refusalReasonPrefix starts the result page line naming a refusal's
// verifier.Reason.
const refusalReasonPrefix = "reason: "

// writeResultPage writes a plain HTML page headed heading, each of
// lines escaped in its own <pre>.
func writeResultPage(w http.ResponseWriter, status int, heading string, lines ...string) {
	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<html><body><h1>%s</h1>", html.EscapeString(heading))
	for _, line := range lines {
		_, _ = fmt.Fprintf(w, "<pre>%s</pre>", html.EscapeString(line))
	}
	_, _ = fmt.Fprint(w, "</body></html>")
}

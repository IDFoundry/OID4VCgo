package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

const sessionIDEntropyBytes = 16

const contentTypeHeader = "Content-Type"

// maxKeyBindingAge is this binary's own Key Binding JWT freshness
// policy (verifier.VerifyResponseRequest.MaxKeyBindingAge) — not a
// spec-mandated value (OID4VP/HAIP leave the exact bound to each
// Verifier's own policy, the same way a nonce/clock-skew window is a
// relying party's own choice), just a generous bound relative to how
// quickly this binary's own session lifecycle actually completes
// (request_uri fetch through direct_post.jwt response, all within one
// suite-driven module run, always well under a minute).
const maxKeyBindingAge = 5 * time.Minute

func newSessionID() (string, error) {
	buf := make([]byte, sessionIDEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// server bundles the dependencies every handler needs.
type server struct {
	cfg            Config
	v              *verifier.Verifier
	sessions       *sessionStore
	issuerKeys     verifier.SDJWTVCIssuerKeyResolver
	mdocIssuerKeys verifier.MdocIssuerKeyResolver
	// status is Config.statusPolicy's: nil checks no status.
	status *verifier.StatusPolicy
}

// routes is this binary's HTTP API. The /dcapi/ routes answer only when
// Config.DCAPIOrigins is set.
func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /request/{id}", s.handleRequestObject)
	mux.HandleFunc("POST /request/{id}", s.handleRequestObject)
	mux.HandleFunc("POST /response", s.handleResponse)
	mux.HandleFunc("GET /result/{id}", s.handleResult)
	mux.HandleFunc("GET /result/{id}/redeem", s.handleRedeem)
	mux.HandleFunc("POST /dcapi/request", s.handleDCAPIRequest)
	mux.HandleFunc("POST /dcapi/response/{id}", s.handleDCAPIResponse)
	return mux
}

// buildQuery constructs the DCQL query every session asks — a single
// Credential Query, no credential_sets/claim_sets: this binary's job
// is exercising VerifyResponse's own core verification path for
// whichever one format cfg.CredentialFormat selects, not every DCQL
// selection permutation or both formats in one run.
func (s *server) buildQuery() (dcql.Query, error) {
	switch s.cfg.CredentialFormat {
	case "", "dc+sd-jwt":
		return s.buildSDJWTVCQuery()
	case "mso_mdoc":
		return s.buildMdocQuery()
	default:
		return dcql.Query{}, fmt.Errorf("build dcql query: unsupported credential_format %q", s.cfg.CredentialFormat)
	}
}

func (s *server) buildSDJWTVCQuery() (dcql.Query, error) {
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{s.cfg.VCT}})
	if err != nil {
		return dcql.Query{}, fmt.Errorf("build dcql meta: %w", err)
	}
	claims := make([]dcql.ClaimsQuery, len(s.cfg.Claims))
	for i, name := range s.cfg.Claims {
		claims[i] = dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(name)}}
	}
	return dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{ID: "cred1", Format: "dc+sd-jwt", Meta: meta, Claims: claims},
		},
	}, nil
}

// buildMdocQuery is buildSDJWTVCQuery's own "mso_mdoc" counterpart —
// each claim path is namespace-then-element (Appendix B.2.4), unlike
// dc+sd-jwt's flat top-level claim names, so every cfg.MdocClaims
// entry is paired with the one cfg.Namespace this binary asks about.
func (s *server) buildMdocQuery() (dcql.Query, error) {
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: s.cfg.Doctype})
	if err != nil {
		return dcql.Query{}, fmt.Errorf("build dcql meta: %w", err)
	}
	claims := make([]dcql.ClaimsQuery, len(s.cfg.MdocClaims))
	for i, name := range s.cfg.MdocClaims {
		claims[i] = dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey(s.cfg.Namespace), dcql.PathKey(name)}}
	}
	return dcql.Query{
		Credentials: []dcql.CredentialQuery{
			{ID: "cred1", Format: "mso_mdoc", Meta: meta, Claims: claims},
		},
	}, nil
}

// handleAuthorize starts a new session — the DCQL query it will ask
// for is fixed now, but the Authorization Request itself isn't built
// and signed yet (see session.ensureBuilt's own doc comment for why:
// a POST fetch of request_uri can carry a wallet_nonce that must be
// embedded in the signed object, and that's only knowable once the
// fetch happens). It redirects the caller (the suite's own browser,
// playing Wallet) to an "openid4vp://" URL carrying this Verifier's
// own client_id, the request_uri the Wallet fetches next, and
// request_uri_method=post (§5.10) advertising that this binary
// supports fetching it via POST as well as the default GET.
//
// An interop run picks the request_uri_method with the query parameter
// of the same name: "post" (the default), "get", or "none" to leave it
// out (§5.10: the Wallet then fetches with GET).
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Query().Get("request_uri_method")
	switch method {
	case "":
		method = "post"
	case "post", "get":
	case "none":
		method = ""
	default:
		http.Error(w, `request_uri_method must be "post", "get" or "none"`, http.StatusBadRequest)
		return
	}
	query, err := s.buildQuery()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, err := newSessionID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sessions.put(&session{id: id, query: query, createdAt: time.Now()})

	requestURI := s.cfg.BaseURL + "/request/" + id
	params := url.Values{
		"client_id":   {s.v.ClientID()},
		"request_uri": {requestURI},
	}
	if method != "" {
		params.Set("request_uri_method", method)
	}
	deepLink := "openid4vp://?" + params.Encode()
	log.Printf("session %s: created, request_uri=%s", id, requestURI)
	http.Redirect(w, r, deepLink, http.StatusFound)
}

// handleRequestObject builds (on first fetch) or replays (on any
// later fetch) the signed Request Object JWS for one session, per
// §5.10's own request_uri content type. A GET fetch (§5) carries no
// body; a POST fetch (§5.10) may carry a form-encoded wallet_nonce,
// which — only on the fetch that actually triggers the build — ends
// up embedded in the signed object per §5.10.1. wallet_metadata is
// accepted (so a POST with it doesn't fail) and recorded with the rest
// of the fetch (see requestFetch), but unused: this binary's own
// encryption/algorithm support is fixed by its own Config, not
// negotiated per-request.
func (s *server) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := s.sessions.get(id)
	if !ok || sess.dcapi {
		http.NotFound(w, r)
		return
	}

	fetch := requestFetch{Method: r.Method, Accept: r.Header.Get("Accept"), ContentType: r.Header.Get(contentTypeHeader)}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fetch.WalletNonce = r.PostForm.Get("wallet_nonce")
		fetch.WalletMetadata = r.PostForm.Get("wallet_metadata")
	}

	requestObject, err := sess.ensureBuilt(s.v, fetch)
	if err != nil {
		http.Error(w, fmt.Sprintf("build authorization request: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set(contentTypeHeader, "application/oauth-authz-req+jwt")
	_, _ = w.Write([]byte(requestObject)) //nolint:gosec // not XSS-exploitable: Content-Type is a compact JWS (dot-separated base64url segments), never text/html, regardless of walletNonce's own taint
}

// handleResponse receives the direct_post.jwt response (§8.3.1) at
// this Verifier's own fixed response_uri, correlates it to a pending
// session by trying each one's decryptionKey (see sessionStore's own
// doc comment for why), verifies it, and replies with the HAIP-
// required "redirect_uri" JSON body pointing at that session's own
// human-readable result page, with a response_code (§8.2) that
// handleRedeem releases the result for. A response that matches no
// pending session (a replay of an answered one among them) is refused,
// and so, with Config.RejectUnverifiedResponses, is a presentation that
// fails verification.
func (s *server) handleResponse(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	responseJWE := r.FormValue("response")
	if responseJWE == "" {
		http.Error(w, "missing response parameter", http.StatusBadRequest)
		return
	}

	var matched *session
	var parsed verifier.ParsedResponse
	var walletErr *verifier.ResponseError
	for _, sess := range s.sessions.pendingDecryptionKeys() {
		p, err := s.v.ParseDirectPostJWTResponse(responseJWE, sess.decryptionKey)
		if err == nil {
			matched, parsed = sess, p
			break
		}
		var re *verifier.ResponseError
		if errors.As(err, &re) {
			matched, walletErr = sess, re
			break
		}
	}
	if matched == nil {
		http.Error(w, "response did not decrypt against any pending session", http.StatusBadRequest)
		return
	}

	responseCode, err := newSessionID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	matched.mu.Lock()
	defer matched.mu.Unlock()
	// Another response to the same request may have been taken between
	// pendingDecryptionKeys and here: only the first is verified.
	if matched.done {
		http.Error(w, "the request has already been answered", http.StatusBadRequest)
		return
	}
	matched.done = true
	matched.responseCode = responseCode
	if walletErr != nil {
		matched.failErr = walletErr
		log.Printf("session %s: the wallet answered with an error: %v", matched.id, walletErr)
	} else {
		s.verify(r, matched, parsed, "")
		if matched.failErr != nil && s.cfg.RejectUnverifiedResponses {
			// The outcome stays on the result page, for the run's logs.
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error":             "invalid_request",
				"error_description": "the presentation was not verified",
			})
			return
		}
	}

	// The response_code (§8.2) lets the browser the Wallet redirects
	// redeem the result, as a same-device flow's frontend would.
	w.Header().Set(contentTypeHeader, "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": s.cfg.BaseURL + "/result/" + matched.id + "?" + url.Values{"response_code": {responseCode}}.Encode(),
	})
}

// verify verifies sess's response, parsed, and records the outcome in
// sess, whose mu the caller holds. origin is the Digital Credentials
// API request's origin, or "" for a redirect-flow response.
func (s *server) verify(r *http.Request, sess *session, parsed verifier.ParsedResponse, origin string) {
	req := verifier.VerifyResponseRequest{
		Query: sess.query, Response: parsed, ExpectedNonce: sess.nonce,
		IssuerKeys: s.issuerKeys, MdocIssuerKeys: s.mdocIssuerKeys,
		ResponseEncryptionKey: sess.decryptionKey,
		MaxKeyBindingAge:      maxKeyBindingAge,
		// Config.StatusListTrustAnchorsPEM turns the status check on,
		// as the suite's runs and the interop runs do; without it, no
		// status check, decided explicitly. A deployment sets Status
		// (a verifier.StatusPolicy), which runs before any Accept.
		Status:        s.status,
		NoStatusCheck: s.status == nil,
	}
	if origin != "" {
		req.Origin, req.ExpectedOrigins = origin, sess.expectedOrigins
	}
	result, err := s.v.VerifyResponse(r.Context(), req)
	if err != nil {
		sess.failErr = err
		// The suite grades from a screenshot of the result page, so
		// the outcome is logged too, for the run's artifacts.
		log.Printf("session %s: response not verified: %v", sess.id, err)
		return
	}
	sess.result = result.Credentials
	log.Printf("session %s: response verified: %d credential(s)", sess.id, len(result.Credentials))
}

// outcome is a session's result as JSON: what handleRedeem and
// handleDCAPIResponse answer with.
type outcome struct {
	// Status is "verified", "failed" or "pending".
	Status string `json:"status"`
	// Error is why it failed.
	Error string `json:"error,omitempty"`
	// Credentials are the verified credentials' disclosed claims, by
	// Credential Query ID.
	Credentials map[string]map[string]any `json:"credentials,omitempty"`
	// RequestURIFetch is how the Wallet fetched the Request Object of a
	// redirect-flow request.
	RequestURIFetch *requestFetch `json:"request_uri_fetch,omitempty"`
}

// outcomeOf is sess's outcome; the caller holds sess.mu.
func outcomeOf(sess *session) outcome {
	var o outcome
	if !sess.dcapi {
		o.RequestURIFetch = &sess.fetch
	}
	switch {
	case !sess.done:
		o.Status = "pending"
	case sess.failErr != nil:
		o.Status, o.Error = "failed", sess.failErr.Error()
	default:
		o.Status = "verified"
		o.Credentials = make(map[string]map[string]any, len(sess.result))
		for _, cred := range sess.result {
			o.Credentials[cred.CredentialQueryID] = cred.Claims
		}
	}
	return o
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set(contentTypeHeader, "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// handleRedeem releases one session's outcome, as JSON, to the bearer
// of the response_code handleResponse returned in its redirect_uri,
// once: a same-device flow's result goes only to the browser the
// Wallet redirected (§8.2, §13.3).
func (s *server) handleRedeem(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	code := r.URL.Query().Get("response_code")
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.responseCode == "" || sess.redeemed || subtle.ConstantTimeCompare([]byte(code), []byte(sess.responseCode)) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "no result for this response_code"})
		return
	}
	sess.redeemed = true
	writeJSON(w, http.StatusOK, outcomeOf(sess))
}

// maxDCAPIResponseBytes bounds the Digital Credentials API answer
// handleDCAPIResponse reads.
const maxDCAPIResponseBytes = verifier.MaxDCAPIResponseBytes

// dcAPIRequest is handleDCAPIRequest's answer: the request a page
// passes to navigator.credentials.get, and the session id it posts the
// answer back under.
type dcAPIRequest struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Data     struct {
		Request string `json:"request"`
	} `json:"data"`
}

// handleDCAPIRequest starts a Digital Credentials API session for the
// page origin names, one of Config.DCAPIOrigins, standing in for the
// Verifier's page: a signed request (Appendix A.3.2.1), for the
// "openid4vp-v1-signed" protocol.
func (s *server) handleDCAPIRequest(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.DCAPIOrigins) == 0 {
		http.NotFound(w, r)
		return
	}
	origin := r.URL.Query().Get("origin")
	if !slices.Contains(s.cfg.DCAPIOrigins, origin) {
		http.Error(w, "origin isn't one of dc_api_origins", http.StatusBadRequest)
		return
	}
	query, err := s.buildQuery()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	id, err := newSessionID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	built, err := s.v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: s.cfg.DCAPIOrigins,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("build authorization request: %v", err), http.StatusInternalServerError)
		return
	}
	s.sessions.put(&session{
		id: id, query: query, createdAt: time.Now(), built: true,
		requestObject: built.RequestObject, nonce: built.Nonce, decryptionKey: built.ResponseDecryptionKey,
		dcapi: true, origin: origin, expectedOrigins: built.ExpectedOrigins,
	})
	// The origin isn't logged: it's the caller's.
	log.Printf("session %s: created, Digital Credentials API", id)
	answer := dcAPIRequest{ID: id, Protocol: "openid4vp-v1-signed"}
	answer.Data.Request = built.RequestObject
	writeJSON(w, http.StatusOK, answer)
}

// handleDCAPIResponse verifies the answer the Digital Credentials API
// gave a session's page (its data object: {"response": JWE}, or an
// unencrypted {"error": ...}), as the page posts it back, and answers
// with the outcome. The response is verified against the session's own
// origin, never one the HTTP request names.
func (s *server) handleDCAPIResponse(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.sessions.get(r.PathValue("id"))
	if !ok || !sess.dcapi {
		http.NotFound(w, r)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDCAPIResponseBytes+1))
	if err != nil || len(body) > maxDCAPIResponseBytes {
		http.Error(w, "unreadable or oversized response", http.StatusBadRequest)
		return
	}
	var answer struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal(body, &answer); err != nil {
		http.Error(w, "the response isn't a JSON object", http.StatusBadRequest)
		return
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.done {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "the request has already been answered"})
		return
	}
	sess.done = true
	switch {
	case answer.Response != "":
		parsed, err := s.v.ParseDirectPostJWTResponse(answer.Response, sess.decryptionKey)
		if err != nil {
			sess.failErr = err
			log.Printf("session %s: response not parsed: %v", sess.id, err)
			break
		}
		s.verify(r, sess, parsed, sess.origin)
	case answer.Error != "":
		sess.failErr = &verifier.ResponseError{Code: answer.Error}
	default:
		sess.failErr = errors.New(`the response has neither "response" nor "error"`)
	}
	writeJSON(w, http.StatusOK, outcomeOf(sess))
}

// handleResult renders a plain HTML page reporting one session's own
// verification outcome — what the suite's own
// "verifier_verification_result_screenshot" evidence step captures.
func (s *server) handleResult(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := s.sessions.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()

	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	if !sess.done {
		_, _ = fmt.Fprintf(w, "<html><body><h1>Pending</h1><p>Session %s has not received a response yet.</p></body></html>", html.EscapeString(id))
		return
	}
	if sess.failErr != nil {
		_, _ = fmt.Fprintf(w, "<html><body><h1>Verification failed</h1><pre>%s</pre></body></html>", html.EscapeString(sess.failErr.Error()))
		return
	}
	_, _ = fmt.Fprintf(w, "<html><body><h1>Verification succeeded</h1><ul>")
	for _, cred := range sess.result {
		claims, _ := json.MarshalIndent(cred.Claims, "", "  ")
		_, _ = fmt.Fprintf(w, "<li>%s<pre>%s</pre></li>", html.EscapeString(cred.CredentialQueryID), html.EscapeString(string(claims)))
	}
	_, _ = fmt.Fprintf(w, "</ul></body></html>")
}

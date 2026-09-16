package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/verifier"
)

const sessionIDEntropyBytes = 16

func newSessionID() (string, error) {
	buf := make([]byte, sessionIDEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// server bundles the dependencies every handler needs.
type server struct {
	cfg        Config
	v          *verifier.Verifier
	sessions   *sessionStore
	issuerKeys verifier.SDJWTVCIssuerKeyResolver
}

// buildQuery constructs the DCQL query every session asks — a single
// "dc+sd-jwt" Credential Query for cfg.VCT, requesting exactly
// cfg.Claims. One Credential Query, no credential_sets/claim_sets:
// this binary's job is exercising VerifyResponse's own core
// verification path, not every DCQL selection permutation.
func (s *server) buildQuery() (dcql.Query, error) {
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

// handleAuthorize starts a new session: builds and signs an
// Authorization Request, stores it, and redirects the caller (the
// suite's own browser, playing Wallet) to an "openid4vp://" URL
// carrying this Verifier's own client_id and the request_uri the
// Wallet fetches next.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	query, err := s.buildQuery()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result, err := s.v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		http.Error(w, fmt.Sprintf("build authorization request: %v", err), http.StatusInternalServerError)
		return
	}
	id, err := newSessionID()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.sessions.put(&session{
		id: id, requestObject: result.RequestObject, query: query,
		nonce: result.Nonce, decryptionKey: result.ResponseDecryptionKey, createdAt: time.Now(),
	})

	requestURI := s.cfg.BaseURL + "/request/" + id
	deepLink := "openid4vp://?" + url.Values{
		"client_id":   {result.ClientID},
		"request_uri": {requestURI},
	}.Encode()
	log.Printf("session %s: built authorization request, request_uri=%s", id, requestURI)
	http.Redirect(w, r, deepLink, http.StatusFound)
}

// handleRequestObject serves the signed Request Object JWS a prior
// handleAuthorize call built, per §5.10's own request_uri content
// type.
func (s *server) handleRequestObject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	sess, ok := s.sessions.get(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
	_, _ = w.Write([]byte(sess.requestObject))
}

// handleResponse receives the direct_post.jwt response (§8.3.1) at
// this Verifier's own fixed response_uri, correlates it to a pending
// session by trying each one's decryptionKey (see sessionStore's own
// doc comment for why), verifies it, and replies with the HAIP-
// required "redirect_uri" JSON body pointing at that session's own
// human-readable result page.
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

	matched.mu.Lock()
	defer matched.mu.Unlock()
	matched.done = true
	if walletErr != nil {
		matched.failErr = walletErr
	} else {
		result, err := s.v.VerifyResponse(r.Context(), verifier.VerifyResponseRequest{
			Query: matched.query, Response: parsed, ExpectedNonce: matched.nonce,
			IssuerKeys: s.issuerKeys,
		})
		if err != nil {
			matched.failErr = err
		} else {
			matched.result = result.Credentials
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"redirect_uri": s.cfg.BaseURL + "/result/" + matched.id,
	})
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

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
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

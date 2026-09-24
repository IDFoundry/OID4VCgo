package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// httpClient is shared across every outbound call this binary makes
// (fetching request_uri, POSTing the direct_post.jwt response,
// following the HAIP redirect_uri) — TLS verification deliberately
// skipped, matching the OIDF conformance suite's own documented
// posture toward the implementation under test (its outbound client
// trusts any certificate, see conformance/verifier/docker-compose.yml's
// own comment): this binary calls back into whatever Verifier a live
// suite run points it at, itself running on throwaway conformance-only
// TLS material with no real trust chain, the same as this binary's own
// listener cert. Confirmed live during local wallet<->verifier
// smoke-testing (see conformance/wallet-vp/README.md) — without this,
// Go's own default TLS verification rejects the paired
// cmd/conformance-verifier's self-signed cert outright.
var httpClient = &http.Client{
	Timeout:   30 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // deliberate — see this var's own doc comment
}

const contentTypeHeader = "Content-Type"

func httpGetString(rawURL string) (string, error) {
	resp, err := httpClient.Get(rawURL) //nolint:gosec,noctx // rawURL is the Verifier's own request_uri from a request this binary just verified, not attacker-controlled input reaching this call untrusted
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: status %d: %s", rawURL, resp.StatusCode, body)
	}
	return string(body), nil
}

// httpPostFormString POSTs form as application/x-www-form-urlencoded
// to rawURL with an Accept header naming the Request URI response's
// own content type (§5.10), matching §5.10's exact POST semantics
// (as opposed to postDirectPostResponse's own POST, a different
// endpoint/content type entirely).
func httpPostFormString(rawURL string, form url.Values) (string, error) {
	req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(form.Encode())) //nolint:gosec,noctx // rawURL is the Verifier's own request_uri from a request this binary just verified, not attacker-controlled
	if err != nil {
		return "", err
	}
	req.Header.Set(contentTypeHeader, "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	resp, err := httpClient.Do(req) //nolint:gosec // same rawURL as above, already validated/verified before this call is reached
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s: status %d: %s", rawURL, resp.StatusCode, body)
	}
	return string(body), nil
}

// server bundles this binary's own fixed dependencies.
type server struct {
	cred wallet.HeldCredential
}

// handleAuthorize is this binary's own "server.authorization_endpoint"
// — what the OIDF suite's own browser navigates to (a plain HTTPS GET
// with client_id/request_uri query parameters — not a custom
// "openid4vp://" scheme; see conformance/wallet-vp/README.md for how
// this was confirmed against the suite's own source). It runs the
// whole flow synchronously: fetch+verify the Request Object, select
// and present the fixture credential, POST the encrypted response,
// and follow the HAIP-required redirect_uri — the same "complete
// everything before rendering a result" strategy a real same-device
// in-app-browser wallet takes.
func (s *server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	requestURI := r.URL.Query().Get("request_uri")
	clientID := r.URL.Query().Get("client_id")
	if requestURI == "" || clientID == "" {
		http.Error(w, "missing request_uri or client_id query parameter", http.StatusBadRequest)
		return
	}
	usePost := r.URL.Query().Get("request_uri_method") == "post"

	authReq, err := fetchAndVerifyRequestObject(requestURI, clientID, usePost)
	if err != nil {
		// A *wallet.RequestRejectedError means the Request Object itself
		// was authenticated (signature verified, client_id matches) —
		// only some other MUST it violates (redirect_uri alongside
		// direct_post, an unrecognized transaction_data type) stopped
		// processing — so its own carried ResponseURI/encryption key are
		// safe to send an OID4VP §8.1 error response to, the same as a
		// wallet.PresentCredentials failure below. Anything else (an
		// invalid signature, an untrusted client_id) means there is no
		// trustworthy response_uri yet, so it stays a local-only
		// rejection.
		var rejected *wallet.RequestRejectedError
		if errors.As(err, &rejected) {
			log.Printf("fetch/verify request object: %v", err)
			s.respondWithError(w, errorResponseParams{
				responseURI: rejected.ResponseURI, encryptionKey: rejected.ResponseEncryptionKey,
				encryptionKeyID: rejected.ResponseEncryptionKeyID, encryptionEnc: rejected.ResponseEncryptionEnc,
				state: rejected.State, code: rejected.Code, description: rejected.Description,
			})
			return
		}
		log.Printf("fetch/verify request object: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ResponseURI/ResponseEncryptionKey are only actually read when
	// authReq.Query asks for an "mso_mdoc" credential (see
	// wallet.PresentationRequest's own doc comment) — passing them
	// unconditionally is harmless for a "dc+sd-jwt"-only session
	// (presentSDJWTVCSelectively never looks at them), and
	// wallet.PresentCredentials now derives the JWK thumbprint itself,
	// so authReq's own *ecdsa.PublicKey goes straight through.
	vpToken, err := wallet.PresentCredentials(r.Context(), wallet.PresentationRequest{
		Query: authReq.Query, Credentials: []wallet.HeldCredential{s.cred},
		Audience: authReq.ClientID, Nonce: authReq.Nonce,
		ResponseURI: authReq.ResponseURI, ResponseEncryptionKey: authReq.ResponseEncryptionKey,
	})
	if err != nil {
		// Unlike fetchAndVerifyRequestObject's own failures above (an
		// invalid signature, an untrusted client_id — no trustworthy
		// response_uri to contact yet), authReq is already verified
		// legitimate by this point: OID4VP §8.1 lets a Wallet that can't
		// or won't satisfy the request send an encrypted error response
		// instead of just rejecting locally, and doing so here avoids the
		// suite's own screenshot-REVIEW gate for a module this genuinely
		// passes. "invalid_request" (RFC 6749 §5.2) is the generic code
		// for a missing/invalid required parameter (e.g. no nonce); a
		// required DCQL query with no satisfying held credential is its
		// own case — OID4VP §8.5/§6.4.2 call for "access_denied" there
		// instead, confirmed live against a real OIDF conformance suite
		// instance: VP1FinalWalletRequiredNonMatchingCredential.java's own
		// EnsureAuthorizationEndpointErrorIsAccessDenied check.
		log.Printf("present credentials: %v", err)
		code := "invalid_request"
		if errors.Is(err, wallet.ErrNoMatchingCredential) {
			code = "access_denied"
		}
		s.respondWithError(w, errorResponseParams{
			responseURI: authReq.ResponseURI, encryptionKey: authReq.ResponseEncryptionKey,
			encryptionKeyID: authReq.ResponseEncryptionKeyID, encryptionEnc: authReq.ResponseEncryptionEnc,
			state: authReq.State, code: code, description: err.Error(),
		})
		return
	}

	responseJWE, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, State: authReq.State,
		EncryptionKey: authReq.ResponseEncryptionKey, EncryptionKeyID: authReq.ResponseEncryptionKeyID,
		EncryptionEnc: authReq.ResponseEncryptionEnc,
	})
	if err != nil {
		log.Printf("build direct_post response: %v", err)
		http.Error(w, fmt.Sprintf("build direct_post response: %v", err), http.StatusInternalServerError)
		return
	}

	redirectURI, err := postDirectPostResponse(authReq.ResponseURI, responseJWE)
	if err != nil {
		log.Printf("post direct_post.jwt response: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	presentedLead := ""
	if redirectURI == "" {
		presentedLead = "<p>No redirect_uri was returned.</p>"
	}
	respondFollowingRedirect(w, "Presented", presentedLead, redirectURI)
}

// respondFollowingRedirect writes w's own HTML response, following
// redirectURI first if non-empty — shared by handleAuthorize's own
// success path and respondWithError's own error path, which differ
// only in title/leadParagraph, not in the follow-redirect-or-not
// branching itself. HAIP requires the Verifier's own direct_post.jwt
// response to carry a redirect_uri (see cmd/conformance-verifier's own
// handleResponse) — a real same-device wallet's in-app browser
// navigates there next, closing the loop back to the Verifier's own
// UI. This binary has no real browser; a plain GET completes the same
// round trip for an automated flow.
func respondFollowingRedirect(w http.ResponseWriter, title, leadParagraph, redirectURI string) {
	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	if redirectURI == "" {
		_, _ = fmt.Fprintf(w, "<html><body><h1>%s</h1>%s</body></html>", title, leadParagraph)
		return
	}
	if _, err := httpGetString(redirectURI); err != nil {
		log.Printf("follow redirect_uri %s: %v", redirectURI, err)
	}
	_, _ = fmt.Fprintf(w, "<html><body><h1>%s</h1>%s<p>Followed redirect_uri: %s</p></body></html>", title, leadParagraph, redirectURI)
}

// errorResponseParams bundles respondWithError's own trailing
// arguments — both call sites already have these five response-target
// fields sitting on a *wallet.RequestRejectedError or the verified
// authReq, just under those types' own field names, plus the two
// per-failure code/description strings.
type errorResponseParams struct {
	responseURI     string
	encryptionKey   *ecdsa.PublicKey
	encryptionKeyID string
	encryptionEnc   string
	state           string
	code            string
	description     string
}

// respondWithError builds an OID4VP §8.1 error response
// (wallet.BuildDirectPostErrorResponse) and POSTs it to p.responseURI —
// the same way handleAuthorize's own success path POSTs a vp_token
// one. Callable from two call sites in handleAuthorize, each already
// having established responseURI/the encryption key are trustworthy
// before calling this (see each one's own doc comment for why). Falls
// back to a local http.Error only if building/POSTing the error
// response itself fails, which that already-verified state makes
// unlikely in practice.
func (s *server) respondWithError(w http.ResponseWriter, p errorResponseParams) {
	responseJWE, err := wallet.BuildDirectPostErrorResponse(wallet.BuildDirectPostErrorResponseParams{
		Error: p.code, ErrorDescription: p.description, State: p.state,
		EncryptionKey: p.encryptionKey, EncryptionKeyID: p.encryptionKeyID,
		EncryptionEnc: p.encryptionEnc,
	})
	if err != nil {
		log.Printf("build direct_post error response: %v", err)
		http.Error(w, fmt.Sprintf("build direct_post error response: %v", err), http.StatusInternalServerError)
		return
	}

	redirectURI, err := postDirectPostResponse(p.responseURI, responseJWE)
	if err != nil {
		log.Printf("post direct_post.jwt error response: %v", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	respondFollowingRedirect(w, "Rejected", fmt.Sprintf("<p>Sent error response: %s: %s</p>", p.code, p.description), redirectURI)
}

// postDirectPostResponse POSTs responseJWE as the "response" form
// parameter (§8.3.1) to responseURI, and returns the JSON body's own
// "redirect_uri" if present.
func postDirectPostResponse(responseURI, responseJWE string) (string, error) {
	form := url.Values{"response": {responseJWE}}
	resp, err := httpClient.PostForm(responseURI, form) //nolint:noctx // responseURI is the Verifier's own request_uri-derived response_uri, not attacker-controlled
	if err != nil {
		return "", fmt.Errorf("POST %s: %w", responseURI, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s: status %d: %s", responseURI, resp.StatusCode, body)
	}
	if !strings.Contains(resp.Header.Get(contentTypeHeader), "json") {
		return "", nil
	}
	var wire struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return "", fmt.Errorf("parse direct_post response: %w", err)
	}
	return wire.RedirectURI, nil
}

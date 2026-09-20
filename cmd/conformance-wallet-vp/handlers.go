package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
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
		log.Printf("fetch/verify request object: %v", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// ResponseURI/ResponseEncryptionJWKThumbprint are only actually read
	// when authReq.Query asks for an "mso_mdoc" credential (see
	// wallet.PresentationRequest's own doc comment) — computing and
	// passing them unconditionally is harmless for an "dc+sd-jwt"-only
	// session (presentSDJWTVCSelectively never looks at them).
	thumbprint, err := responseEncryptionJWKThumbprint(authReq.ResponseEncryptionKey)
	if err != nil {
		log.Printf("compute response encryption jwk thumbprint: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	vpToken, err := wallet.PresentCredentials(r.Context(), wallet.PresentationRequest{
		Query: authReq.Query, Credentials: []wallet.HeldCredential{s.cred},
		Audience: authReq.ClientID, Nonce: authReq.Nonce,
		ResponseURI: authReq.ResponseURI, ResponseEncryptionJWKThumbprint: thumbprint,
	})
	if err != nil {
		log.Printf("present credentials: %v", err)
		http.Error(w, fmt.Sprintf("present credentials: %v", err), http.StatusInternalServerError)
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

	w.Header().Set(contentTypeHeader, "text/html; charset=utf-8")
	if redirectURI == "" {
		_, _ = fmt.Fprintln(w, "<html><body><h1>Presented</h1><p>No redirect_uri was returned.</p></body></html>")
		return
	}
	// HAIP requires the Verifier's own direct_post.jwt response to
	// carry a redirect_uri (see cmd/conformance-verifier's own
	// handleResponse) — a real same-device wallet's in-app browser
	// navigates there next, closing the loop back to the Verifier's
	// own UI. This binary has no real browser; a plain GET completes
	// the same round trip for an automated flow.
	if _, err := httpGetString(redirectURI); err != nil {
		log.Printf("follow redirect_uri %s: %v", redirectURI, err)
	}
	_, _ = fmt.Fprintf(w, "<html><body><h1>Presented</h1><p>Followed redirect_uri: %s</p></body></html>", redirectURI)
}

// responseEncryptionJWKThumbprint computes the RFC 7638 SHA-256 JWK
// thumbprint of pub as raw bytes — wallet.PresentationRequest.
// ResponseEncryptionJWKThumbprint's own shape (Appendix B.2.6.1's own
// Handover input), what an "mso_mdoc" presentation binds
// SessionTranscriptBytes to so the Verifier can independently
// reconstruct the identical transcript from the same encryption key it
// already published. Returns nil, nil for a nil pub (an "dc+sd-jwt"-only
// session's authReq never resolves one) — mirrors
// internal/testmdoc.ResponseEncryptionThumbprint's own computation.
func responseEncryptionJWKThumbprint(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, nil
	}
	j, err := jwk.Marshal(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal response encryption public key: %w", err)
	}
	thumbprint, err := j.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("compute response encryption jwk thumbprint: %w", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		return nil, fmt.Errorf("decode response encryption jwk thumbprint: %w", err)
	}
	return raw, nil
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

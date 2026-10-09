package verifierapp

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// errBuildRequest answers a request the page couldn't build.
const errBuildRequest = "couldn't build the request"

// The request page can also ask in the browser, over the Digital
// Credentials API, offering two requests, of which the browser and
// wallet answer one:
//
//   - ISO mdoc's own protocol ("org-iso-mdoc", ISO/IEC TS 18013-7 Annex
//     C) — Safari's, answered by an iOS document provider app or Apple
//     Wallet: the scenario's mdoc claims, signed with the scenario's own
//     mdoc reader certificate.
//   - OpenID4VP ("openid4vp-v1-signed", OpenID4VP 1.0 Appendix A) —
//     Chrome's, answered by an Android wallet through Credential Manager:
//     the scenario's own query, signed by its relying party.
//
// Either answer is verified into the same Outcome as the OpenID4VP
// requests.

// maxDCAPIResponseBody bounds the page's POST of a response.
const maxDCAPIResponseBody = mdocdcapi.MaxResponseBytes + 1024

// dcapiRequest is what the page passes to navigator.credentials.get as
// one of digital.requests.
type dcapiRequest struct {
	Protocol string `json:"protocol"`
	Data     any    `json:"data"`
}

// openID4VPProtocol is the DC API protocol of a signed OpenID4VP request.
const openID4VPProtocol = "openid4vp-v1-signed"

// relyingParty is a scenario's Verifier, for the Digital Credentials
// API's OpenID4VP requests, and how it verifies their answers.
type relyingParty struct {
	v      *verifier.Verifier
	verify verifier.VerifyResponseRequest
}

// openID4VPPending is an OpenID4VP DC API request waiting for its
// answer: what verifying it needs.
type openID4VPPending struct {
	query dcql.Query
	nonce string
	key   *ecdsa.PrivateKey
}

// originOf is the serialized origin of verifierURL: the origin the
// request page is served from.
func originOf(verifierURL string) (string, error) {
	u, err := url.Parse(verifierURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("verifierapp: VerifierURL %q has no origin", verifierURL)
	}
	return u.Scheme + "://" + u.Host, nil
}

// mdocElements are the mdoc data elements sc's query asks for, by
// namespace, none to be retained.
func (a *App) mdocElements(sc Scenario) (map[string]map[string]bool, error) {
	q, err := buildQuery(sc, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, cq := range q.Credentials {
		if cq.ID != mdocQueryID {
			continue
		}
		for _, cl := range cq.Claims {
			ns, el, ok := mdocPath(cl.Path)
			if !ok {
				return nil, fmt.Errorf("verifierapp: scenario %q: an mdoc claim isn't a namespace and an element", sc)
			}
			if out[ns] == nil {
				out[ns] = map[string]bool{}
			}
			out[ns][el] = false
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("verifierapp: scenario %q asks for no mdoc", sc)
	}
	return out, nil
}

// handleDCAPIRequest starts a Digital Credentials API request for the
// page: one at a time, replacing any earlier one.
func (a *App) handleDCAPIRequest(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r.PathValue("id"))
	if !ok || !sameBrowser(r, s) {
		http.NotFound(w, r)
		return
	}
	if info, _ := s.scenario.Info(); info.Multiple {
		http.Error(w, "this scenario takes several passports, which one Digital Credentials API request can't", http.StatusBadRequest)
		return
	}
	elements, err := a.mdocElements(s.scenario)
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: a.origin, DocType: credential.DocType, Elements: elements,
		Readers: []mdocdcapi.ReaderKey{a.readers[s.scenario]},
	})
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	query, err := buildQuery(s.scenario, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	built, err := a.rps[s.scenario].v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{a.origin},
	})
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	s.dcapi = &req.Pending
	s.dcapiOpenID = &openID4VPPending{query: query, nonce: built.Nonce, key: built.ResponseDecryptionKey}
	a.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerContentType, "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Requests []dcapiRequest `json:"requests"`
	}{[]dcapiRequest{
		{Protocol: mdocdcapi.Protocol, Data: req.Data},
		{Protocol: openID4VPProtocol, Data: map[string]string{"request": built.RequestObject}},
	}})
}

// handleDCAPIResponse verifies the page's Digital Credentials API
// answer, once: the pending request is spent whatever the outcome.
func (a *App) handleDCAPIResponse(w http.ResponseWriter, r *http.Request) {
	s, ok := a.session(r.PathValue("id"))
	if !ok || !sameBrowser(r, s) {
		http.NotFound(w, r)
		return
	}
	var body struct {
		Protocol string `json:"protocol"`
		Response string `json:"response"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDCAPIResponseBody)).Decode(&body); err != nil {
		http.Error(w, "malformed response", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	pending, openID := s.dcapi, s.dcapiOpenID
	s.dcapi, s.dcapiOpenID = nil, nil
	a.mu.Unlock()
	if pending == nil || openID == nil {
		http.Error(w, "no request is waiting for an answer: start again", http.StatusConflict)
		return
	}
	var out *Outcome
	var err error
	if body.Protocol == openID4VPProtocol {
		out, err = a.verifyDCAPIOpenID4VP(r, s, *openID, body.Response)
	} else {
		out, err = a.verifyDCAPI(r, s, *pending, body.Response)
	}
	if err != nil {
		http.Error(w, "not verified: "+err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	s.dcapiOutcome = out
	a.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// verifyDCAPI verifies response to pending and decides s's scenario
// from it, as accept does for an OpenID4VP answer.
func (a *App) verifyDCAPI(r *http.Request, s *session, pending mdocdcapi.Pending, response string) (*Outcome, error) {
	if a.answered(r, s) {
		return nil, errors.New("this request has already been answered")
	}
	verified, err := mdocdcapi.VerifyResponse(r.Context(), mdocdcapi.VerifyParams{
		Pending: pending, Response: response,
		IssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: a.issuerRoots},
		Now:        a.now, MaxClockSkew: time.Minute,
	})
	if err != nil {
		return nil, err
	}
	claims := make(map[string]any, len(verified.NameSpaces))
	for ns, elements := range verified.NameSpaces {
		claims[ns] = elements
	}
	info, _ := s.scenario.Info()
	people, err := a.people(r.Context(), info, []verifier.VerifiedCredential{{
		CredentialQueryID: mdocQueryID, Claims: claims, MdocStatus: verified.Status,
	}})
	if err != nil {
		return nil, err
	}
	p := people[0]
	out := &Outcome{Scenario: s.scenario, Format: p.Format, Claims: p.Claims, Status: p.Status, ICAO: p.ICAO}
	out.Decision = decide(s.scenario, out)
	return out, nil
}

// verifyDCAPIOpenID4VP verifies the OpenID4VP answer, response (the
// encrypted dc_api.jwt response), to pending, bound to the page's
// origin, and decides s's scenario from it.
func (a *App) verifyDCAPIOpenID4VP(r *http.Request, s *session, pending openID4VPPending, response string) (*Outcome, error) {
	if a.answered(r, s) {
		return nil, errors.New("this request has already been answered")
	}
	rp := a.rps[s.scenario]
	parsed, err := rp.v.ParseDirectPostJWTResponse(response, pending.key)
	if err != nil {
		return nil, err
	}
	req := rp.verify
	req.Query, req.Response, req.ExpectedNonce, req.ResponseEncryptionKey = pending.query, parsed, pending.nonce, pending.key
	req.Origin, req.ExpectedOrigins = a.origin, []string{a.origin}
	result, err := rp.v.VerifyResponse(r.Context(), req)
	if err != nil {
		return nil, err
	}
	return a.outcomeOf(r.Context(), s.scenario, result)
}

// answered reports whether s already has an outcome, from either
// OpenID4VP request or the Digital Credentials API.
func (a *App) answered(r *http.Request, s *session) bool {
	return a.state(r.Context(), s).outcome != nil
}

// mdocPath splits an mdoc claims path: a namespace, then an element.
func mdocPath(p dcql.Path) (ns, el string, ok bool) {
	if len(p) != 2 || !p[0].IsKey() || !p[1].IsKey() {
		return "", "", false
	}
	return p[0].Key(), p[1].Key(), true
}

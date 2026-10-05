package verifierapp

import (
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

// The request page can also ask in the browser, over the Digital
// Credentials API with ISO mdoc's own protocol ("org-iso-mdoc", ISO/IEC
// TS 18013-7 Annex C) — Safari's, answered by an iOS document provider
// app or Apple Wallet. It asks for the scenario's mdoc claims, signed
// with the scenario's own verifier certificate as the mdoc reader, and
// verifies the answer into the same Outcome as the OpenID4VP requests.

// maxDCAPIResponseBody bounds the page's POST of a response.
const maxDCAPIResponseBody = mdocdcapi.MaxResponseBytes + 1024

// dcapiRequest is what the page passes to navigator.credentials.get as
// one of digital.requests.
type dcapiRequest struct {
	Protocol string                `json:"protocol"`
	Data     mdocdcapi.RequestData `json:"data"`
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
		http.Error(w, "couldn't build the request", http.StatusInternalServerError)
		return
	}
	req, err := mdocdcapi.BuildRequest(mdocdcapi.RequestParams{
		Origin: a.origin, DocType: credential.DocType, Elements: elements,
		Readers: []mdocdcapi.ReaderKey{a.readers[s.scenario]},
	})
	if err != nil {
		http.Error(w, "couldn't build the request", http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	s.dcapi = &req.Pending
	a.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(headerContentType, "application/json")
	_ = json.NewEncoder(w).Encode(dcapiRequest{Protocol: mdocdcapi.Protocol, Data: req.Data})
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
		Response string `json:"response"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxDCAPIResponseBody)).Decode(&body); err != nil {
		http.Error(w, "malformed response", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	pending := s.dcapi
	s.dcapi = nil
	a.mu.Unlock()
	if pending == nil {
		http.Error(w, "no request is waiting for an answer: start again", http.StatusConflict)
		return
	}
	out, err := a.verifyDCAPI(r, s, *pending, body.Response)
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

package verifierapp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

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
// requests. Both are verifier.Transactions requests, like the page's
// others (BeginMdocDCAPI, BeginDCAPI): an answer runs the scenario's
// Accept, only the page's browser can post it, a refused one leaves its
// request open, and the first to complete closes the rest.

// maxDCAPIResponseBody bounds the page's POST of a response.
const maxDCAPIResponseBody = mdocdcapi.MaxResponseBytes + 1024

// dcapiRequest is what the page passes to navigator.credentials.get as
// one of digital.requests.
type dcapiRequest struct {
	Protocol string `json:"protocol"`
	Data     any    `json:"data"`
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
// namespace, none to be retained, and whether some may be withheld: the
// query's claim sets make some of them optional, which an org-iso-mdoc
// request can't say, so it asks for them all and checkMdocClaimSets
// checks the answer against the query's claim sets.
func (a *App) mdocElements(sc Scenario) (elements map[string]map[string]bool, optional bool, err error) {
	q, err := buildQuery(sc, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		return nil, false, err
	}
	out := map[string]map[string]bool{}
	for _, cq := range q.Credentials {
		if cq.ID != mdocQueryID {
			continue
		}
		optional = optional || len(cq.ClaimSets) > 0
		for _, cl := range cq.Claims {
			ns, el, ok := mdocPath(cl.Path)
			if !ok {
				return nil, false, fmt.Errorf("verifierapp: scenario %q: an mdoc claim isn't a namespace and an element", sc)
			}
			if out[ns] == nil {
				out[ns] = map[string]bool{}
			}
			out[ns][el] = false
		}
	}
	if len(out) == 0 {
		return nil, false, fmt.Errorf("verifierapp: scenario %q asks for no mdoc", sc)
	}
	return out, optional, nil
}

// checkMdocClaimSets refuses an mdoc that withheld elements sc's query
// requires: an org-iso-mdoc request that let some be withheld
// (mdocElements) is answered with whichever the holder disclosed.
func (a *App) checkMdocClaimSets(sc Scenario, result verifier.VerifyResponseResult) error {
	var q dcql.Query
	for _, vc := range result.Credentials {
		if vc.Withheld == nil || vc.CredentialQueryID != mdocQueryID {
			continue
		}
		if q.Credentials == nil {
			var err error
			if q, err = buildQuery(sc, a.cfg.IssuerVCT, a.issuerTrusted); err != nil {
				return err
			}
		}
		nameSpaces := map[string]map[string]any{}
		for ns, elements := range vc.Claims {
			nameSpaces[ns], _ = elements.(map[string]any)
		}
		for _, cq := range q.Credentials {
			if cq.ID != mdocQueryID {
				continue
			}
			if err := cq.SatisfiedByMdocClaims(credential.DocType, nameSpaces); err != nil {
				return fmt.Errorf("the mdoc doesn't disclose what the request needs: %w", err)
			}
		}
	}
	return nil
}

// handleDCAPIRequest starts a Digital Credentials API request for the
// page: one at a time, replacing any earlier one.
func (a *App) handleDCAPIRequest(w http.ResponseWriter, r *http.Request) {
	pageID := r.PathValue("id")
	s, ok := a.session(pageID)
	if !ok || !sameBrowser(r, s) {
		http.NotFound(w, r)
		return
	}
	if info, _ := s.scenario.Info(); info.Multiple {
		http.Error(w, "this scenario takes several passports, which one Digital Credentials API request can't", http.StatusBadRequest)
		return
	}
	elements, optional, err := a.mdocElements(s.scenario)
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	query, err := buildQuery(s.scenario, a.cfg.IssuerVCT, a.issuerTrusted)
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	txs := a.txs[s.scenario]
	// The mdoc is reported under the query's own mdoc ID, so the
	// scenario's Accept reads it as it reads an OpenID4VP answer's.
	mdocBegun, err := txs.BeginMdocDCAPI(r.Context(), verifier.MdocDCAPIRequest{
		DocType: credential.DocType, Elements: elements, CredentialQueryID: mdocQueryID, AllowWithheld: optional,
	}, s.binding, a.origin)
	if err != nil {
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	begun, err := txs.BeginDCAPI(r.Context(), query, s.binding, a.origin)
	if err != nil {
		_ = txs.Close(r.Context(), mdocBegun.ID)
		http.Error(w, errBuildRequest, http.StatusInternalServerError)
		return
	}
	a.mu.Lock()
	previous := []string{s.dcapiMdoc, s.dcapiOpenID}
	s.dcapiMdoc, s.dcapiOpenID = mdocBegun.ID, begun.ID
	a.byTx[mdocBegun.ID], a.byTx[begun.ID] = pageID, pageID
	a.mu.Unlock()
	for _, id := range previous {
		if id != "" {
			_ = txs.Close(r.Context(), id)
		}
	}
	w.Header().Set(headerCacheControl, noStore)
	w.Header().Set(headerContentType, "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Requests []dcapiRequest `json:"requests"`
	}{[]dcapiRequest{
		{Protocol: mdocBegun.Request.Protocol, Data: mdocBegun.Request.Data},
		{Protocol: begun.Request.Protocol, Data: begun.Request.Data},
	}})
}

// handleDCAPIResponse passes the page's Digital Credentials API answer
// to its verifier.Transactions request — the org-iso-mdoc one, or the
// OpenID4VP one — which verifies it bound to the page's origin and runs
// the scenario's Accept; the page then reads the outcome as for its
// other requests. A refused answer leaves its request open, until the
// page asks again.
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
	txs := a.txs[s.scenario]
	a.mu.Lock()
	id, handle := s.dcapiMdoc, txs.HandleMdocDCAPIResponse
	if body.Protocol == verifier.DCAPIProtocolSigned {
		// The encrypted dc_api.jwt response.
		id, handle = s.dcapiOpenID, txs.HandleDCAPIResponse
	}
	a.mu.Unlock()
	if id == "" {
		http.Error(w, noRequestWaiting, http.StatusConflict)
		return
	}
	data, err := json.Marshal(map[string]string{"response": body.Response})
	if err != nil {
		http.Error(w, "malformed response", http.StatusBadRequest)
		return
	}
	_, err = handle(r.Context(), id, s.binding, data)
	switch {
	case errors.Is(err, verifier.ErrTransactionAnswered), errors.Is(err, verifier.ErrTransactionClosed), errors.Is(err, verifier.ErrTransactionExpired):
		http.Error(w, noRequestWaiting, http.StatusConflict)
	case err != nil:
		http.Error(w, "not verified: "+err.Error(), http.StatusBadRequest)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// noRequestWaiting answers an answer to no request.
const noRequestWaiting = "no request is waiting for an answer: start again"

// mdocPath splits an mdoc claims path: a namespace, then an element.
func mdocPath(p dcql.Path) (ns, el string, ok bool) {
	if len(p) != 2 || !p[0].IsKey() || !p[1].IsKey() {
		return "", "", false
	}
	return p[0].Key(), p[1].Key(), true
}
